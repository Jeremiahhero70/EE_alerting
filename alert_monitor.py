#!/usr/bin/env python3
"""
Wazuh Alert Monitor - Simple Multi-Tenant Alert System
Monitors level 12+ alerts, deduplicates using cache, sends emails
"""

import os
import sys
import yaml
import logging
import json
import hashlib
from typing import Dict, Any, List
from datetime import datetime, timedelta
from pathlib import Path

from wazuh_connector import WazuhAlertConnector
from email_reporter import AlertEmailReporter
from alert_formatter import AlertFormatter

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ConfigLoader:
    """Load and manage configuration from YAML"""
    
    def __init__(self, config_file: str = "mt_config.yaml"):
        """Load configuration from YAML file"""
        self.config_file = config_file
        self.config = {}
        self.load_config()
    
    def load_config(self):
        """Load configuration from file"""
        try:
            with open(self.config_file, 'r') as f:
                self.config = yaml.safe_load(f)
            logger.info(f"✅ Configuration loaded from {self.config_file}")
        except Exception as e:
            logger.error(f"❌ Failed to load config: {e}")
            sys.exit(1)
    
    def get(self, key: str, default=None):
        """Get config value"""
        return self.config.get(key, default)
    
    def get_client_config(self, client_name: str) -> Dict[str, Any]:
        """Get per-client configuration"""
        clients = self.config.get('clients', {})
        return clients.get(client_name, {})
    
    def get_enabled_clients(self) -> List[str]:
        """Get list of enabled clients"""
        clients = self.config.get('clients', {})
        enabled = [name for name, config in clients.items() if config.get('enabled', False)]
        return enabled
    
    def get_dashboard_config(self) -> Dict[str, Any]:
        """Get shared dashboard configuration"""
        return self.config.get('dashboard', {})
    
    def get_alert_config(self) -> Dict[str, Any]:
        """Get alert configuration"""
        return self.config.get('alert_config', {})


class AlertCache:
    """Manage alert deduplication cache with daily rotation"""
    
    def __init__(self, cache_dir: str = "./alert_cache"):
        """Initialize cache
        
        Args:
            cache_dir: Directory to store cache files
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.current_date = datetime.now().strftime("%Y-%m-%d")
        self.cache_file = self.cache_dir / f"alerts_{self.current_date}.json"
        self.cache = self._load_cache()
    
    def _load_cache(self) -> set:
        """Load cache from file"""
        try:
            if self.cache_file.exists():
                with open(self.cache_file, 'r') as f:
                    data = json.load(f)
                    return set(data.get('alert_hashes', []))
            return set()
        except Exception as e:
            logger.warning(f"Could not load cache: {e}")
            return set()
    
    def _get_alert_hash(self, alert: Dict[str, Any]) -> str:
        """Generate unique hash for alert to prevent duplicates
        
        Args:
            alert: Wazuh alert document
            
        Returns:
            Hash string
        """
        key_parts = [
            alert.get('rule', {}).get('id', ''),
            alert.get('agent', {}).get('id', ''),
            alert.get('timestamp', ''),
        ]
        key_str = '|'.join(str(p) for p in key_parts)
        return hashlib.md5(key_str.encode()).hexdigest()
    
    def is_new_alert(self, alert: Dict[str, Any]) -> bool:
        """Check if alert is new (not in cache)
        
        Args:
            alert: Wazuh alert document
            
        Returns:
            True if alert is new, False if already sent
        """
        alert_hash = self._get_alert_hash(alert)
        return alert_hash not in self.cache
    
    def add_alert(self, alert: Dict[str, Any]) -> None:
        """Add alert to cache
        
        Args:
            alert: Wazuh alert document
        """
        alert_hash = self._get_alert_hash(alert)
        self.cache.add(alert_hash)
        self._save_cache()
    
    def _save_cache(self) -> None:
        """Save cache to file"""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump({
                    'date': self.current_date,
                    'alert_hashes': list(self.cache)
                }, f, indent=2)
        except Exception as e:
            logger.warning(f"Could not save cache: {e}")
    
    def rotate_if_needed(self) -> None:
        """Rotate cache file if date changed (24hr rotation)"""
        current_date = datetime.now().strftime("%Y-%m-%d")
        if current_date != self.current_date:
            logger.info(f"📁 Rotating alert cache (new day: {current_date})")
            self.current_date = current_date
            self.cache_file = self.cache_dir / f"alerts_{self.current_date}.json"
            self.cache = set()


class AlertMonitor:
    """Monitor Wazuh for level 12+ alerts"""
    
    def __init__(self, config: ConfigLoader):
        """Initialize alert monitor
        
        Args:
            config: Configuration loader instance
        """
        self.config = config
        self.wazuh_connector = WazuhAlertConnector(config.get_dashboard_config())
        self.email_reporter = AlertEmailReporter(config.get('email_server'),
                                                 config.get('email_port'),
                                                 config.get('email_sender'),
                                                 config.get('email_password'),
                                                 config.get('email_use_tls', True))
        self.cache = AlertCache()
    
    def scan_and_alert(self):
        """Scan for alerts and send emails for new ones
        
        Deduplication Strategy:
        1. Cache tracks alerts across runs (24-hour rotation)
        2. Within same minute: group identical rule_id + agent_id, send one email per group
        3. Fallback format: If alert format fails, use generic format
        """
        
        # Rotate cache if needed (every 24hrs)
        self.cache.rotate_if_needed()
        
        # Get enabled clients
        enabled_clients = self.config.get_enabled_clients()
        if not enabled_clients:
            logger.warning("⚠️  No enabled clients found")
            return
        
        # Get alert configuration
        alert_config = self.config.get_alert_config()
        min_level = alert_config.get('min_level', 12)
        lookback_hours = alert_config.get('lookback_hours', 1)  # Default to 1 hour lookback
        
        total_processed = 0
        total_sent = 0
        total_grouped = 0  # Track how many alerts were grouped/deduplicated
        
        # Scan each client
        for client_name in enabled_clients:
            try:
                # Get alerts for this client
                result = self.wazuh_connector.search_alerts(client_name, min_level, lookback_hours)
                
                if result.get('error'):
                    logger.error(f"❌ {client_name}: {result['error']}")
                    continue
                
                alerts = result.get('alerts', [])
                if not alerts:
                    logger.info(f"ℹ️  {client_name}: No alerts found")
                    continue
                
                logger.info(f"Found {len(alerts)} alert(s) for {client_name}")
                
                # Get email recipients for this client
                client_config = self.config.get_client_config(client_name)
                email_recipients = client_config.get('email_recipients', [])
                
                if not email_recipients:
                    logger.warning(f"⚠️  {client_name}: No email recipients configured")
                    continue
                
                # Group identical alerts within this minute (same rule + agent)
                # This prevents sending multiple emails for identical alerts
                alerts_to_send = self._deduplicate_alerts_in_batch(alerts)
                total_grouped = len(alerts) - len(alerts_to_send)
                
                if total_grouped > 0:
                    logger.info(f"  Deduplicated {total_grouped} identical alert(s) in batch")
                
                # Process deduplicated alerts
                for alert in alerts_to_send:
                    total_processed += 1
                    
                    # Check if alert is new (not in 24-hour cache)
                    if not self.cache.is_new_alert(alert):
                        logger.debug(f"  ⏭️  Duplicate alert (already sent in previous run)")
                        continue
                    
                    # Format email (with fallback handling)
                    try:
                        email_body = AlertFormatter.format_email(alert)
                    except Exception as e:
                        logger.warning(f"  ⚠️  Format error, using fallback: {e}")
                        email_body = self._get_fallback_format(alert)
                    
                    # Generate subject
                    rule = alert.get('rule', {})
                    rule_desc = rule.get('description', 'Security Alert')
                    rule_level = rule.get('level', 12)
                    subject = f"Wazuh Alert [L{rule_level}] - {rule_desc}"
                    
                    # Send email
                    try:
                        # Send to each recipient
                        for recipient in email_recipients:
                            self.email_reporter.send_alert(
                                recipient=recipient,
                                subject=subject,
                                body=email_body
                            )
                        
                        # Add to cache after successful send
                        self.cache.add_alert(alert)
                        total_sent += 1
                        logger.info(f"  ✅ Email sent for rule {rule.get('id')}")
                        
                    except Exception as e:
                        logger.error(f"  ❌ Failed to send email: {e}")
            
            except Exception as e:
                logger.error(f"❌ Error processing {client_name}: {e}")
        
        logger.info(f"✅ Scan complete: {total_sent}/{total_processed} new alerts sent (deduplicated {total_grouped} in batch)")
    
    def _deduplicate_alerts_in_batch(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate identical alerts within current batch
        
        Group by: rule_id + agent_id
        Keep: First alert from each group (to send one email per group)
        
        Args:
            alerts: List of alerts from current query
            
        Returns:
            Deduplicated list (one alert per rule+agent combination)
        """
        seen = {}  # Track: (rule_id, agent_id) → alert
        
        for alert in alerts:
            rule_id = alert.get('rule', {}).get('id', 'unknown')
            agent_id = alert.get('agent', {}).get('id', 'unknown')
            key = (rule_id, agent_id)
            
            # Keep only first occurrence of each rule+agent combination
            if key not in seen:
                seen[key] = alert
        
        return list(seen.values())
    
    def _get_fallback_format(self, alert: Dict[str, Any]) -> str:
        """Fallback format when alert formatting fails
        
        Args:
            alert: Wazuh alert document
            
        Returns:
            Professional fallback email format
        """
        try:
            rule = alert.get('rule', {})
            agent = alert.get('agent', {})
            data = alert.get('data', {})
            
            # Extract what we can
            timestamp = alert.get('timestamp', 'Unknown')
            rule_id = rule.get('id', 'Unknown')
            rule_level = rule.get('level', 'Unknown')
            rule_desc = rule.get('description', 'Unknown')
            agent_name = agent.get('name', 'Unknown')
            agent_ip = agent.get('ip', 'Unknown')
            
            # Build professional fallback format
            fallback_body = f"""======================================================================
WAZUH ALERT - Level {rule_level}
======================================================================

Alert Details:
  Timestamp:       {timestamp}
  Rule ID:         {rule_id}
  Description:     {rule_desc}
  Agent:           {agent_name} ({agent_ip})

Event Information:
"""
            
            # Add any available data fields
            if data.get('srcip'):
                fallback_body += f"  Source IP:       {data.get('srcip')}\n"
            if data.get('dstip'):
                fallback_body += f"  Destination IP:  {data.get('dstip')}\n"
            if data.get('command'):
                fallback_body += f"  Command:         {data.get('command')}\n"
            if data.get('process'):
                fallback_body += f"  Process:         {data.get('process')}\n"
            if data.get('user'):
                fallback_body += f"  User:            {data.get('user')}\n"
            
            # Add raw JSON for debugging (first 1000 chars)
            alert_json = json.dumps(alert, indent=2)[:1000]
            fallback_body += f"""
======================================================================
Raw Alert Details:
{alert_json}

======================================================================
Please investigate this alert.
"""
            return fallback_body
        except Exception as e:
            return f"""======================================================================
WAZUH ALERT - Error Processing
======================================================================

We received an alert from our monitoring system, but encountered an error
while processing the alert details.

Error Message: {str(e)}

Raw Alert Data (truncated):
{json.dumps(alert, indent=2)[:500]}

======================================================================
Please investigate this alert and contact the security team.
"""


def main():
    """Main entry point"""
    try:
        # Load configuration
        config = ConfigLoader("mt_config.yaml")
        logger.info("✅ Email reporter initialized")
        
        # Create monitor
        monitor = AlertMonitor(config)
        
        # Run scan
        logger.info("\n" + "="*70)
        logger.info("WAZUH ALERT MONITORING - RUNNING SCAN")
        logger.info("="*70 + "\n")
        
        monitor.scan_and_alert()
        
        logger.info("\n" + "="*70)
        logger.info("✅ Alert scan complete!")
        logger.info("="*70 + "\n")
        
    except Exception as e:
        logger.error(f"❌ Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
