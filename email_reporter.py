#!/usr/bin/env python3
"""
Email Reporter Module - Alert System
Sends individual alert notifications via SMTP
"""

import smtplib
import logging
from typing import List, Dict
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)


class AlertEmailReporter:
    """Send individual alert emails via SMTP"""
    
    def __init__(self, smtp_server: str, smtp_port: int, sender: str, password: str, use_tls: bool = True):
        """Initialize email reporter with SMTP credentials
        
        Args:
            smtp_server: SMTP server hostname
            smtp_port: SMTP port (typically 587 for TLS)
            sender: Sender email address
            password: SMTP password or app-specific password
            use_tls: Whether to use TLS (default True)
        """
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender = sender
        self.password = password
        self.use_tls = use_tls
    
    def send_alert(self, recipient: str, subject: str, body: str) -> bool:
        """Send individual alert email
        
        Args:
            recipient: Email recipient address
            subject: Email subject line
            body: Email body content
        
        Returns:
            True if email sent successfully, False otherwise
        """
        
        try:
            msg = MIMEMultipart()
            msg['From'] = self.sender
            msg['To'] = recipient
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email via SMTP
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                server.login(self.sender, self.password)
                server.send_message(msg)
            
            logger.info(f"  ✅ Alert email sent to {recipient}")
            return True
            
        except Exception as e:
            logger.error(f"  ❌ Failed to send alert email to {recipient}: {e}")
            return False
    
    def send_batch_summary(self, recipient: str, client_name: str, alerts: List[Dict], alert_count: int) -> bool:
        """Send summary of alerts (optional digest mode)
        
        Args:
            recipient: Email recipient address
            client_name: Client name
            alerts: List of alerts
            alert_count: Total alert count
        
        Returns:
            True if email sent successfully, False otherwise
        """
        
        try:
            msg = MIMEMultipart()
            msg['From'] = self.sender
            msg['To'] = recipient
            msg['Subject'] = f"Alert Digest - {client_name}: {alert_count} alerts detected"
            
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            body = f"""Alert Digest Report

Client: {client_name}
Total Alerts (Level 12+): {alert_count}
Report Time: {timestamp} UTC

=============================

Alert Summary:

"""
            
            # Add alerts summary
            for idx, alert in enumerate(alerts[:10], 1):
                rule = alert.get('rule', {})
                agent = alert.get('agent', {})
                agent_name = agent.get('name', 'Unknown') if isinstance(agent, dict) else 'Unknown'
                timestamp_alert = alert.get('timestamp', 'Unknown')
                
                body += f"{idx}. [{rule.get('level', 'N/A')}] {rule.get('description', 'Unknown')}\n"
                body += f"   Host: {agent_name}\n"
                body += f"   Time: {timestamp_alert}\n\n"
            
            if alert_count > 10:
                body += f"\n... and {alert_count - 10} more alerts\n\n"
            
            body += "=============================\n\nPlease log into your Wazuh dashboard for detailed analysis.\n\nThank You."
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email via SMTP
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                server.login(self.sender, self.password)
                server.send_message(msg)
            
            logger.info(f"  ✅ Digest email sent to {recipient} with {alert_count} alerts")
            return True
            
        except Exception as e:
            logger.error(f"  ❌ Failed to send digest email: {e}")
            return False
