#!/usr/bin/env python3
"""
Wazuh Connector for Alert Monitoring
Handles multi-tenant Wazuh dashboard connections for level 12+ alerts
"""

import requests
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class WazuhAlertConnector:
    """Wazuh connector for querying and retrieving high-level alerts"""
    
    def __init__(self, dashboard_config: Dict[str, Any]):
        """Initialize connector with shared dashboard configuration
        
        Args:
            dashboard_config: Shared dashboard configuration dict containing:
                - host: Wazuh dashboard host
                - port: Wazuh dashboard port (default 9200)
                - username: Authentication username
                - password: Authentication password
                - verify_ssl: SSL verification (default False)
        """
        host = dashboard_config.get('host', 'localhost')
        port = dashboard_config.get('port', 9200)
        user = dashboard_config.get('username', 'admin')
        password = dashboard_config.get('password', '')
        
        # Remove https:// prefix if already included in host
        host = host.replace('https://', '').replace('http://', '').rstrip('/')
        
        self.base_url = f"https://{host}:{port}"
        self.auth = (user, password)
        self.verify_ssl = dashboard_config.get('verify_ssl', False)
        self.timeout = 30
    
    def search_alerts(self, client_name: str, min_level: int = 12, hours: int = 24, size: int = 5000) -> Dict[str, Any]:
        """Search for alerts with minimum level threshold
        
        Args:
            client_name: Client identifier (e.g., "lab", "homelab")
            min_level: Minimum alert level (default 12)
            hours: Number of hours to look back (default 24)
            size: Max results to return (default 5000)
        
        Returns:
            Dictionary with:
                - total: Total number of alerts found
                - alerts: List of alert documents
                - error: Error message if query failed (optional)
        """
        try:
            # Build client-specific alert index pattern
            index_pattern = f"{client_name}:wazuh-alerts-*"
            search_url = f"{self.base_url}/{index_pattern}/_search"
            
            # Query for alerts with minimum level
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {
                                "range": {
                                    "rule.level": {
                                        "gte": min_level
                                    }
                                }
                            },
                            {
                                "range": {
                                    "timestamp": {
                                        "gte": f"now-{hours}h",
                                        "lt": "now"
                                    }
                                }
                            }
                        ]
                    }
                },
                "size": size,
                "sort": [{"timestamp": {"order": "desc"}}]
            }
            
            response = requests.post(
                search_url,
                auth=self.auth,
                json=query,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            data = response.json()
            total_hits = data.get("hits", {}).get("total", {}).get("value", 0)
            hits = data.get("hits", {}).get("hits", [])
            
            logger.info(f"✅ Retrieved {len(hits)} alerts (level {min_level}+) for {client_name}")
            
            return {
                'total': total_hits,
                'alerts': [hit.get('_source', {}) for hit in hits]
            }
            
        except Exception as e:
            logger.error(f"Error retrieving alerts for {client_name}: {e}")
            return {
                'total': 0,
                'alerts': [],
                'error': str(e)
            }
