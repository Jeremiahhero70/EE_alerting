#!/usr/bin/env python3
"""
Alert Formatter for Wazuh Events
Simple field extraction and email formatting
"""

import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


class AlertFormatter:
    """Format Wazuh alerts into simple email format"""
    
    @staticmethod
    def extract_fields(alert: Dict[str, Any]) -> Dict[str, Any]:
        """Extract common fields from Wazuh alert
        
        Args:
            alert: Wazuh alert document
            
        Returns:
            Dictionary with extracted fields
        """
        try:
            data = alert.get('data', {})
            rule = alert.get('rule', {})
            agent = alert.get('agent', {})
            
            # Extract common fields
            fields = {
                'timestamp': alert.get('timestamp', 'Unknown'),
                'rule_id': rule.get('id', 'Unknown'),
                'rule_level': rule.get('level', 'Unknown'),
                'rule_description': rule.get('description', 'Unknown'),
                'agent_name': agent.get('name', 'Unknown'),
                'agent_id': agent.get('id', 'Unknown'),
                'agent_ip': agent.get('ip', 'Unknown'),
                'source_ip': alert.get('source', {}).get('ip', 'Unknown'),
                'destination_ip': alert.get('destination', {}).get('ip', 'Unknown'),
                'user': data.get('user', 'Unknown'),
                'command': data.get('command', 'Unknown'),
                'process': data.get('process', 'Unknown'),
                'file': data.get('file', 'Unknown'),
            }
            
            return fields
        except Exception as e:
            logger.warning(f"Error extracting fields: {e}")
            return {}
    
    @staticmethod
    def format_email(alert: Dict[str, Any]) -> str:
        """Format alert into simple email body
        
        Args:
            alert: Wazuh alert document
            
        Returns:
            Formatted email body as string
        """
        try:
            fields = AlertFormatter.extract_fields(alert)
            
            # Build email content
            email_lines = [
                "=" * 70,
                f"WAZUH ALERT - Level {fields.get('rule_level')}",
                "=" * 70,
                "",
                "Alert Details:",
                f"  Timestamp:       {fields.get('timestamp')}",
                f"  Rule ID:         {fields.get('rule_id')}",
                f"  Description:     {fields.get('rule_description')}",
                f"  Agent:           {fields.get('agent_name')} ({fields.get('agent_ip')})",
                "",
                "Event Information:",
            ]
            
            # Add optional fields if present
            if fields.get('source_ip') != 'Unknown':
                email_lines.append(f"  Source IP:       {fields.get('source_ip')}")
            if fields.get('destination_ip') != 'Unknown':
                email_lines.append(f"  Destination IP:  {fields.get('destination_ip')}")
            if fields.get('user') != 'Unknown':
                email_lines.append(f"  User:            {fields.get('user')}")
            if fields.get('command') != 'Unknown':
                email_lines.append(f"  Command:         {fields.get('command')}")
            if fields.get('process') != 'Unknown':
                email_lines.append(f"  Process:         {fields.get('process')}")
            if fields.get('file') != 'Unknown':
                email_lines.append(f"  File:            {fields.get('file')}")
            
            email_lines.extend([
                "",
                "=" * 70,
                "Please investigate this alert.",
                "=" * 70,
            ])
            
            return "\n".join(email_lines)
        
        except Exception as e:
            logger.error(f"Error formatting email: {e}")
            return f"Error formatting alert email: {e}"
