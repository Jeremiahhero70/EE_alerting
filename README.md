# Wazuh Alert System - Multi-Tenant

Professional alert monitoring system for level 12+ Wazuh events with intelligent email notification.

## Overview

This system monitors Wazuh for security events with level 12 and above, extracts key information, and sends professional formatted email alerts. Each alert is automatically formatted based on its type (VPN login, foreign login, brute force, privilege escalation, malware, etc).

## Features

- **Level 12+ Monitoring** - Only high-level critical and important alerts
- **Multi-Tenant Support** - Monitor multiple Wazuh clients simultaneously
- **Smart Formatting** - Automatic template selection based on alert type
- **Agent IP Enrichment** - Automatically adds agent IP information
- **Professional Templates** - Pre-built email templates for common alert types:
  - VPN Login alerts
  - Foreign/Unusual login alerts
  - Brute force attack alerts
  - Privilege escalation alerts
  - Malware detection alerts
  - Generic alerts

## Configuration

### Setup Instructions

1. **Copy the template**: `cp mt_config.template.yaml mt_config.yaml`
2. **Edit the configuration**: Update `mt_config.yaml` with your credentials and settings
3. **Credentials are ignored**: `mt_config.yaml` is in `.gitignore` to protect sensitive data

### Configuration Files

- `mt_config.yaml` - **Your configuration** (gitignored, never committed)
- `mt_config.template.yaml` - Template reference (use as a guide)

### Configuration Options

```yaml
# Email settings - SMTP credentials for alert delivery
email_server: "smtp.gmail.com"
email_port: 587
email_sender: "alerting@company.com"
email_password: "app-password"
email_use_tls: true

# Wazuh dashboard - Single shared connection
dashboard:
  host: "https://wazuh-server.local/"
  port: 9200
  username: "admin"
  password: "password"
  verify_ssl: false

# Alert configuration
alert_config:
  min_level: 12          # Minimum alert level to process
  lookback_hours: 24     # Look back how many hours

# Client configurations
clients:
  lab:
    enabled: true
    email_recipients: 
      - "admin@company.com"
      - "soc@company.com"
```

## Files

- `alert_monitor.py` - Main alert monitoring orchestrator
- `wazuh_connector.py` - Wazuh connectivity and query execution
- `alert_formatter.py` - Professional email template formatting
- `email_reporter.py` - SMTP email delivery
- `mt_config.yaml` - Configuration file

## Usage

```bash
python3 alert_monitor.py
```

### How It Works

1. **Query Phase**: Searches Wazuh for level 12+ alerts from the last `lookback_hours`
2. **Deduplication Phase**: Checks `alert_cache/` directory for alerts already sent
3. **Format Phase**: Selects appropriate email template based on alert type
4. **Send Phase**: Sends formatted email to configured recipients
5. **Cache Phase**: Records alert hash to prevent duplicate sends

### Alert Deduplication

The system prevents duplicate email alerts using a **smart hash-based cache** with time-bucketing:

#### How It Works

1. **Alert Fingerprinting with Time-Bucketing**: For each alert, the system combines:
   ```
   Rule ID | Agent ID | Hour Bucket → MD5 Hash
   ```
   The timestamp is **rounded to the nearest hour** to prevent exact duplicate spam while still alerting on recurring issues.
   
   Example:
   ```
   Alert at 14:23:15 → Rule 5101|Agent 002|14:00:00 → Hash ABC123
   Alert at 14:45:30 → Rule 5101|Agent 002|14:00:00 → Hash ABC123 (same hour = skip)
   Alert at 16:10:22 → Rule 5101|Agent 002|16:00:00 → Hash XYZ789 (different hour = send)
   ```

2. **Cache Checking**: Before sending an email:
   - Generates hash from the alert (with hour-bucketed timestamp)
   - Checks if hash exists in today's cache file
   - If found → **Skip email** (already sent this hour)
   - If new → **Send email** and add hash to cache

3. **Daily Rotation**: Cache files reset each day
   - `alert_cache/alerts_2025-11-12.json` → stored sent alert hashes
   - New day = new file, preventing infinite history

#### Why Time-Bucketing?

- **Reduces alert fatigue**: Same issue in the same hour = 1 email
- **Catches recurring problems**: Same issue in a different hour = new alert
- **Real-world example**: Foreign login at 2 PM and 2:30 PM = 1 email. Foreign login at 2 PM and 4 PM = 2 emails

#### Why Hashing?

- **Speed**: Hash comparison is instant (no data parsing)
- **Efficiency**: Small hash size vs storing full alert data
- **Accuracy**: Same alert in same hour = same hash (reliable deduplication)
- **Security**: Raw credentials/IPs not exposed in cache files

#### Example Scenario

Same foreign login alert, different times of day:
```
14:15:00 → Hash generated → Email sent ✉️  → Hash stored (hour 14)
14:45:00 → Hash exists in cache → Email skipped ⏭️  (same hour)
16:30:00 → NEW hash generated → Email sent ✉️  → Hash stored (hour 16)
16:55:00 → Hash exists in cache → Email skipped ⏭️  (same hour 16)
```

**Result**: 2 emails for the same login issue across different time periods, instead of 4!

### Configuration Notes

- `lookback_hours`: Set to 1-2 hours for frequent monitoring (deduplication prevents re-sends)
- `min_level`: 12 = medium/high, 13+ = critical (adjust as needed)
- Cache directory is NOT gitignored so you can inspect alert history

## Email Templates

### VPN Login Alert
```
User: odall@company.com
VPN: Yes
Provider: datacamp.co.uk
Country: Canada
IP Address: 84.14.76.52
Device: Windows 10
```

### Foreign Login Alert
```
Username: eng@company.com
Country: Rwanda
IP Address: 41.87.87.87
Device: windows
Result Status: Success
```

### Brute Force Attack Alert
```
Alert Level: CRITICAL
Source IP: 192.168.1.100
Target User(s): admin
Failed Attempts: 50
Target Host: production-server
```

### Privilege Escalation Alert
```
Alert Level: CRITICAL
User: john.doe
Command: sudo su -
Host: workstation-01
```

### Malware Detection Alert
```
Alert Level: CRITICAL
Threat Name: Trojan.Win32.Generic
File Path: C:\Users\Admin\Downloads\malware.exe
Host: desktop-02
```

## Alert Level Reference

- **Level 0-3**: Ignored
- **Level 4-7**: Info/Debug
- **Level 8-11**: Low Priority
- **Level 12-13**: Medium Priority (sent as HIGH)
- **Level 14+**: Critical Priority (sent as CRITICAL)

## Smart Template Selection

The system automatically selects the appropriate email template based on the alert description:

- **VPN keywords** → VPN Login template
- **Foreign/Unusual location keywords** → Foreign Login template
- **Brute Force keywords** → Brute Force template
- **Privilege/Escalation keywords** → Privilege Escalation template
- **Malware keywords** → Malware Detection template
- **No match** → Generic Alert template

## Field Extraction

For each alert, the system extracts and includes:

- User/Username
- Source IP / Destination IP
- Country/Location
- Device/OS
- Timestamp
- Rule Description
- Agent/Host name
- Status/Result


