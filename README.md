# Sysmon AI - Advanced Threat Hunting Platform

![Version](https://img.shields.io/badge/version-1.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)

**Sysmon AI** is a comprehensive, multi-platform threat hunting and log analysis platform designed for cybersecurity professionals. It combines advanced pattern detection, AI-powered analysis, threat intelligence feeds, and automated reporting to provide deep insights into security events across Windows and Linux environments.

## Overview

Sysmon AI provides both a powerful CLI tool and an interactive web interface for analyzing Windows Sysmon logs and other security events. The platform uses AI-powered analysis to detect suspicious patterns, extract Indicators of Compromise (IOCs), analyze network connections with threat intelligence feeds, and generate comprehensive threat reports.

## Features

### Key Features
- **Multi-Platform Support**: Windows Event logs, Sysmon, PowerShell, Security logs
- **AI-Powered Analysis**: Integration with Groq for advanced threat detection and analysis
- **Threat Intelligence Integration**: VirusTotal and AbuseIPDB integration for IP/domain/hash analysis
- **Automated IP Extraction**: Extract and analyze IPs from Sysmon network connections
- **Modular Architecture**: Well-structured codebase for easy extensibility
- **Interactive Web UI**: User-friendly Streamlit interface for visualization and analysis
- **Comprehensive CLI**: Command-line interface for automation and scripting
- **Threat Hunting**: Advanced pattern detection and IOC extraction
- **Detailed Reporting**: Executive summaries, technical reports, and PDF threat intelligence reports
- **Linux**: Auth logs, Syslog, Audit logs, Application logs
- **Network**: Firewall logs, DNS logs, Proxy logs, IDS/IPS logs

### Threat Intelligence Features
- **Automated IP Analysis**: Extract IPs from Sysmon logs and analyze with threat intelligence feeds
- **VirusTotal Integration**: Domain, IP, and file hash analysis
- **AbuseIPDB Integration**: IP reputation and abuse history checking
- **Safe IP Filtering**: Automatically filter out known safe IPs (CDNs, DNS servers, cloud providers)
- **Batch Analysis**: Analyze multiple IPs, domains, or hashes from files
- **PDF Report Generation**: Professional threat intelligence reports with analysis results

### Advanced Threat Hunting
- **MITRE ATT&CK Framework** mapping and analysis
- **Lateral Movement** detection and visualization
- **Persistence Mechanism** identification
- **Command & Control** communication analysis
- **Data Exfiltration** pattern detection
- **Process Injection** technique identification
- **Network Connection Analysis** with threat intelligence correlation

### AI-Powered Analysis
- **Groq AI Integration** for intelligent threat analysis
- **Automated IOC Extraction** from logs
- **Context-Aware Recommendations** for incident response
- **Natural Language Insights** for threat descriptions

### Professional Reporting
- **Executive Summaries** for C-level stakeholders
- **Technical Analysis Reports** for SOC analysts
- **Threat Intelligence Reports** with IOC analysis
- **Threat Hunting Playbooks** for security teams
- **MISP Event Generation** for threat intelligence sharing
- **SIEM Rule Generation** for automated detection

## Installation

### Prerequisites
- Python 3.8 or higher
- Administrative privileges (for log collection)
- Groq API key (optional, for AI analysis)

### Quick Install
```bash
git clone https://github.com/atiilla/sysmon-ai.git
cd sysmon-ai
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
pip install -r requirements.txt
```

## Quick Start

### 1. Basic EVTX Analysis
```bash
# Analyze a single EVTX file
python app.py analyze -f sample.evtx -o results.json

# With AI analysis
python app.py analyze -f sample.evtx -a -o results.json
```

### 2. Comprehensive Threat Hunting
```bash
# Full system analysis with log collection
python app.py hunt -a

# Generate executive report
python app.py hunt --report-type executive -o hunt_report.md
```

### 3. Web Interface
```bash
# Launch interactive web interface
python app.py web

# Open browser to http://localhost:8501
```

## Usage Examples

### Basic Log Collection and Analysis
```bash
# Collect Sysmon logs for the past 24 hours
python sysmon_cli.py collect --time-range 24

# Collect logs with IP threat intelligence analysis
python sysmon_cli.py collect --time-range 48 --analyze-ips --sysmon-only

# Analyze existing EVTX file
python sysmon_cli.py analyze sample.evtx --ai --output results.json
```

### Threat Intelligence Analysis
```bash
# Extract and analyze IPs from existing Sysmon logs
python sysmon_cli.py intel --extract-ips

# Analyze IPs from a file
python sysmon_cli.py intel --ip-file suspicious_ips.txt

# Analyze a single IP, domain, or hash
python sysmon_cli.py intel --single-ip 192.168.1.100
python sysmon_cli.py intel --single-domain malicious.com
python sysmon_cli.py intel --single-hash abc123def456...

# Generate PDF report from existing analysis
python sysmon_cli.py intel --generate-pdf
```

### Advanced Threat Hunting
```bash
# Comprehensive threat hunting with log collection and AI analysis
python sysmon_cli.py hunt --collect-logs --time-range 72 --report-type full

# Hunt using existing EVTX file
python sysmon_cli.py hunt --evtx-file sample.evtx --format markdown
```

### Setup and Configuration
```bash
# Install Sysmon with default configuration
python sysmon_cli.py setup --install-sysmon

# Install with custom configuration
python sysmon_cli.py setup --install-sysmon --sysmon-config custom_config.xml

# Uninstall Sysmon
python sysmon_cli.py setup --uninstall
```

### Web Interface
```bash
# Launch interactive web interface
python sysmon_cli.py web --port 8501

# Launch on different host/port
python sysmon_cli.py web --host 0.0.0.0 --port 8080
```

## Key Features

### Threat Intelligence Integration
- **VirusTotal API**: Domain, IP address, and file hash reputation checking
- **AbuseIPDB API**: IP address abuse confidence scoring and reporting history
- **Automated Filtering**: Smart filtering of safe IPs (CDNs, DNS servers, cloud providers)
- **Batch Processing**: Analyze multiple indicators efficiently with rate limiting
- **Professional Reports**: Generate PDF reports with analysis results and recommendations

### Threat Detection Patterns
- **Process Injection**: CreateRemoteThread, VirtualAllocEx, WriteProcessMemory
- **Network Connections**: Outbound connections, DNS queries, suspicious IPs
- **Lateral Movement**: PSExec, WMI, Remote tasks, Network shares
- **Privilege Escalation**: Token manipulation, Service creation, LSASS access
- **Defense Evasion**: Log clearing, PowerShell obfuscation, DLL hijacking
- **Command & Control**: DNS tunneling, HTTP beaconing, Encrypted communications

### IOC Extraction and Analysis
- **Network IOCs**: IP Addresses, Domain Names, Network connections
- **File IOCs**: File Hashes, File Paths, Process information
- **Registry IOCs**: Registry Keys, Registry modifications
- **Behavioral IOCs**: Process patterns, Command lines, Parent-child relationships
- **Threat Intelligence Correlation**: Automatic lookup and scoring of extracted IOCs

### Report Types
- **Executive Summary**: Risk assessment, Key findings, Business impact
- **Technical Analysis**: Detailed detections, MITRE mapping, Timeline reconstruction
- **Threat Intelligence Report**: IOC analysis, reputation scores, threat actor attribution
- **Hunting Playbook**: Investigation procedures, SIEM queries, IOC watchlists
- **SIEM Integration**: Splunk queries, Elasticsearch searches, Sigma rules

## Incident Response Workflow

1. **Detection**: Run comprehensive log collection with threat intelligence analysis
2. **Analysis**: Map to MITRE ATT&CK, correlate with threat feeds, reconstruct timeline
3. **Intelligence**: Analyze extracted IOCs for threat actor attribution and TTPs
4. **Response**: Follow playbooks, implement SIEM rules, share IOCs with threat intelligence platforms
5. **Recovery**: Patch vulnerabilities, update signatures, improve security posture

## Command Line Interface

Sysmon AI provides a comprehensive command-line interface with the following commands:

```
usage: app.py [-h] {analyze,collect,hunt,web,setup} ...

Sysmon AI - Advanced Threat Hunting Platform

positional arguments:
  {analyze,collect,hunt,web,setup}
                        Command to execute
    analyze             Analyze EVTX log file
    collect             Collect Sysmon logs
    hunt                Hunt for threats in logs
    web                 Start web interface
    setup               Setup and configure tool

optional arguments:
  -h, --help            show this help message and exit

Example usage:
  sysmon_ai analyze -f sysmon_logs.evtx
  sysmon_ai collect -t 24
  sysmon_ai hunt -f sysmon_logs.evtx
  sysmon_ai web
```

### Analyze Command
Analyzes an EVTX file for suspicious events and patterns:

```bash
python app.py analyze -f path/to/sysmon.evtx [-s] [-a] [-o output.json]
```

Options:
- `-f, --file`: Path to EVTX file (required)
- `-s, --simple`: Simple analysis mode
- `-a, --ai`: Use AI for enhanced analysis
- `-o, --output`: Output file for results

### Collect Command
Collects Sysmon logs from the system:

```bash
python app.py collect [-t HOURS] [-m MAX_EVENTS] [-o output.json]
```

Options:
- `-t, --time`: Time range in hours (default: 24)
- `-m, --max-events`: Maximum number of events to collect
- `-o, --output`: Output file for collected logs

### Hunt Command
Performs comprehensive threat hunting:

```bash
python app.py hunt [-f FILE] [-a] [-r {executive,technical,full}] [-o output.md]
```

Options:
- `-f, --file`: Path to EVTX file (optional)
- `-a, --ai`: Use AI for enhanced hunting
- `-r, --report-type`: Type of report to generate
- `-o, --output`: Output file for results

### Web Interface Command
Launches the Streamlit web interface:

```bash
python app.py web [-p PORT]
```

Options:
- `-p, --port`: Port for web interface (default: 8501)

### Setup Command
Configures the tool settings:

```bash
python app.py setup [--config]
```

Options:
- `--config`: Configure API keys and settings

## Modular Architecture

Sysmon AI has been designed with a modular architecture for maintainability and extensibility:

- **app.py**: Main entry point for the application
- **sysmon_cli.py**: Command-line interface implementation
- **modules/config.py**: Configuration management
- **modules/groq_analyzer.py**: AI-powered log analysis
- **modules/log_collector.py**: Log collection functionality
- **modules/threat_hunter.py**: Threat hunting capabilities
- **modules/report_generator.py**: Report generation
- **modules/streamlit_app.py**: Web interface

This modular approach makes it easy to extend the functionality of the application with new features and capabilities.

## Built for Cybersecurity Professionals

Sysmon AI is built for cybersecurity professionals who need comprehensive, automated threat hunting capabilities with professional reporting suitable for executive briefings and technical analysis.
