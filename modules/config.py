#!/usr/bin/env python3
"""
Configuration module for Sysmon AI
Centralized configuration management for all components
"""

import os
from pathlib import Path
from typing import Dict, List, Any
import json

class SysmonAIConfig:
    """Centralized configuration for Sysmon AI"""
    
    def __init__(self):
        """Initialize configuration with defaults"""
        
        # Base directories
        self.BASE_DIR = Path(__file__).parent
        self.OUTPUT_DIR = Path(os.getenv('SYSMON_AI_OUTPUT_DIR', 'output'))
        self.LOGS_DIR = Path(os.getenv('SYSMON_AI_LOGS_DIR', 'logs'))
        self.TEMP_DIR = Path(os.getenv('SYSMON_AI_TEMP_DIR', 'temp'))
        
        # Create directories if they don't exist
        self.OUTPUT_DIR.mkdir(exist_ok=True)
        self.LOGS_DIR.mkdir(exist_ok=True)
        self.TEMP_DIR.mkdir(exist_ok=True)
        
        # API Configuration
        self.GROQ_API_KEY = os.getenv('GROQ_API_KEY')
        self.VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
        self.ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')
        
        # Logging Configuration
        self.LOG_LEVEL = os.getenv('SYSMON_AI_LOG_LEVEL', 'INFO')
        self.LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        self.LOG_FILE = self.LOGS_DIR / 'sysmon_ai.log'
        
        # Analysis Configuration
        self.DEFAULT_TIME_RANGE_HOURS = int(os.getenv('SYSMON_AI_TIME_RANGE', '24'))
        self.MAX_EVENTS_PER_ANALYSIS = int(os.getenv('SYSMON_AI_MAX_EVENTS', '100000'))
        self.ENABLE_AI_ANALYSIS = os.getenv('SYSMON_AI_ENABLE_AI', 'true').lower() == 'true'
        
        # Web Interface Configuration
        self.WEB_PORT = int(os.getenv('SYSMON_AI_WEB_PORT', '8501'))
        self.WEB_HOST = os.getenv('SYSMON_AI_WEB_HOST', 'localhost')
        
        # Report Configuration
        self.DEFAULT_REPORT_TYPE = os.getenv('SYSMON_AI_REPORT_TYPE', 'full')
        self.DEFAULT_REPORT_FORMAT = os.getenv('SYSMON_AI_REPORT_FORMAT', 'html')
        self.REPORT_CLASSIFICATION = os.getenv('SYSMON_AI_CLASSIFICATION', 'CONFIDENTIAL')
        
        # Windows Log Sources
        self.WINDOWS_LOGS = {
            'Security': {
                'channel': 'Security',
                'priority': 'high',
                'description': 'Windows Security Events'
            },
            'System': {
                'channel': 'System',
                'priority': 'medium',
                'description': 'Windows System Events'
            },
            'Application': {
                'channel': 'Application',
                'priority': 'low',
                'description': 'Windows Application Events'
            },
            'Sysmon': {
                'channel': 'Microsoft-Windows-Sysmon/Operational',
                'priority': 'critical',
                'description': 'Sysmon Operational Events'
            },
            'PowerShell': {
                'channel': 'Microsoft-Windows-PowerShell/Operational',
                'priority': 'high',
                'description': 'PowerShell Execution Events'
            },
            'Defender': {
                'channel': 'Microsoft-Windows-Windows Defender/Operational',
                'priority': 'high',
                'description': 'Windows Defender Events'
            },
            'TaskScheduler': {
                'channel': 'Microsoft-Windows-TaskScheduler/Operational',
                'priority': 'medium',
                'description': 'Scheduled Task Events'
            },
            'WinRM': {
                'channel': 'Microsoft-Windows-WinRM/Operational',
                'priority': 'high',
                'description': 'Windows Remote Management Events'
            },
            'RDP': {
                'channel': 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
                'priority': 'high',
                'description': 'Remote Desktop Connection Events'
            },
            'DNS': {
                'channel': 'Microsoft-Windows-DNS-Client/Operational',
                'priority': 'medium',
                'description': 'DNS Client Events'
            }
        }
        
        # Linux Log Sources
        self.LINUX_LOGS = {
            'Authentication': {
                'paths': ['/var/log/auth.log', '/var/log/secure'],
                'priority': 'critical',
                'description': 'Authentication and Authorization Events'
            },
            'System': {
                'paths': ['/var/log/syslog', '/var/log/messages'],
                'priority': 'high',
                'description': 'System Messages'
            },
            'Kernel': {
                'paths': ['/var/log/kern.log', '/var/log/dmesg'],
                'priority': 'medium',
                'description': 'Kernel Messages'
            },
            'Audit': {
                'paths': ['/var/log/audit/audit.log'],
                'priority': 'critical',
                'description': 'Linux Audit Events'
            },
            'Apache': {
                'paths': ['/var/log/apache2/access.log', '/var/log/apache2/error.log'],
                'priority': 'medium',
                'description': 'Apache Web Server Logs'
            },
            'Nginx': {
                'paths': ['/var/log/nginx/access.log', '/var/log/nginx/error.log'],
                'priority': 'medium',
                'description': 'Nginx Web Server Logs'
            },
            'Fail2Ban': {
                'paths': ['/var/log/fail2ban.log'],
                'priority': 'high',
                'description': 'Fail2Ban Security Events'
            },
            'UFW': {
                'paths': ['/var/log/ufw.log'],
                'priority': 'medium',
                'description': 'UFW Firewall Events'
            }
        }
        
        # Threat Detection Patterns
        self.THREAT_PATTERNS = {
            'process_injection': {
                'patterns': [
                    r'CreateRemoteThread',
                    r'VirtualAllocEx',
                    r'WriteProcessMemory',
                    r'SetWindowsHookEx',
                    r'QueueUserAPC',
                    r'NtMapViewOfSection',
                    r'RtlCreateUserThread'
                ],
                'severity': 'high',
                'mitre_tactics': ['TA0005'],
                'description': 'Process injection techniques'
            },
            'lateral_movement': {
                'patterns': [
                    r'psexec.*\\\\[\w\.-]+',
                    r'wmic.*process.*call.*create',
                    r'schtasks.*\\s.*\\\\[\w\.-]+',
                    r'net\s+use\s+\\\\[\w\.-]+',
                    r'powershell.*invoke-command.*computername'
                ],
                'severity': 'high',
                'mitre_tactics': ['TA0008'],
                'description': 'Lateral movement activities'
            },
            'privilege_escalation': {
                'patterns': [
                    r'SeDebugPrivilege',
                    r'SeTakeOwnershipPrivilege',
                    r'SeImpersonatePrivilege',
                    r'whoami\s+/priv',
                    r'runas\s+/user:',
                    r'sudo\s+su\s*-'
                ],
                'severity': 'high',
                'mitre_tactics': ['TA0004'],
                'description': 'Privilege escalation attempts'
            },
            'persistence': {
                'patterns': [
                    r'HKEY_.*\\Run',
                    r'schtasks.*create',
                    r'sc\s+create',
                    r'New-Service',
                    r'crontab\s+-e',
                    r'systemctl\s+enable'
                ],
                'severity': 'medium',
                'mitre_tactics': ['TA0003'],
                'description': 'Persistence mechanisms'
            },
            'defense_evasion': {
                'patterns': [
                    r'wevtutil.*clear-log',
                    r'powershell.*-encodedcommand',
                    r'rundll32.*javascript',
                    r'regsvr32.*scrobj\.dll',
                    r'certutil.*-decode'
                ],
                'severity': 'high',
                'mitre_tactics': ['TA0005'],
                'description': 'Defense evasion techniques'
            },
            'credential_access': {
                'patterns': [
                    r'mimikatz',
                    r'lsass\.exe',
                    r'sekurlsa::logonpasswords',
                    r'reg\s+save.*sam',
                    r'ntdsutil.*ifm.*create',
                    r'/etc/shadow',
                    r'/etc/passwd'
                ],
                'severity': 'critical',
                'mitre_tactics': ['TA0006'],
                'description': 'Credential access attempts'
            },
            'command_control': {
                'patterns': [
                    r'powershell.*downloadstring',
                    r'certutil.*urlcache',
                    r'bitsadmin.*download',
                    r'dns.*query.*txt',
                    r'nc\s+-l\s+-p\s+\d+'
                ],
                'severity': 'high',
                'mitre_tactics': ['TA0011'],
                'description': 'Command and control communications'
            },
            'data_exfiltration': {
                'patterns': [
                    r'powershell.*invoke-webrequest.*outfile',
                    r'wget\s+.*-O',
                    r'curl\s+.*-o',
                    r'scp\s+.*@',
                    r'ftp\s+.*put',
                    r'dropbox|onedrive|googledrive'
                ],
                'severity': 'high',
                'mitre_tactics': ['TA0010'],
                'description': 'Data exfiltration activities'
            }
        }
        
        # IOC Patterns
        self.IOC_PATTERNS = {
            'ip_addresses': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'domains': r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\b',
            'urls': r'https?://[^\s<>"{}|\\^`\[\]]+',
            'file_hashes': r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b',
            'registry_keys': r'HKEY_[A-Z_]+\\[\\A-Za-z0-9_\-\s]+',
            'file_paths': r'[C-Z]:\\[\\A-Za-z0-9\s_\-\.]+|/[/a-zA-Z0-9\s_\-\.]+',
            'email_addresses': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        }
        
        # MITRE ATT&CK Tactics
        self.MITRE_TACTICS = {
            'TA0001': 'Initial Access',
            'TA0002': 'Execution',
            'TA0003': 'Persistence',
            'TA0004': 'Privilege Escalation',
            'TA0005': 'Defense Evasion',
            'TA0006': 'Credential Access',
            'TA0007': 'Discovery',
            'TA0008': 'Lateral Movement',
            'TA0009': 'Collection',
            'TA0010': 'Exfiltration',
            'TA0011': 'Command and Control'
        }
        
        # Risk Assessment Weights
        self.RISK_WEIGHTS = {
            'critical_threats': 25,
            'high_threats': 10,
            'medium_threats': 5,
            'low_threats': 1,
            'lateral_movement': 15,
            'persistence_mechanisms': 10,
            'credential_access': 20,
            'data_exfiltration': 15,
            'command_control': 12
        }
        
        # Report Templates
        self.REPORT_TEMPLATES = {
            'executive': {
                'sections': ['executive_summary', 'risk_assessment', 'key_findings', 'recommendations'],
                'format': 'markdown',
                'audience': 'C-level executives'
            },
            'technical': {
                'sections': ['analysis_overview', 'threat_detections', 'mitre_mapping', 'ioc_analysis', 'timeline'],
                'format': 'html',
                'audience': 'SOC analysts and incident responders'
            },
            'full': {
                'sections': ['all'],
                'format': 'html',
                'audience': 'Security professionals'
            }
        }
        
        # Performance Settings
        self.PERFORMANCE = {
            'max_file_size_mb': 500,
            'max_memory_usage_mb': 2048,
            'parallel_processing': True,
            'max_workers': 4,
            'chunk_size': 1000,
            'timeout_seconds': 300
        }
        
    def get_log_sources(self, platform: str = None) -> Dict[str, Any]:
        """Get log sources for specific platform"""
        if platform == 'windows':
            return self.WINDOWS_LOGS
        elif platform == 'linux':
            return self.LINUX_LOGS
        else:
            return {**self.WINDOWS_LOGS, **self.LINUX_LOGS}
    
    def get_threat_patterns(self, category: str = None) -> Dict[str, Any]:
        """Get threat patterns for specific category"""
        if category:
            return self.THREAT_PATTERNS.get(category, {})
        return self.THREAT_PATTERNS
    
    def save_config(self, config_file: str = None):
        """Save current configuration to file"""
        if not config_file:
            config_file = self.BASE_DIR / 'config.json'
        
        config_data = {
            'api_keys': {
                'groq': bool(self.GROQ_API_KEY),
                'virustotal': bool(self.VIRUSTOTAL_API_KEY),
                'abuseipdb': bool(self.ABUSEIPDB_API_KEY)
            },
            'directories': {
                'output': str(self.OUTPUT_DIR),
                'logs': str(self.LOGS_DIR),
                'temp': str(self.TEMP_DIR)
            },
            'analysis': {
                'time_range_hours': self.DEFAULT_TIME_RANGE_HOURS,
                'max_events': self.MAX_EVENTS_PER_ANALYSIS,
                'enable_ai': self.ENABLE_AI_ANALYSIS
            },
            'web': {
                'port': self.WEB_PORT,
                'host': self.WEB_HOST
            },
            'reports': {
                'type': self.DEFAULT_REPORT_TYPE,
                'format': self.DEFAULT_REPORT_FORMAT,
                'classification': self.REPORT_CLASSIFICATION
            }
        }
        
        with open(config_file, 'w') as f:
            json.dump(config_data, f, indent=2)
    
    def load_config(self, config_file: str = None):
        """Load configuration from file"""
        if not config_file:
            config_file = self.BASE_DIR / 'config.json'
        
        if not Path(config_file).exists():
            return
        
        with open(config_file, 'r') as f:
            config_data = json.load(f)
        
        # Update configuration with loaded values
        directories = config_data.get('directories', {})
        if directories.get('output'):
            self.OUTPUT_DIR = Path(directories['output'])
        if directories.get('logs'):
            self.LOGS_DIR = Path(directories['logs'])
        if directories.get('temp'):
            self.TEMP_DIR = Path(directories['temp'])
        
        analysis = config_data.get('analysis', {})
        self.DEFAULT_TIME_RANGE_HOURS = analysis.get('time_range_hours', self.DEFAULT_TIME_RANGE_HOURS)
        self.MAX_EVENTS_PER_ANALYSIS = analysis.get('max_events', self.MAX_EVENTS_PER_ANALYSIS)
        self.ENABLE_AI_ANALYSIS = analysis.get('enable_ai', self.ENABLE_AI_ANALYSIS)
        
        web = config_data.get('web', {})
        self.WEB_PORT = web.get('port', self.WEB_PORT)
        self.WEB_HOST = web.get('host', self.WEB_HOST)
        
        reports = config_data.get('reports', {})
        self.DEFAULT_REPORT_TYPE = reports.get('type', self.DEFAULT_REPORT_TYPE)
        self.DEFAULT_REPORT_FORMAT = reports.get('format', self.DEFAULT_REPORT_FORMAT)
        self.REPORT_CLASSIFICATION = reports.get('classification', self.REPORT_CLASSIFICATION)

# Global configuration instance
config = SysmonAIConfig()
