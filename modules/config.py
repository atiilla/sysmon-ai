#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sysmon AI - Configuration Module
Centralized configuration management for all components
"""

import os
import logging
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Centralized configuration for Sysmon AI"""
    
    def __init__(self):
        """Initialize configuration and create necessary directories"""
        # Base directories
        self.BASE_DIR = Path(__file__).parent.parent.resolve()
        self.MODULES_DIR = self.BASE_DIR / 'modules'
        self.OUTPUT_DIR = self.BASE_DIR / 'output'
        self.LOGS_DIR = self.OUTPUT_DIR / 'logs'
        self.REPORTS_DIR = self.OUTPUT_DIR / 'reports'
        
        # Create output directories
        self.OUTPUT_DIR.mkdir(exist_ok=True)
        self.LOGS_DIR.mkdir(exist_ok=True)
        self.REPORTS_DIR.mkdir(exist_ok=True)
        
        # Sysmon configuration
        self.SYSMON_CFG = self.BASE_DIR / "sysmon_config.xml"
        self.EVENTLOG_NAME = "Microsoft-Windows-Sysmon/Operational"
        self.MAX_LOG_SIZE_BYTES = 1 * 1024 * 1024 * 1024  # 1 GiB
        self.OUTPUT_PREFIX = "Sysmon_Analysis"
        
        # API keys from environment variables
        self.GROQ_API_KEY = os.getenv("GROQ_API_KEY")
        self.VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
        self.ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
        
        # Report configuration
        self.REPORT_FORMATS = ["json", "html", "markdown", "pdf"]
        self.DEFAULT_REPORT_FORMAT = "markdown"
        
        # Web interface configuration
        self.WEB_PORT = int(os.getenv("SYSMON_AI_WEB_PORT", "8501"))
        self.WEB_HOST = os.getenv("SYSMON_AI_WEB_HOST", "localhost")
        
        # Logger configuration
        self.LOG_LEVEL = os.getenv("SYSMON_AI_LOG_LEVEL", "INFO")
        self.LOG_FILE = self.BASE_DIR / "sysmon_ai.log"
        
        # Output file names
        self.CSV_FILE = self.OUTPUT_DIR / "threat_lookup_results.csv"
        
        # Configure logging with proper encoding
        logging.basicConfig(
            level=getattr(logging, self.LOG_LEVEL),
            format="%(asctime)s [%(levelname)s] %(message)s",
            handlers=[
                logging.FileHandler(str(self.LOG_FILE), encoding="utf-8"),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger(__name__)
        
    def get_timestamp(self) -> str:
        """Get a formatted timestamp for file names"""
        return datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def get_log_path(self, prefix: Optional[str] = None) -> Path:
        """Get a path for a log file with timestamp"""
        prefix = prefix or self.OUTPUT_PREFIX
        return self.LOGS_DIR / f"{prefix}_{self.get_timestamp()}.tsv"
    
    def get_evtx_path(self, prefix: Optional[str] = None) -> Path:
        """Get a path for an EVTX file with timestamp"""
        prefix = prefix or self.OUTPUT_PREFIX
        return self.LOGS_DIR / f"{prefix}_{self.get_timestamp()}.evtx"
    
    def get_report_path(self, report_type: str = "threat", format: str = "markdown") -> Path:
        """Get a path for a report file with timestamp"""
        if format not in self.REPORT_FORMATS:
            format = self.DEFAULT_REPORT_FORMAT
            
        extension = {
            "json": "json",
            "html": "html",
            "markdown": "md",
            "pdf": "pdf"
        }.get(format, "md")
        
        return self.REPORTS_DIR / f"{report_type}_report_{self.get_timestamp()}.{extension}"
    
    def validate_api_keys(self) -> List[str]:
        """Validate that required API keys are available"""
        missing_keys = []
        if not self.GROQ_API_KEY:
            missing_keys.append("GROQ_API_KEY")
        if not self.VIRUSTOTAL_API_KEY:
            missing_keys.append("VIRUSTOTAL_API_KEY")
        if not self.ABUSEIPDB_API_KEY:
            missing_keys.append("ABUSEIPDB_API_KEY")
        
        return missing_keys
        
    def get_log_sources(self, platform: Optional[str] = None) -> Dict[str, Any]:
        """Get available log sources for a specific platform"""
        sources = {
            "windows": {
                "sysmon": {
                    "name": "Microsoft-Windows-Sysmon/Operational",
                    "description": "Sysmon Events"
                },
                "security": {
                    "name": "Security",
                    "description": "Windows Security Events"
                },
                "system": {
                    "name": "System",
                    "description": "Windows System Events"
                },
                "application": {
                    "name": "Application",
                    "description": "Windows Application Events"
                },
                "powershell": {
                    "name": "Microsoft-Windows-PowerShell/Operational",
                    "description": "PowerShell Events"
                }
            },
            "linux": {
                "syslog": {
                    "name": "/var/log/syslog",
                    "description": "System Log"
                },
                "auth": {
                    "name": "/var/log/auth.log",
                    "description": "Authentication Log"
                },
                "audit": {
                    "name": "/var/log/audit/audit.log",
                    "description": "Audit Log"
                }
            }
        }
        
        if platform:
            return sources.get(platform.lower(), {})
        return sources
    
    def get_threat_patterns(self, category: Optional[str] = None) -> Dict[str, Any]:
        """Get threat hunting patterns"""
        patterns = {
            "process_injection": [
                "CreateRemoteThread",
                "VirtualAllocEx",
                "WriteProcessMemory",
                "SetWindowsHookEx"
            ],
            "powershell_obfuscation": [
                "-encodedcommand",
                "frombase64string",
                "invoke-expression",
                "iex ",
                "downloadstring"
            ],
            "privilege_escalation": [
                "SeDebugPrivilege",
                "SeTakeOwnershipPrivilege",
                "SeImpersonatePrivilege"
            ],
            "suspicious_network": [
                "powershell.*New-Object.*Net.WebClient",
                "certutil.*-urlcache",
                "bitsadmin.*transfer"
            ],
            "evasion_techniques": [
                "vssadmin.*delete.*shadows",
                "wevtutil.*clear-log",
                "wmic.*shadowcopy.*delete"
            ]
        }
        
        if category:
            return {category: patterns.get(category, [])} if category in patterns else {}
        return patterns
    
    def validate_api_keys(self) -> List[str]:
        """Validate that required API keys are available"""
        missing_keys = []
        
        if not self.GROQ_API_KEY:
            missing_keys.append("GROQ_API_KEY")
        if not self.VIRUSTOTAL_API_KEY:
            missing_keys.append("VIRUSTOTAL_API_KEY")
        if not self.ABUSEIPDB_API_KEY:
            missing_keys.append("ABUSEIPDB_API_KEY")
        
        return missing_keys
    
    def has_threat_intel_keys(self) -> bool:
        """Check if threat intelligence API keys are available"""
        return bool(self.VIRUSTOTAL_API_KEY or self.ABUSEIPDB_API_KEY)


# Create a singleton instance for global access
config = Config()
