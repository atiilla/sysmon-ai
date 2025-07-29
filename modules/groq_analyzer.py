#!/usr/bin/env python3
"""
Groq Analyzer Module
AI-powered Sysmon log analysis using Groq API
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
import xml.etree.ElementTree as ET

try:
    import Evtx.Evtx as evtx
    import Evtx.Views as e_views
except ImportError:
    evtx = None
    e_views = None

class SysmonAnalyzer:
    """Main analyzer class for Sysmon logs using AI"""
    
    def __init__(self, groq_api_key: str = None):
        """Initialize the analyzer
        
        Args:
            groq_api_key: API key for Groq service
        """
        self.logger = logging.getLogger(__name__)
        self.groq_api_key = groq_api_key
        
        # Detection patterns for suspicious activities
        self.suspicious_patterns = {
            'process_injection': [
                'CreateRemoteThread',
                'VirtualAllocEx',
                'WriteProcessMemory',
                'SetWindowsHookEx',
                'NtCreateThreadEx',
                'RtlCreateUserThread',
                'QueueUserAPC',
                'SuspendThread',
                'ResumeThread',
                'Process Hollowing',
                'DLL Injection',
                'Reflective DLL'
            ],
            'powershell_obfuscation': [
                'EncodedCommand',
                'FromBase64String',
                'Invoke-Expression',
                'DownloadString',
                'DownloadFile',
                'WebClient',
                'Net.WebClient',
                'IEX',
                'Invoke-Obfuscation',
                'powershell -enc',
                'powershell -e',
                'hidden',
                'bypass',
                'unrestricted',
                'noprofile',
                'windowstyle hidden'
            ],
            'privilege_escalation': [
                'SeDebugPrivilege',
                'SeTakeOwnershipPrivilege',
                'SeImpersonatePrivilege',
                'SeAssignPrimaryTokenPrivilege',
                'SeLoadDriverPrivilege',
                'SeRestorePrivilege',
                'SeBackupPrivilege',
                'SeTcbPrivilege',
                'UAC Bypass',
                'Token Manipulation',
                'Access Token Manipulation',
                'runas',
                'psexec'
            ],
            'dcsync_attack': [
                'mimikatz',
                'lsadump::dcsync',
                'powerview',
                'Add-DomainObjectAcl',
                'Get-DomainObjectAcl',
                'drsuapi',
                'DsGetNCChanges',
                'DS-Replication-Get-Changes',
                'Replicating Directory Changes',
                'Directory Replication Service',
                'DRSR',
                'GetNCChanges',
                'DRS_MSG_GETCHGREQ',
                'DsReplicaGetInfo',
                'ntdsutil',
                'vssadmin',
                'diskshadow',
                'ntds.dit'
            ],
            'credential_dumping': [
                'lsass.exe',
                'procdump',
                'comsvcs.dll',
                'MiniDump',
                'sekurlsa',
                'logonpasswords',
                'kerberos::list',
                'crypto::capi',
                'lsadump::sam',
                'lsadump::cache',
                'lsadump::secrets',
                'hashdump',
                'pwdump',
                'fgdump',
                'gsecdump',
                'wce.exe',
                'mimikittenz',
                'LaZagne',
                'Windows Credential Manager'
            ],
            'acl_manipulation': [
                'Add-DomainObjectAcl',
                'Set-DomainObjectOwner',
                'Add-ObjectAcl',
                'dacledit',
                'DACL',
                'Access Control List',
                'GenericAll',
                'WriteDacl',
                'WriteOwner',
                'FullControl',
                'TakeOwnership',
                'ChangePermissions',
                'Modify',
                'icacls',
                'takeown',
                'SetACL'
            ],
            'log_tampering': [
                'EventLog',
                'Clear-EventLog',
                'wevtutil',
                'log cleared',
                'Remove-EventLog',
                'Limit-EventLog',
                'auditpol',
                'Security log cleared',
                'Event log service',
                'Windows Event Log'
            ],
            'lateral_movement': [
                'psexec',
                'wmic',
                'schtasks',
                'at.exe',
                'WinRM',
                'PowerShell Remoting',
                'Enter-PSSession',
                'Invoke-Command',
                'New-PSSession',
                'RDP',
                'Remote Desktop',
                'net use',
                'net view',
                'SMB',
                'admin$',
                'c$',
                'ipc$'
            ],
            'persistence': [
                'schtasks',
                'at.exe',
                'sc.exe',
                'reg add',
                'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                'Startup folder',
                'WMI Event',
                'New-Service',
                'Set-Service',
                'winlogon',
                'userinit',
                'shell',
                'AppInit_DLLs',
                'DLL Search Order Hijacking'
            ],
            'defense_evasion': [
                'Disable-WindowsOptionalFeature',
                'Set-MpPreference',
                'Disable Windows Defender',
                'Uninstall-WindowsFeature',
                'Stop-Service',
                'sc stop',
                'taskkill',
                'ProcessHacker',
                'Process Hacker',
                'Sysinternals',
                'PsKill',
                'rootkit',
                'Anti-VM',
                'Anti-Debug',
                'Packing',
                'UPX'
            ],
            'reconnaissance': [
                'whoami',
                'ipconfig',
                'systeminfo',
                'tasklist',
                'net user',
                'net group',
                'net localgroup',
                'net share',
                'quser',
                'query user',
                'nltest',
                'dsquery',
                'ldapsearch',
                'Get-ADUser',
                'Get-ADGroup',
                'Get-ADComputer',
                'bloodhound',
                'SharpHound'
            ],
            'data_exfiltration': [
                'bitsadmin',
                'certutil',
                'curl',
                'wget',
                'Invoke-WebRequest',
                'Start-BitsTransfer',
                'Copy-Item',
                'robocopy',
                'xcopy',
                'WinSCP',
                'FileZilla',
                'FTP',
                'SFTP',
                'SCP',
                'rsync'
            ],
            'network_scanning': [
                'nmap',
                'masscan',
                'zmap',
                'ping',
                'Test-NetConnection',
                'telnet',
                'nc.exe',
                'netcat',
                'portscan',
                'port scan',
                'nslookup',
                'dig',
                'Resolve-DnsName'
            ],
            'web_exploitation': [
                'SQL Injection',
                'XSS',
                'CSRF',
                'LFI',
                'RFI',
                'Path Traversal',
                'Directory Traversal',
                'Command Injection',
                'Code Injection',
                'File Upload',
                'Unrestricted File Upload',
                'webshell',
                'Web Shell'
            ],
            'malware_execution': [
                'rundll32',
                'regsvr32',
                'mshta',
                'cscript',
                'wscript',
                'powershell',
                'cmd.exe',
                'conhost.exe',
                'suspicious process',
                'living off the land',
                'LOLBins',
                'LOLBAS'
            ]
        }
    
    def analyze_evtx(self, evtx_path: Path, detailed: bool = False) -> Dict[str, Any]:
        """Analyze EVTX file for suspicious activities
        
        Args:
            evtx_path: Path to EVTX file
            detailed: Whether to perform detailed analysis
            
        Returns:
            Analysis results dictionary
        """
        self.logger.info(f"Analyzing EVTX file: {evtx_path} (detailed={detailed})")
        
        if evtx is None:
            self.logger.warning("python-evtx not installed, using fallback parser")
            return self._analyze_fallback(evtx_path, detailed)
        
        results = {
            'file_path': str(evtx_path),
            'analysis_timestamp': datetime.now().isoformat(),
            'total_events': 0,
            'suspicious_events': [],
            'threat_categories': {},
            'ai_analysis': None,
            'detailed_analysis': detailed,
            'event_summary': {},
            'process_tree': [],
            'network_connections': [],
            'file_operations': []
        }
        
        try:
            with evtx.Evtx(str(evtx_path)) as log:
                for record in log.records():
                    results['total_events'] += 1
                    
                    # Parse event XML
                    event_xml = record.xml()
                    event_id = self._extract_event_id(event_xml)
                    
                    # Track event summary
                    if event_id not in results['event_summary']:
                        results['event_summary'][event_id] = 0
                    results['event_summary'][event_id] += 1
                    
                    # Detailed analysis
                    if detailed:
                        self._extract_detailed_info(event_xml, event_id, results)
                    
                    suspicious_indicators = self._detect_suspicious_activity(event_xml)
                    
                    if suspicious_indicators:
                        event_data = {
                            'event_id': event_id,
                            'timestamp': self._extract_timestamp(event_xml),
                            'indicators': suspicious_indicators,
                            'raw_xml': event_xml[:1000] if not detailed else event_xml,
                            'process_info': self._extract_process_info(event_xml) if detailed else {},
                            'network_info': self._extract_network_info(event_xml) if detailed else {},
                            'file_info': self._extract_file_info(event_xml) if detailed else {}
                        }
                        results['suspicious_events'].append(event_data)
                        
                        # Categorize threats
                        for category in suspicious_indicators:
                            if category not in results['threat_categories']:
                                results['threat_categories'][category] = 0
                            results['threat_categories'][category] += 1
            
            # Perform AI analysis if API key available
            if self.groq_api_key and results['suspicious_events']:
                results['ai_analysis'] = self._perform_ai_analysis(results['suspicious_events'])
            
            self.logger.info(f"Analysis complete: {len(results['suspicious_events'])} suspicious events found")
            return results
            
        except Exception as e:
            self.logger.error(f"Error analyzing EVTX: {str(e)}")
            raise
    
    def _analyze_fallback(self, evtx_path: Path, detailed: bool = False) -> Dict[str, Any]:
        """Fallback analysis method when python-evtx is not available"""
        self.logger.info("Using fallback analysis method")
        
        return {
            'file_path': str(evtx_path),
            'analysis_timestamp': datetime.now().isoformat(),
            'total_events': 0,
            'suspicious_events': [],
            'threat_categories': {},
            'ai_analysis': "Analysis requires python-evtx package. Install with: pip install python-evtx",
            'status': 'fallback_mode',
            'detailed_analysis': detailed,
            'event_summary': {},
            'process_tree': [],
            'network_connections': [],
            'file_operations': []
        }
    
    def _detect_suspicious_activity(self, event_xml: str) -> List[str]:
        """Detect suspicious patterns in event XML
        
        Args:
            event_xml: Raw event XML string
            
        Returns:
            List of detected threat categories
        """
        detected_threats = []
        
        # Check for text-based patterns
        for category, patterns in self.suspicious_patterns.items():
            for pattern in patterns:
                if pattern.lower() in event_xml.lower():
                    detected_threats.append(category)
                    break
        
        # Specific Windows Security Event analysis
        event_id = self._extract_event_id(event_xml)
        
        # Event 1102: Security log cleared - highly suspicious
        if event_id == "1102":
            detected_threats.append("log_tampering")
        
        # Event 4624: Successful logon - check for suspicious patterns
        elif event_id == "4624":
            if self._is_suspicious_4624_event(event_xml):
                detected_threats.append("lateral_movement")
        
        # Event 4625: Failed logon - potential brute force
        elif event_id == "4625":
            detected_threats.append("reconnaissance")
        
        # Event 4648: Logon with explicit credentials
        elif event_id == "4648":
            detected_threats.append("lateral_movement")
        
        # Event 4662: Directory Service Object Access - check for DCSync indicators
        elif event_id == "4662":
            if self._is_dcsync_4662_event(event_xml):
                detected_threats.append("dcsync_attack")
        
        # Event 4672: Special privileges assigned to new logon
        elif event_id == "4672":
            if self._is_suspicious_4672_event(event_xml):
                detected_threats.append("privilege_escalation")
        
        # Event 4688: Process creation
        elif event_id == "4688":
            if self._is_suspicious_4688_event(event_xml):
                detected_threats.extend(self._analyze_process_creation(event_xml))
        
        # Event 4697: Service installed
        elif event_id == "4697":
            detected_threats.append("persistence")
        
        # Event 4698/4699: Scheduled task created/deleted
        elif event_id in ["4698", "4699"]:
            detected_threats.append("persistence")
        
        # Event 4720: User account created
        elif event_id == "4720":
            detected_threats.append("persistence")
        
        # Event 4732/4728: User added to group
        elif event_id in ["4732", "4728"]:
            if self._is_privileged_group_addition(event_xml):
                detected_threats.append("privilege_escalation")
        
        # Event 4769: Kerberos service ticket requested
        elif event_id == "4769":
            if self._is_suspicious_kerberos_event(event_xml):
                detected_threats.append("lateral_movement")
        
        # Event 5136: Directory Service Object Modified - check for ACL changes
        elif event_id == "5136":
            if self._is_suspicious_5136_event(event_xml):
                detected_threats.append("acl_manipulation")
        
        # Event 5140: Network share accessed
        elif event_id == "5140":
            if self._is_suspicious_share_access(event_xml):
                detected_threats.append("lateral_movement")
        
        # Event 5156: Network connection allowed
        elif event_id == "5156":
            if self._is_suspicious_network_connection(event_xml):
                detected_threats.append("data_exfiltration")
        
        return detected_threats
    
    def _is_dcsync_4662_event(self, event_xml: str) -> bool:
        """Check if Event 4662 indicates DCSync activity"""
        try:
            # Look for Directory Service access with replication rights
            if "ObjectServer\">DS<" in event_xml:
                # Check for GUID that indicates replication permissions
                # 19195a5b-6da0-11d0-afd3-00c04fd930c9 is DS-Replication-Get-Changes
                dcsync_guids = [
                    "19195a5b-6da0-11d0-afd3-00c04fd930c9",  # DS-Replication-Get-Changes
                    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes-All
                    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes-In-Filtered-Set
                ]
                
                for guid in dcsync_guids:
                    if guid.lower() in event_xml.lower():
                        return True
                
                # Also check for suspicious access masks that indicate replication
                # Access mask 0x00000100 or similar for directory replication
                if "AccessMask\">0x00000100<" in event_xml or "AccessMask\">0x00040000<" in event_xml:
                    return True
            
            return False
        except:
            return False
    
    def _is_suspicious_5136_event(self, event_xml: str) -> bool:
        """Check if Event 5136 indicates suspicious ACL manipulation"""
        try:
            # Look for DACL or ACL modifications
            if any(indicator in event_xml.lower() for indicator in [
                "dacl", "acl", "access control", "permissions",
                "ds-replication-get-changes", "genericall", "writedacl"
            ]):
                return True
            return False
        except:
            return False
    
    def _is_suspicious_4624_event(self, event_xml: str) -> bool:
        """Check if Event 4624 indicates suspicious logon"""
        try:
            # Look for suspicious logon types or accounts
            suspicious_indicators = [
                "logontype\">3<",  # Network logon
                "logontype\">10<", # Remote interactive logon
                "administrator", "admin", "service", "system"
            ]
            return any(indicator in event_xml.lower() for indicator in suspicious_indicators)
        except:
            return False
    
    def _is_suspicious_4672_event(self, event_xml: str) -> bool:
        """Check if Event 4672 indicates suspicious privilege assignment"""
        try:
            # Look for high privilege assignments
            high_privileges = [
                "sedebugprivilege", "setakeownershipprivilege", 
                "seimpersonateprivilege", "seloaddriverprivilege",
                "serestoreprivilege", "sebackupprivilege"
            ]
            return any(priv in event_xml.lower() for priv in high_privileges)
        except:
            return False
    
    def _is_suspicious_4688_event(self, event_xml: str) -> bool:
        """Check if Event 4688 indicates suspicious process creation"""
        try:
            suspicious_processes = [
                "powershell", "cmd.exe", "wmic", "psexec", "mimikatz",
                "procdump", "rundll32", "regsvr32", "mshta", "certutil"
            ]
            return any(proc in event_xml.lower() for proc in suspicious_processes)
        except:
            return False
    
    def _analyze_process_creation(self, event_xml: str) -> List[str]:
        """Analyze process creation for multiple threat categories"""
        threats = []
        xml_lower = event_xml.lower()
        
        # Check for different threat patterns
        if any(pattern in xml_lower for pattern in ["powershell", "cmd.exe", "wmic"]):
            if any(pattern in xml_lower for pattern in ["encoded", "bypass", "hidden"]):
                threats.append("powershell_obfuscation")
            elif any(pattern in xml_lower for pattern in ["net user", "net group", "whoami"]):
                threats.append("reconnaissance")
            elif any(pattern in xml_lower for pattern in ["psexec", "wmic", "schtasks"]):
                threats.append("lateral_movement")
        
        if any(pattern in xml_lower for pattern in ["mimikatz", "procdump", "lsass"]):
            threats.append("credential_dumping")
        
        if any(pattern in xml_lower for pattern in ["rundll32", "regsvr32", "mshta"]):
            threats.append("defense_evasion")
        
        return threats
    
    def _is_privileged_group_addition(self, event_xml: str) -> bool:
        """Check if user was added to privileged group"""
        try:
            privileged_groups = [
                "administrators", "domain admins", "enterprise admins",
                "schema admins", "backup operators", "server operators"
            ]
            return any(group in event_xml.lower() for group in privileged_groups)
        except:
            return False
    
    def _is_suspicious_kerberos_event(self, event_xml: str) -> bool:
        """Check if Kerberos event indicates suspicious activity"""
        try:
            # Look for service ticket requests that might indicate lateral movement
            suspicious_services = [
                "cifs/", "host/", "ldap/", "mssqlsvc/", "http/", "rpcss/"
            ]
            return any(service in event_xml.lower() for service in suspicious_services)
        except:
            return False
    
    def _is_suspicious_share_access(self, event_xml: str) -> bool:
        """Check if network share access is suspicious"""
        try:
            suspicious_shares = ["admin$", "c$", "ipc$", "sysvol", "netlogon"]
            return any(share in event_xml.lower() for share in suspicious_shares)
        except:
            return False
    
    def _is_suspicious_network_connection(self, event_xml: str) -> bool:
        """Check if network connection is suspicious"""
        try:
            # Look for connections to suspicious ports or protocols
            suspicious_patterns = [
                "port\">443<", "port\">80<", "port\">53<",  # Common exfil ports
                "port\">22<", "port\">21<", "port\">23<",  # Remote access
                "direction\">outbound"  # Outbound connections
            ]
            return any(pattern in event_xml.lower() for pattern in suspicious_patterns)
        except:
            return False
    
    def _extract_event_id(self, event_xml: str) -> str:
        """Extract Event ID from XML"""
        try:
            root = ET.fromstring(event_xml)
            event_id = root.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}EventID')
            return event_id.text if event_id is not None else "Unknown"
        except:
            return "Unknown"
    
    def _extract_timestamp(self, event_xml: str) -> str:
        """Extract timestamp from XML"""
        try:
            root = ET.fromstring(event_xml)
            timestamp = root.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}TimeCreated')
            return timestamp.get('SystemTime') if timestamp is not None else "Unknown"
        except:
            return "Unknown"
    
    def _perform_ai_analysis(self, suspicious_events: List[Dict]) -> str:
        """Perform AI analysis using Groq API
        
        Args:
            suspicious_events: List of suspicious events
            
        Returns:
            AI analysis summary
        """
        # Placeholder for Groq API integration
        # In a real implementation, this would send data to Groq API
        self.logger.info("Performing AI analysis...")
        
        threat_summary = {}
        for event in suspicious_events:
            for indicator in event['indicators']:
                threat_summary[indicator] = threat_summary.get(indicator, 0) + 1
        
        analysis = f"AI Analysis Summary:\n"
        analysis += f"- Total suspicious events: {len(suspicious_events)}\n"
        
        for threat, count in threat_summary.items():
            analysis += f"- {threat.replace('_', ' ').title()}: {count} occurrences\n"
        
        analysis += "\nRecommendations:\n"
        if 'process_injection' in threat_summary:
            analysis += "- Investigate process injection activities for potential malware\n"
        if 'powershell_obfuscation' in threat_summary:
            analysis += "- Review PowerShell command executions for malicious scripts\n"
        if 'privilege_escalation' in threat_summary:
            analysis += "- Check for unauthorized privilege escalation attempts\n"
        
        return analysis
    
    def _extract_detailed_info(self, event_xml: str, event_id: str, results: Dict):
        """Extract detailed information from events"""
        try:
            root = ET.fromstring(event_xml)
            
            # Process creation events (Event ID 1)
            if event_id == "1":
                process_info = {
                    'timestamp': self._extract_timestamp(event_xml),
                    'process_name': self._extract_data_value(root, 'Image'),
                    'command_line': self._extract_data_value(root, 'CommandLine'),
                    'parent_process': self._extract_data_value(root, 'ParentImage'),
                    'process_id': self._extract_data_value(root, 'ProcessId')
                }
                results['process_tree'].append(process_info)
            
            # Network connections (Event ID 3)
            elif event_id == "3":
                network_info = {
                    'timestamp': self._extract_timestamp(event_xml),
                    'process_name': self._extract_data_value(root, 'Image'),
                    'source_ip': self._extract_data_value(root, 'SourceIp'),
                    'dest_ip': self._extract_data_value(root, 'DestinationIp'),
                    'dest_port': self._extract_data_value(root, 'DestinationPort'),
                    'protocol': self._extract_data_value(root, 'Protocol')
                }
                results['network_connections'].append(network_info)
            
            # File creation events (Event ID 11)
            elif event_id == "11":
                file_info = {
                    'timestamp': self._extract_timestamp(event_xml),
                    'process_name': self._extract_data_value(root, 'Image'),
                    'target_filename': self._extract_data_value(root, 'TargetFilename'),
                    'creation_time': self._extract_data_value(root, 'CreationUtcTime')
                }
                results['file_operations'].append(file_info)
                
        except Exception as e:
            self.logger.debug(f"Error extracting detailed info: {e}")
    
    def _extract_data_value(self, root, name: str) -> str:
        """Extract data value from event XML by name"""
        try:
            data_elements = root.findall('.//{http://schemas.microsoft.com/win/2004/08/events/event}Data')
            for data in data_elements:
                if data.get('Name') == name:
                    return data.text or "Unknown"
            return "Unknown"
        except:
            return "Unknown"
    
    def _extract_process_info(self, event_xml: str) -> Dict[str, str]:
        """Extract process information from event XML"""
        try:
            root = ET.fromstring(event_xml)
            return {
                'image': self._extract_data_value(root, 'Image'),
                'command_line': self._extract_data_value(root, 'CommandLine'),
                'process_id': self._extract_data_value(root, 'ProcessId'),
                'parent_image': self._extract_data_value(root, 'ParentImage')
            }
        except:
            return {}
    
    def _extract_network_info(self, event_xml: str) -> Dict[str, str]:
        """Extract network information from event XML"""
        try:
            root = ET.fromstring(event_xml)
            return {
                'source_ip': self._extract_data_value(root, 'SourceIp'),
                'dest_ip': self._extract_data_value(root, 'DestinationIp'),
                'dest_port': self._extract_data_value(root, 'DestinationPort'),
                'protocol': self._extract_data_value(root, 'Protocol')
            }
        except:
            return {}
    
    def _extract_file_info(self, event_xml: str) -> Dict[str, str]:
        """Extract file information from event XML"""
        try:
            root = ET.fromstring(event_xml)
            return {
                'target_filename': self._extract_data_value(root, 'TargetFilename'),
                'creation_time': self._extract_data_value(root, 'CreationUtcTime')
            }
        except:
            return {}
    
    def save_results(self, results: Dict[str, Any], output_path: str, detailed: bool = False):
        """Save analysis results to file
        
        Args:
            results: Analysis results
            output_path: Output file path
            detailed: Whether to include detailed information
        """
        output_file = Path(output_path)
        
        if output_file.suffix.lower() == '.json':
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
        else:
            # Save as detailed text report
            with open(output_file, 'w') as f:
                f.write(f"Sysmon AI Analysis Report\n")
                f.write(f"========================\n\n")
                f.write(f"File: {results['file_path']}\n")
                f.write(f"Analysis Time: {results['analysis_timestamp']}\n")
                f.write(f"Analysis Type: {'Detailed' if detailed else 'Standard'}\n")
                f.write(f"Total Events: {results['total_events']}\n")
                f.write(f"Suspicious Events: {len(results['suspicious_events'])}\n\n")
                
                # Event Summary
                if results.get('event_summary'):
                    f.write("Event Summary by ID:\n")
                    for event_id, count in sorted(results['event_summary'].items()):
                        f.write(f"- Event {event_id}: {count} occurrences\n")
                    f.write("\n")
                
                # Threat Categories
                if results['threat_categories']:
                    f.write("Threat Categories:\n")
                    for category, count in results['threat_categories'].items():
                        f.write(f"- {category.replace('_', ' ').title()}: {count}\n")
                    f.write("\n")
                
                # Detailed Analysis Sections
                if detailed and results.get('detailed_analysis'):
                    if results.get('process_tree'):
                        f.write(f"Process Creation Events ({len(results['process_tree'])}):\n")
                        for i, proc in enumerate(results['process_tree'][:10], 1):
                            f.write(f"  {i}. {proc.get('process_name', 'Unknown')} "
                                   f"(PID: {proc.get('process_id', 'Unknown')})\n")
                            if proc.get('command_line') != 'Unknown':
                                f.write(f"     Command: {proc['command_line'][:100]}...\n")
                        f.write("\n")
                    
                    if results.get('network_connections'):
                        f.write(f"Network Connections ({len(results['network_connections'])}):\n")
                        for i, conn in enumerate(results['network_connections'][:10], 1):
                            f.write(f"  {i}. {conn.get('process_name', 'Unknown')} -> "
                                   f"{conn.get('dest_ip', 'Unknown')}:{conn.get('dest_port', 'Unknown')}\n")
                        f.write("\n")
                    
                    if results.get('file_operations'):
                        f.write(f"File Operations ({len(results['file_operations'])}):\n")
                        for i, file_op in enumerate(results['file_operations'][:10], 1):
                            f.write(f"  {i}. {file_op.get('process_name', 'Unknown')} -> "
                                   f"{file_op.get('target_filename', 'Unknown')}\n")
                        f.write("\n")
                
                # AI Analysis
                if results.get('ai_analysis'):
                    f.write("AI Analysis:\n")
                    f.write(results['ai_analysis'])
                    f.write("\n")
                
                # Top Suspicious Events
                if results['suspicious_events']:
                    f.write("Detailed Suspicious Events:\n")
                    for i, event in enumerate(results['suspicious_events'][:10], 1):
                        f.write(f"\n{i}. Event ID: {event['event_id']}\n")
                        f.write(f"   Time: {event['timestamp']}\n")
                        f.write(f"   Threats: {', '.join(event['indicators'])}\n")
                        
                        if detailed:
                            if event.get('process_info'):
                                proc = event['process_info']
                                if proc.get('image') != 'Unknown':
                                    f.write(f"   Process: {proc['image']}\n")
                                if proc.get('command_line') != 'Unknown':
                                    f.write(f"   Command: {proc['command_line'][:150]}...\n")
                            
                            if event.get('network_info'):
                                net = event['network_info']
                                if net.get('dest_ip') != 'Unknown':
                                    f.write(f"   Network: {net['dest_ip']}:{net.get('dest_port', 'Unknown')}\n")
                            
                            if event.get('file_info'):
                                file_info = event['file_info']
                                if file_info.get('target_filename') != 'Unknown':
                                    f.write(f"   File: {file_info['target_filename']}\n")
        
        self.logger.info(f"Results saved to {output_file}")
    
    def print_results(self, results: Dict[str, Any], detailed: bool = False):
        """Print analysis results to console
        
        Args:
            results: Analysis results
            detailed: Whether to show detailed information
        """
        print(f"\n=== Sysmon AI Analysis Results ===")
        print(f"File: {results['file_path']}")
        print(f"Analysis Type: {'Detailed' if detailed else 'Standard'}")
        print(f"Total Events: {results['total_events']}")
        print(f"Suspicious Events: {len(results['suspicious_events'])}")
        
        # Event Summary
        if results.get('event_summary'):
            print(f"\nEvent Summary:")
            for event_id, count in sorted(results['event_summary'].items()):
                print(f"  Event {event_id}: {count}")
        
        if results['threat_categories']:
            print(f"\nThreat Categories:")
            for category, count in results['threat_categories'].items():
                print(f"  - {category.replace('_', ' ').title()}: {count}")
        
        # Detailed information
        if detailed and results.get('detailed_analysis'):
            if results.get('process_tree'):
                print(f"\nProcess Activity: {len(results['process_tree'])} processes")
            if results.get('network_connections'):
                print(f"Network Activity: {len(results['network_connections'])} connections")
            if results.get('file_operations'):
                print(f"File Activity: {len(results['file_operations'])} operations")
        
        if results.get('ai_analysis'):
            print(f"\n{results['ai_analysis']}")
        
        if results['suspicious_events']:
            print(f"\nTop Suspicious Events:")
            for i, event in enumerate(results['suspicious_events'][:5], 1):
                print(f"  {i}. Event ID: {event['event_id']}, "
                      f"Time: {event['timestamp']}, "
                      f"Indicators: {', '.join(event['indicators'])}")
                
                if detailed:
                    if event.get('process_info', {}).get('image') != 'Unknown':
                        print(f"     Process: {event['process_info']['image']}")
                    if event.get('network_info', {}).get('dest_ip') != 'Unknown':
                        print(f"     Network: {event['network_info']['dest_ip']}:{event['network_info'].get('dest_port', '?')}")
