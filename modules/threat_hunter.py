#!/usr/bin/env python3
"""
Advanced Threat Hunting Analyzer
Comprehensive threat detection and analysis for cybersecurity professionals
"""

import json
import logging
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import xml.etree.ElementTree as ET
from collections import defaultdict, Counter
import hashlib
import base64

try:
    from groq import Groq
except ImportError:
    Groq = None

class ThreatHuntingAnalyzer:
    """Advanced threat hunting and analysis capabilities"""
    
    def __init__(self, groq_api_key: str = None):
        """Initialize the threat hunting analyzer
        
        Args:
            groq_api_key: API key for AI analysis
        """
        self.logger = logging.getLogger(__name__)
        self.groq_client = None
        
        if groq_api_key and Groq:
            try:
                self.groq_client = Groq(api_key=groq_api_key)
                self.logger.info("AI analysis enabled")
            except Exception as e:
                self.logger.warning(f"Failed to initialize AI client: {e}")
        
        # Advanced threat indicators and patterns
        self.threat_patterns = {
            'lateral_movement': {
                'patterns': [
                    r'net\s+use\s+\\\\[\w\.-]+\\[\w$]+',
                    r'psexec.*\\\\[\w\.-]+',
                    r'wmic.*process.*call.*create',
                    r'powershell.*invoke-command.*computername',
                    r'schtasks.*\\s.*\\\\[\w\.-]+',
                    r'at\s+\\\\[\w\.-]+',
                    r'reg\s+add\s+\\\\[\w\.-]+'
                ],
                'severity': 'high',
                'mitre_tactics': ['TA0008']
            },
            'privilege_escalation': {
                'patterns': [
                    r'SeDebugPrivilege',
                    r'SeTakeOwnershipPrivilege',
                    r'SeImpersonatePrivilege',
                    r'SeAssignPrimaryTokenPrivilege',
                    r'whoami\s+/priv',
                    r'runas\s+/user:',
                    r'sudo\s+su\s*-',
                    r'chmod\s+[47]777',
                    r'setuid|setgid'
                ],
                'severity': 'high',
                'mitre_tactics': ['TA0004']
            },
            'persistence_mechanisms': {
                'patterns': [
                    r'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                    r'HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                    r'schtasks.*create',
                    r'at\s+\d{2}:\d{2}',
                    r'crontab\s+-e',
                    r'systemctl\s+enable',
                    r'wevtutil.*set-log.*enabled:false',
                    r'sc\s+create',
                    r'New-Service'
                ],
                'severity': 'medium',
                'mitre_tactics': ['TA0003']
            },
            'defense_evasion': {
                'patterns': [
                    r'wevtutil.*clear-log',
                    r'del\s+.*\.log',
                    r'rm\s+-rf\s+/var/log',
                    r'powershell.*-encodedcommand',
                    r'powershell.*-noprofile.*-windowstyle\s+hidden',
                    r'rundll32.*javascript',
                    r'mshta.*javascript',
                    r'regsvr32.*scrobj\.dll',
                    r'certutil.*-decode',
                    r'bitsadmin.*transfer'
                ],
                'severity': 'high',
                'mitre_tactics': ['TA0005']
            },
            'credential_access': {
                'patterns': [
                    r'mimikatz',
                    r'lsass\.exe',
                    r'sekurlsa::logonpasswords',
                    r'procdump.*lsass',
                    r'reg\s+save.*sam',
                    r'reg\s+save.*security',
                    r'reg\s+save.*system',
                    r'ntdsutil.*ifm.*create',
                    r'vssadmin.*create.*shadow',
                    r'/etc/shadow',
                    r'/etc/passwd'
                ],
                'severity': 'critical',
                'mitre_tactics': ['TA0006']
            },
            'data_exfiltration': {
                'patterns': [
                    r'powershell.*invoke-webrequest.*outfile',
                    r'wget\s+.*-O',
                    r'curl\s+.*-o',
                    r'scp\s+.*@',
                    r'rsync\s+.*@',
                    r'ftp\s+.*put',
                    r'dropbox|onedrive|googledrive',
                    r'pastebin\.com',
                    r'github\.com.*raw',
                    r'dns.*txt.*query'
                ],
                'severity': 'high',
                'mitre_tactics': ['TA0010']
            },
            'command_control': {
                'patterns': [
                    r'powershell.*downloadstring',
                    r'powershell.*invoke-expression',
                    r'certutil.*urlcache',
                    r'regsvr32.*http',
                    r'mshta.*http',
                    r'rundll32.*url\.dll',
                    r'bitsadmin.*download',
                    r'dns.*query.*txt',
                    r'nc\s+-l\s+-p\s+\d+',
                    r'python.*-c.*socket'
                ],
                'severity': 'high',
                'mitre_tactics': ['TA0011']
            },
            'process_injection': {
                'patterns': [
                    r'CreateRemoteThread',
                    r'VirtualAllocEx',
                    r'WriteProcessMemory',
                    r'SetWindowsHookEx',
                    r'QueueUserAPC',
                    r'NtMapViewOfSection',
                    r'RtlCreateUserThread',
                    r'NtQueueApcThread',
                    r'ptrace\s+PTRACE_POKETEXT'
                ],
                'severity': 'high',
                'mitre_tactics': ['TA0005']
            },
            'suspicious_network': {
                'patterns': [
                    r'(?:\d{1,3}\.){3}\d{1,3}:\d+',  # IP:Port
                    r'[a-f0-9]{32,}\.onion',  # Tor addresses
                    r'dga_domain_\w{8,16}\.com',  # DGA patterns
                    r'\.tk|\.ml|\.ga|\.cf',  # Suspicious TLDs
                    r'bit\.ly|tinyurl\.com|goo\.gl',  # URL shorteners
                    r'pastebin\.com|hastebin\.com',  # Paste sites
                    r'ngrok\.io|localtunnel\.me'  # Tunneling services
                ],
                'severity': 'medium',
                'mitre_tactics': ['TA0011']
            }
        }
        
        # File hash databases for known threats
        self.known_malware_hashes = set()
        self.whitelisted_hashes = set()
        
        # Suspicious file patterns
        self.suspicious_files = {
            'executables': [r'\.exe$', r'\.scr$', r'\.com$', r'\.bat$', r'\.cmd$', r'\.ps1$'],
            'documents': [r'\.docm$', r'\.xlsm$', r'\.pptm$', r'\.rtf$'],
            'archives': [r'\.zip$', r'\.rar$', r'\.7z$', r'\.tar\.gz$'],
            'scripts': [r'\.js$', r'\.vbs$', r'\.hta$', r'\.wsf$']
        }
        
        # IOC patterns
        self.ioc_patterns = {
            'ip_addresses': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'domains': r'\b[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\b',
            'urls': r'https?://[^\s<>"{}|\\^`\[\]]+',
            'file_hashes': r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b',
            'registry_keys': r'HKEY_[A-Z_]+\\[\\A-Za-z0-9_\-\s]+',
            'file_paths': r'[C-Z]:\\[\\A-Za-z0-9\s_\-\.]+|/[/a-zA-Z0-9\s_\-\.]+',
            'email_addresses': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        }

    def analyze_collected_logs(self, log_collection_results: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive threat hunting analysis on collected logs
        
        Args:
            log_collection_results: Results from log collection
            
        Returns:
            Comprehensive threat analysis results
        """
        self.logger.info("Starting comprehensive threat hunting analysis")
        
        analysis_results = {
            'analysis_metadata': {
                'timestamp': datetime.now().isoformat(),
                'analyst_version': '0.1',
                'log_sources_analyzed': len(log_collection_results.get('collected_logs', {})),
                'analysis_duration': 0
            },
            'executive_summary': {},
            'threat_detections': [],
            'ioc_extraction': {
                'ip_addresses': set(),
                'domains': set(),
                'urls': set(),
                'file_hashes': set(),
                'registry_keys': set(),
                'file_paths': set(),
                'email_addresses': set()
            },
            'attack_timeline': [],
            'lateral_movement_analysis': {},
            'persistence_analysis': {},
            'data_flow_analysis': {},
            'recommendations': [],
            'hunting_queries': [],
            'mitre_attack_mapping': defaultdict(list),
            'risk_assessment': {}
        }
        
        start_time = datetime.now()
        
        # Analyze each log source
        for log_name, log_info in log_collection_results.get('collected_logs', {}).items():
            if log_info.get('collection_status') == 'success':
                self.logger.info(f"Analyzing log source: {log_name}")
                
                log_analysis = self._analyze_log_source(log_name, log_info)
                
                # Merge results
                analysis_results['threat_detections'].extend(log_analysis.get('detections', []))
                
                # Extract IOCs
                for ioc_type, iocs in log_analysis.get('iocs', {}).items():
                    if isinstance(iocs, (list, set)):
                        analysis_results['ioc_extraction'][ioc_type].update(iocs)
                
                # Build attack timeline
                analysis_results['attack_timeline'].extend(log_analysis.get('timeline_events', []))
        
        # Convert sets to lists for JSON serialization
        for ioc_type in analysis_results['ioc_extraction']:
            analysis_results['ioc_extraction'][ioc_type] = list(analysis_results['ioc_extraction'][ioc_type])
        
        # Perform advanced analysis
        analysis_results['lateral_movement_analysis'] = self._analyze_lateral_movement(analysis_results)
        analysis_results['persistence_analysis'] = self._analyze_persistence(analysis_results)
        analysis_results['data_flow_analysis'] = self._analyze_data_flow(analysis_results)
        
        # Generate executive summary
        analysis_results['executive_summary'] = self._generate_executive_summary(analysis_results)
        
        # Risk assessment
        analysis_results['risk_assessment'] = self._calculate_risk_score(analysis_results)
        
        # Generate hunting queries
        analysis_results['hunting_queries'] = self._generate_hunting_queries(analysis_results)
        
        # AI-powered analysis if available
        if self.groq_client:
            analysis_results['ai_insights'] = self._generate_ai_insights(analysis_results)
        
        # Calculate analysis duration
        analysis_results['analysis_metadata']['analysis_duration'] = (datetime.now() - start_time).total_seconds()
        
        self.logger.info("Threat hunting analysis completed")
        return analysis_results

    def _analyze_log_source(self, log_name: str, log_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a specific log source for threats"""
        log_analysis = {
            'detections': [],
            'iocs': defaultdict(set),
            'timeline_events': []
        }
        
        # Determine log file to analyze
        log_file = None
        if 'csv_file' in log_info and Path(log_info['csv_file']).exists():
            log_file = Path(log_info['csv_file'])
        elif 'output_file' in log_info and Path(log_info['output_file']).exists():
            log_file = Path(log_info['output_file'])
        
        if not log_file:
            return log_analysis
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Extract IOCs
            for ioc_type, pattern in self.ioc_patterns.items():
                matches = re.finditer(pattern, content, re.IGNORECASE)
                # Extract the full matched string (group 0) to avoid tuple issues from capturing groups
                ioc_matches = [match.group(0) for match in matches]
                log_analysis['iocs'][ioc_type].update(ioc_matches)
            
            # Check for threat patterns
            for threat_category, threat_info in self.threat_patterns.items():
                for pattern in threat_info['patterns']:
                    matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                    
                    for match in matches:
                        detection = {
                            'threat_category': threat_category,
                            'severity': threat_info['severity'],
                            'mitre_tactics': threat_info['mitre_tactics'],
                            'pattern_matched': pattern,
                            'matched_content': match.group(),
                            'log_source': log_name,
                            'timestamp': datetime.now().isoformat(),
                            'context': self._extract_context(content, match.start(), match.end())
                        }
                        
                        log_analysis['detections'].append(detection)
                        
                        # Add to MITRE ATT&CK mapping
                        for tactic in threat_info['mitre_tactics']:
                            log_analysis.setdefault('mitre_mapping', defaultdict(list))[tactic].append(detection)
            
            # Extract timeline events
            log_analysis['timeline_events'] = self._extract_timeline_events(content, log_name)
            
        except Exception as e:
            self.logger.error(f"Error analyzing log source {log_name}: {str(e)}")
        
        return log_analysis

    def _extract_context(self, content: str, start: int, end: int, context_size: int = 200) -> str:
        """Extract context around a matched pattern"""
        context_start = max(0, start - context_size)
        context_end = min(len(content), end + context_size)
        return content[context_start:context_end]

    def _extract_timeline_events(self, content: str, log_source: str) -> List[Dict[str, Any]]:
        """Extract timeline events from log content"""
        timeline_events = []
        
        # Common timestamp patterns
        timestamp_patterns = [
            (r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', '%Y-%m-%d %H:%M:%S'),
            (r'(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})', '%m/%d/%Y %H:%M:%S'),
            (r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', '%b %d %H:%M:%S')
        ]
        
        lines = content.split('\n')
        for line_num, line in enumerate(lines[:1000]):  # Limit for performance
            for pattern, date_format in timestamp_patterns:
                match = re.search(pattern, line)
                if match:
                    try:
                        if date_format == '%b %d %H:%M:%S':
                            # Add current year for syslog format
                            timestamp_str = f"{datetime.now().year} {match.group(1)}"
                            timestamp = datetime.strptime(timestamp_str, f'%Y {date_format}')
                        else:
                            timestamp = datetime.strptime(match.group(1), date_format)
                        
                        timeline_events.append({
                            'timestamp': timestamp.isoformat(),
                            'log_source': log_source,
                            'line_number': line_num + 1,
                            'event_data': line.strip()[:500]  # Limit event data size
                        })
                        break
                    except ValueError:
                        continue
        
        return timeline_events

    def _analyze_lateral_movement(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze lateral movement patterns"""
        lateral_movement = {
            'detected_movement': [],
            'compromised_hosts': set(),
            'movement_techniques': Counter(),
            'timeline': []
        }
        
        # Look for lateral movement indicators
        for detection in analysis_results['threat_detections']:
            if detection['threat_category'] == 'lateral_movement':
                lateral_movement['detected_movement'].append(detection)
                lateral_movement['movement_techniques'][detection['pattern_matched']] += 1
                
                # Extract host information from content
                host_matches = re.findall(r'\\\\([\w\.-]+)', detection['matched_content'])
                lateral_movement['compromised_hosts'].update(host_matches)
        
        # Convert set to list for JSON serialization
        lateral_movement['compromised_hosts'] = list(lateral_movement['compromised_hosts'])
        lateral_movement['movement_techniques'] = dict(lateral_movement['movement_techniques'])
        
        return lateral_movement

    def _analyze_persistence(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze persistence mechanisms"""
        persistence = {
            'persistence_methods': Counter(),
            'registry_modifications': [],
            'scheduled_tasks': [],
            'service_creations': [],
            'startup_modifications': []
        }
        
        for detection in analysis_results['threat_detections']:
            if detection['threat_category'] == 'persistence_mechanisms':
                persistence['persistence_methods'][detection['pattern_matched']] += 1
                
                # Categorize persistence type
                matched_content = str(detection.get('matched_content', '')).lower()
                if 'registry' in matched_content:
                    persistence['registry_modifications'].append(detection)
                elif 'schtasks' in matched_content:
                    persistence['scheduled_tasks'].append(detection)
                elif 'service' in matched_content:
                    persistence['service_creations'].append(detection)
        
        persistence['persistence_methods'] = dict(persistence['persistence_methods'])
        return persistence

    def _analyze_data_flow(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze data flow and potential exfiltration"""
        data_flow = {
            'network_connections': Counter(),
            'file_transfers': [],
            'dns_queries': [],
            'suspicious_domains': set(),
            'data_staging': []
        }
        
        # Analyze network IOCs
        for ip in analysis_results['ioc_extraction']['ip_addresses']:
            if self._is_suspicious_ip(ip):
                data_flow['network_connections'][ip] += 1
        
        for domain in analysis_results['ioc_extraction']['domains']:
            if self._is_suspicious_domain(domain):
                data_flow['suspicious_domains'].add(domain)
        
        # Look for data exfiltration patterns
        for detection in analysis_results['threat_detections']:
            if detection['threat_category'] == 'data_exfiltration':
                data_flow['file_transfers'].append(detection)
        
        data_flow['network_connections'] = dict(data_flow['network_connections'])
        data_flow['suspicious_domains'] = list(data_flow['suspicious_domains'])
        
        return data_flow

    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if an IP address is suspicious"""
        # Private IP ranges are less suspicious
        private_ranges = [
            r'^10\.',
            r'^192\.168\.',
            r'^172\.(1[6-9]|2[0-9]|3[01])\.'
        ]
        
        for pattern in private_ranges:
            if re.match(pattern, ip):
                return False
        
        return True

    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check if a domain is suspicious"""
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.onion']
        suspicious_keywords = ['dga', 'malware', 'c2', 'command', 'control']
        
        domain_lower = domain.lower()
        
        # Check TLDs
        for tld in suspicious_tlds:
            if domain_lower.endswith(tld):
                return True
        
        # Check keywords
        for keyword in suspicious_keywords:
            if keyword in domain_lower:
                return True
        
        # Check for DGA-like patterns (random strings)
        parts = domain_lower.split('.')
        if len(parts) > 0:
            subdomain = parts[0]
            if len(subdomain) > 10 and self._looks_like_random_string(subdomain):
                return True
        
        return False

    def _looks_like_random_string(self, s: str) -> bool:
        """Check if a string looks randomly generated"""
        vowels = 'aeiou'
        consonants = 'bcdfghjklmnpqrstvwxyz'
        
        vowel_count = sum(1 for c in s.lower() if c in vowels)
        consonant_count = sum(1 for c in s.lower() if c in consonants)
        
        # Random strings often have unusual vowel/consonant ratios
        if len(s) > 6:
            vowel_ratio = vowel_count / len(s)
            if vowel_ratio < 0.1 or vowel_ratio > 0.6:
                return True
        
        return False

    def _generate_executive_summary(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary for leadership"""
        total_detections = len(analysis_results['threat_detections'])
        
        # Count by severity
        severity_counts = Counter()
        for detection in analysis_results['threat_detections']:
            severity_counts[detection['severity']] += 1
        
        # Count by threat category
        category_counts = Counter()
        for detection in analysis_results['threat_detections']:
            category_counts[detection['threat_category']] += 1
        
        summary = {
            'overall_risk_level': 'LOW',
            'total_threats_detected': total_detections,
            'critical_findings': severity_counts.get('critical', 0),
            'high_severity_findings': severity_counts.get('high', 0),
            'medium_severity_findings': severity_counts.get('medium', 0),
            'low_severity_findings': severity_counts.get('low', 0),
            'top_threat_categories': dict(category_counts.most_common(5)),
            'ioc_summary': {
                'unique_ips': len(analysis_results['ioc_extraction']['ip_addresses']),
                'unique_domains': len(analysis_results['ioc_extraction']['domains']),
                'unique_file_hashes': len(analysis_results['ioc_extraction']['file_hashes'])
            },
            'key_findings': [],
            'immediate_actions_required': []
        }
        
        # Determine overall risk level
        if severity_counts.get('critical', 0) > 0:
            summary['overall_risk_level'] = 'CRITICAL'
        elif severity_counts.get('high', 0) > 5:
            summary['overall_risk_level'] = 'HIGH'
        elif severity_counts.get('high', 0) > 0 or severity_counts.get('medium', 0) > 10:
            summary['overall_risk_level'] = 'MEDIUM'
        
        # Generate key findings
        if analysis_results['lateral_movement_analysis']['detected_movement']:
            summary['key_findings'].append("Lateral movement detected across network")
            summary['immediate_actions_required'].append("Isolate affected systems and reset credentials")
        
        if analysis_results['persistence_analysis']['persistence_methods']:
            summary['key_findings'].append("Persistence mechanisms identified")
            summary['immediate_actions_required'].append("Remove persistence mechanisms and harden systems")
        
        return summary

    def _calculate_risk_score(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate comprehensive risk score"""
        risk_factors = {
            'critical_threats': len([d for d in analysis_results['threat_detections'] if d['severity'] == 'critical']) * 25,
            'high_threats': len([d for d in analysis_results['threat_detections'] if d['severity'] == 'high']) * 10,
            'medium_threats': len([d for d in analysis_results['threat_detections'] if d['severity'] == 'medium']) * 5,
            'lateral_movement': len(analysis_results['lateral_movement_analysis']['detected_movement']) * 15,
            'persistence_mechanisms': len(analysis_results['persistence_analysis']['persistence_methods']) * 10,
            'suspicious_network_activity': len(analysis_results['data_flow_analysis']['suspicious_domains']) * 5
        }
        
        total_score = sum(risk_factors.values())
        max_score = 100
        
        risk_assessment = {
            'total_risk_score': min(total_score, max_score),
            'risk_factors': risk_factors,
            'risk_level': 'LOW',
            'confidence': 'HIGH'
        }
        
        # Determine risk level
        if total_score >= 75:
            risk_assessment['risk_level'] = 'CRITICAL'
        elif total_score >= 50:
            risk_assessment['risk_level'] = 'HIGH'
        elif total_score >= 25:
            risk_assessment['risk_level'] = 'MEDIUM'
        
        return risk_assessment

    def _generate_hunting_queries(self, analysis_results: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate threat hunting queries for various platforms"""
        queries = []
        
        # Splunk queries
        if analysis_results['ioc_extraction']['ip_addresses']:
            ips = '|'.join(analysis_results['ioc_extraction']['ip_addresses'][:10])
            queries.append({
                'platform': 'Splunk',
                'query': f'index=* src_ip="{ips}" OR dest_ip="{ips}" | stats count by src_ip, dest_ip',
                'description': 'Search for network connections to suspicious IPs'
            })
        
        # Elasticsearch/ELK queries
        if analysis_results['ioc_extraction']['domains']:
            domains = '|'.join(analysis_results['ioc_extraction']['domains'][:10])
            queries.append({
                'platform': 'Elasticsearch',
                'query': f'GET logs/_search {{"query": {{"regexp": {{"domain": "({domains})"}}}}}}',
                'description': 'Search for DNS queries to suspicious domains'
            })
        
        # Windows Event Log queries
        queries.append({
            'platform': 'Windows Event Log',
            'query': 'Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4624,4625} | Where-Object {$_.Message -like "*suspicious*"}',
            'description': 'Search for suspicious login attempts'
        })
        
        # Sysmon queries
        queries.append({
            'platform': 'Sysmon',
            'query': 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=1} | Where-Object {$_.Message -like "*powershell*" -and $_.Message -like "*-encodedcommand*"}',
            'description': 'Search for encoded PowerShell commands'
        })
        
        return queries

    def _generate_ai_insights(self, analysis_results: Dict[str, Any]) -> str:
        """Generate AI-powered insights and recommendations"""
        if not self.groq_client:
            return "AI analysis not available"
        
        # Prepare summary for AI analysis
        summary_data = {
            'total_detections': len(analysis_results['threat_detections']),
            'severity_breakdown': {},
            'top_threats': [],
            'ioc_counts': {k: len(v) for k, v in analysis_results['ioc_extraction'].items()},
            'risk_score': analysis_results['risk_assessment']['total_risk_score']
        }
        
        # Get top threats
        threat_categories = Counter()
        for detection in analysis_results['threat_detections']:
            threat_categories[detection['threat_category']] += 1
            summary_data['severity_breakdown'][detection['severity']] = summary_data['severity_breakdown'].get(detection['severity'], 0) + 1
        
        summary_data['top_threats'] = list(threat_categories.most_common(5))
        
        prompt = f"""
        As a cybersecurity expert, analyze these threat hunting results and provide insights:
        
        Summary:
        - Total detections: {summary_data['total_detections']}
        - Risk score: {summary_data['risk_score']}/100
        - Severity breakdown: {summary_data['severity_breakdown']}
        - Top threat categories: {summary_data['top_threats']}
        - IOC counts: {summary_data['ioc_counts']}
        
        Provide:
        1. Assessment of the threat landscape
        2. Priority recommendations for incident response
        3. Long-term security improvements
        4. Specific hunting recommendations
        
        Keep response concise and actionable for cybersecurity professionals.
        """
        
        try:
            response = self.groq_client.chat.completions.create(
                messages=[{"role": "user", "content": prompt}],
                model="mixtral-8x7b-32768",
                temperature=0.1,
                max_tokens=1500
            )
            return response.choices[0].message.content
        except Exception as e:
            self.logger.error(f"AI analysis failed: {str(e)}")
            return f"AI analysis failed: {str(e)}"

    def generate_threat_report(self, analysis_results: Dict[str, Any], output_format: str = 'json') -> str:
        """Generate comprehensive threat hunting report
        
        Args:
            analysis_results: Results from threat analysis
            output_format: Output format ('json', 'html', 'markdown')
            
        Returns:
            Formatted report string
        """
        if output_format.lower() == 'json':
            return json.dumps(analysis_results, indent=2, default=str)
        
        elif output_format.lower() == 'markdown':
            return self._generate_markdown_report(analysis_results)
        
        elif output_format.lower() == 'html':
            return self._generate_html_report(analysis_results)
        
        else:
            raise ValueError(f"Unsupported output format: {output_format}")

    def _generate_markdown_report(self, analysis_results: Dict[str, Any]) -> str:
        """Generate Markdown threat hunting report"""
        report = f"""# Threat Hunting Analysis Report

## Executive Summary

**Overall Risk Level:** {analysis_results['executive_summary']['overall_risk_level']}
**Total Threats Detected:** {analysis_results['executive_summary']['total_threats_detected']}
**Analysis Date:** {analysis_results['analysis_metadata']['timestamp']}

### Severity Breakdown
- **Critical:** {analysis_results['executive_summary']['critical_findings']}
- **High:** {analysis_results['executive_summary']['high_severity_findings']}
- **Medium:** {analysis_results['executive_summary']['medium_severity_findings']}
- **Low:** {analysis_results['executive_summary']['low_severity_findings']}

### Key Findings
"""
        
        for finding in analysis_results['executive_summary']['key_findings']:
            report += f"- {finding}\n"
        
        report += f"""
### Immediate Actions Required
"""
        
        for action in analysis_results['executive_summary']['immediate_actions_required']:
            report += f"- {action}\n"
        
        report += f"""
## Risk Assessment

**Risk Score:** {analysis_results['risk_assessment']['total_risk_score']}/100
**Risk Level:** {analysis_results['risk_assessment']['risk_level']}

## IOC Summary

- **IP Addresses:** {len(analysis_results['ioc_extraction']['ip_addresses'])}
- **Domains:** {len(analysis_results['ioc_extraction']['domains'])}
- **URLs:** {len(analysis_results['ioc_extraction']['urls'])}
- **File Hashes:** {len(analysis_results['ioc_extraction']['file_hashes'])}

## Threat Detections

"""
        
        for i, detection in enumerate(analysis_results['threat_detections'][:10], 1):
            report += f"""### Detection {i}
- **Category:** {detection['threat_category']}
- **Severity:** {detection['severity']}
- **Pattern:** {detection['pattern_matched']}
- **Source:** {detection['log_source']}

"""
        
        if 'ai_insights' in analysis_results:
            report += f"""
## AI Analysis

{analysis_results['ai_insights']}

"""
        
        report += f"""
## Hunting Queries

"""
        
        for query in analysis_results['hunting_queries']:
            report += f"""### {query['platform']}
```
{query['query']}
```
*{query['description']}*

"""
        
        return report

    def _generate_html_report(self, analysis_results: Dict[str, Any]) -> str:
        """Generate HTML threat hunting report"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Threat Hunting Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f44336; color: white; padding: 20px; }}
        .summary {{ background-color: #f9f9f9; padding: 15px; margin: 10px 0; }}
        .detection {{ border-left: 4px solid #ff9800; padding: 10px; margin: 10px 0; }}
        .critical {{ border-left-color: #f44336; }}
        .high {{ border-left-color: #ff9800; }}
        .medium {{ border-left-color: #ffeb3b; }}
        .low {{ border-left-color: #4caf50; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Threat Hunting Analysis Report</h1>
        <p>Analysis Date: {analysis_results['analysis_metadata']['timestamp']}</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Overall Risk Level:</strong> {analysis_results['executive_summary']['overall_risk_level']}</p>
        <p><strong>Total Threats Detected:</strong> {analysis_results['executive_summary']['total_threats_detected']}</p>
        
        <h3>Severity Breakdown</h3>
        <table>
            <tr><th>Severity</th><th>Count</th></tr>
            <tr><td>Critical</td><td>{analysis_results['executive_summary']['critical_findings']}</td></tr>
            <tr><td>High</td><td>{analysis_results['executive_summary']['high_severity_findings']}</td></tr>
            <tr><td>Medium</td><td>{analysis_results['executive_summary']['medium_severity_findings']}</td></tr>
            <tr><td>Low</td><td>{analysis_results['executive_summary']['low_severity_findings']}</td></tr>
        </table>
    </div>
    
    <h2>Risk Assessment</h2>
    <p><strong>Risk Score:</strong> {analysis_results['risk_assessment']['total_risk_score']}/100</p>
    <p><strong>Risk Level:</strong> {analysis_results['risk_assessment']['risk_level']}</p>
    
    <h2>Threat Detections</h2>
"""
        
        for i, detection in enumerate(analysis_results['threat_detections'][:20], 1):
            severity_class = detection['severity'].lower()
            html += f"""
    <div class="detection {severity_class}">
        <h3>Detection {i}</h3>
        <p><strong>Category:</strong> {detection['threat_category']}</p>
        <p><strong>Severity:</strong> {detection['severity']}</p>
        <p><strong>Pattern:</strong> {detection['pattern_matched']}</p>
        <p><strong>Source:</strong> {detection['log_source']}</p>
    </div>
"""
        
        html += """
</body>
</html>
"""
        return html
