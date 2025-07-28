#!/usr/bin/env python3
"""
Multi-Platform Log Collector
Comprehensive log collection for Windows and Linux systems
"""

import json
import logging
import os
import platform
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
import re
import gzip
import zipfile

try:
    import winreg
    import win32evtlog
    import win32con
    import win32evtlogutil
except ImportError:
    winreg = win32evtlog = win32con = win32evtlogutil = None

class LogCollector:
    """Multi-platform log collector for comprehensive security analysis"""
    
    def __init__(self, output_dir: str = "collected_logs"):
        """Initialize the log collector
        
        Args:
            output_dir: Directory to store collected logs
        """
        self.logger = logging.getLogger(__name__)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.system_info = self._get_system_info()
        
        # Define log sources for different platforms
        self.windows_logs = {
            'Security': 'Security',
            'System': 'System', 
            'Application': 'Application',
            'Microsoft-Windows-Sysmon/Operational': 'Sysmon',
            'Microsoft-Windows-PowerShell/Operational': 'PowerShell',
            'Microsoft-Windows-Windows Defender/Operational': 'Defender',
            'Microsoft-Windows-TaskScheduler/Operational': 'TaskScheduler',
            'Microsoft-Windows-WinRM/Operational': 'WinRM',
            'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational': 'RDP',
            'Microsoft-Windows-DNS-Client/Operational': 'DNS',
            'Microsoft-Windows-Kernel-Process/Analytic': 'KernelProcess',
            'Microsoft-Windows-AppLocker/EXE and DLL': 'AppLocker'
        }
        
        self.linux_logs = {
            '/var/log/auth.log': 'Authentication',
            '/var/log/secure': 'Security',
            '/var/log/syslog': 'System',
            '/var/log/kern.log': 'Kernel',
            '/var/log/apache2/access.log': 'Apache_Access',
            '/var/log/apache2/error.log': 'Apache_Error',
            '/var/log/nginx/access.log': 'Nginx_Access',
            '/var/log/nginx/error.log': 'Nginx_Error',
            '/var/log/fail2ban.log': 'Fail2Ban',
            '/var/log/audit/audit.log': 'Audit',
            '/var/log/suricata/eve.json': 'Suricata',
            '/var/log/ossec.log': 'OSSEC',
            '/var/log/snort/alert': 'Snort',
            '/var/log/ufw.log': 'UFW',
            '/var/log/clamav/clamav.log': 'ClamAV'
        }
        
        # Common network monitoring locations
        self.network_logs = {
            'pcap_files': ['/var/log/tcpdump/', '/var/log/wireshark/', 'C:\\PcapFiles\\'],
            'firewall_logs': ['/var/log/iptables.log', 'C:\\Windows\\System32\\LogFiles\\Firewall\\'],
            'proxy_logs': ['/var/log/squid/', 'C:\\SquidLogs\\']
        }

    def _get_system_info(self) -> Dict[str, Any]:
        """Get comprehensive system information"""
        system_info = {
            'platform': platform.system(),
            'platform_release': platform.release(),
            'platform_version': platform.version(),
            'architecture': platform.machine(),
            'hostname': platform.node(),
            'processor': platform.processor(),
            'timestamp': datetime.now().isoformat(),
            'python_version': platform.python_version()
        }
        
        # Add Windows-specific info
        if platform.system() == 'Windows':
            try:
                system_info['windows_version'] = platform.win32_ver()
            except:
                pass
                
        # Add Linux-specific info
        elif platform.system() == 'Linux':
            try:
                with open('/etc/os-release', 'r') as f:
                    for line in f:
                        if line.startswith('PRETTY_NAME='):
                            system_info['linux_distro'] = line.split('=')[1].strip().strip('"')
                            break
            except:
                pass
                
        return system_info

    def collect_all_logs(self, time_range_hours: int = 24, include_network: bool = True) -> Dict[str, Any]:
        """Collect all available logs from the system
        
        Args:
            time_range_hours: Number of hours back to collect logs
            include_network: Whether to include network logs
            
        Returns:
            Dictionary containing collected log information
        """
        self.logger.info(f"Starting comprehensive log collection for {self.system_info['platform']}")
        
        collection_results = {
            'system_info': self.system_info,
            'collection_timestamp': datetime.now().isoformat(),
            'time_range_hours': time_range_hours,
            'collected_logs': {},
            'errors': [],
            'summary': {}
        }
        
        if self.system_info['platform'] == 'Windows':
            collection_results['collected_logs'].update(
                self._collect_windows_logs(time_range_hours)
            )
        elif self.system_info['platform'] == 'Linux':
            collection_results['collected_logs'].update(
                self._collect_linux_logs(time_range_hours)
            )
        
        if include_network:
            collection_results['collected_logs'].update(
                self._collect_network_logs(time_range_hours)
            )
        
        # Collect process and network information
        collection_results['collected_logs'].update(
            self._collect_system_state()
        )
        
        # Generate summary
        collection_results['summary'] = self._generate_collection_summary(collection_results)
        
        # Save collection results
        results_file = self.output_dir / f"log_collection_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(results_file, 'w') as f:
            json.dump(collection_results, f, indent=2, default=str)
        
        self.logger.info(f"Log collection completed. Results saved to {results_file}")
        return collection_results

    def _collect_windows_logs(self, time_range_hours: int) -> Dict[str, Any]:
        """Collect Windows event logs"""
        windows_logs = {}
        
        for log_name, friendly_name in self.windows_logs.items():
            try:
                self.logger.info(f"Collecting Windows log: {log_name}")
                
                # Use PowerShell to export event logs
                output_file = self.output_dir / f"{friendly_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.evtx"
                
                # Calculate start time
                start_time = datetime.now() - timedelta(hours=time_range_hours)
                
                powershell_cmd = f'''
                Get-WinEvent -FilterHashtable @{{LogName="{log_name}"; StartTime="{start_time.strftime('%Y-%m-%d %H:%M:%S')}"}} -ErrorAction SilentlyContinue | 
                Export-Csv -Path "{output_file.with_suffix('.csv')}" -NoTypeInformation
                '''
                
                # Also export as EVTX for tools that require it
                wevtutil_cmd = f'wevtutil epl "{log_name}" "{output_file}"'
                
                try:
                    # Export as CSV for easier parsing
                    subprocess.run(['powershell', '-Command', powershell_cmd], 
                                 check=True, capture_output=True, text=True, timeout=300)
                    
                    # Export as EVTX
                    subprocess.run(wevtutil_cmd, shell=True, check=True, 
                                 capture_output=True, text=True, timeout=300)
                    
                    # Get event count
                    count_cmd = f'Get-WinEvent -FilterHashtable @{{LogName="{log_name}"; StartTime="{start_time.strftime('%Y-%m-%d %H:%M:%S')}"}} -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count'
                    count_result = subprocess.run(['powershell', '-Command', count_cmd], 
                                                capture_output=True, text=True, timeout=60)
                    
                    event_count = int(count_result.stdout.strip()) if count_result.stdout.strip().isdigit() else 0
                    
                    windows_logs[friendly_name] = {
                        'log_name': log_name,
                        'output_file': str(output_file),
                        'csv_file': str(output_file.with_suffix('.csv')),
                        'event_count': event_count,
                        'collection_status': 'success'
                    }
                    
                except subprocess.TimeoutExpired:
                    self.logger.warning(f"Timeout collecting {log_name}")
                    windows_logs[friendly_name] = {
                        'log_name': log_name,
                        'collection_status': 'timeout'
                    }
                    
            except Exception as e:
                self.logger.error(f"Error collecting Windows log {log_name}: {str(e)}")
                windows_logs[friendly_name] = {
                    'log_name': log_name,
                    'collection_status': 'error',
                    'error': str(e)
                }
        
        return windows_logs

    def _collect_linux_logs(self, time_range_hours: int) -> Dict[str, Any]:
        """Collect Linux log files"""
        linux_logs = {}
        
        for log_path, friendly_name in self.linux_logs.items():
            try:
                log_file = Path(log_path)
                if not log_file.exists():
                    linux_logs[friendly_name] = {
                        'log_path': log_path,
                        'collection_status': 'not_found'
                    }
                    continue
                
                self.logger.info(f"Collecting Linux log: {log_path}")
                
                # Calculate cutoff time
                cutoff_time = datetime.now() - timedelta(hours=time_range_hours)
                
                # Copy recent entries
                output_file = self.output_dir / f"{friendly_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
                
                # Use appropriate method based on log format
                if log_path.endswith('.json'):
                    self._extract_json_logs(log_file, output_file, cutoff_time)
                else:
                    self._extract_text_logs(log_file, output_file, cutoff_time)
                
                # Get line count
                line_count = self._count_lines(output_file)
                
                linux_logs[friendly_name] = {
                    'log_path': log_path,
                    'output_file': str(output_file),
                    'line_count': line_count,
                    'collection_status': 'success'
                }
                
            except Exception as e:
                self.logger.error(f"Error collecting Linux log {log_path}: {str(e)}")
                linux_logs[friendly_name] = {
                    'log_path': log_path,
                    'collection_status': 'error',
                    'error': str(e)
                }
        
        return linux_logs

    def _collect_network_logs(self, time_range_hours: int) -> Dict[str, Any]:
        """Collect network-related logs and packet captures"""
        network_logs = {}
        
        # Collect active network connections
        try:
            self.logger.info("Collecting network connections")
            if platform.system() == 'Windows':
                netstat_cmd = 'netstat -ano'
            else:
                netstat_cmd = 'netstat -tulpn'
            
            result = subprocess.run(netstat_cmd.split(), capture_output=True, text=True, timeout=30)
            
            connections_file = self.output_dir / f"network_connections_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(connections_file, 'w') as f:
                f.write(result.stdout)
            
            network_logs['active_connections'] = {
                'output_file': str(connections_file),
                'collection_status': 'success'
            }
            
        except Exception as e:
            self.logger.error(f"Error collecting network connections: {str(e)}")
            network_logs['active_connections'] = {
                'collection_status': 'error',
                'error': str(e)
            }
        
        # Collect DNS cache
        try:
            self.logger.info("Collecting DNS cache")
            if platform.system() == 'Windows':
                dns_cmd = 'ipconfig /displaydns'
            else:
                dns_cmd = 'cat /etc/resolv.conf'
            
            result = subprocess.run(dns_cmd.split(), capture_output=True, text=True, timeout=30)
            
            dns_file = self.output_dir / f"dns_cache_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(dns_file, 'w') as f:
                f.write(result.stdout)
            
            network_logs['dns_cache'] = {
                'output_file': str(dns_file),
                'collection_status': 'success'
            }
            
        except Exception as e:
            self.logger.error(f"Error collecting DNS cache: {str(e)}")
        
        return network_logs

    def _collect_system_state(self) -> Dict[str, Any]:
        """Collect current system state information"""
        system_state = {}
        
        # Collect running processes
        try:
            self.logger.info("Collecting running processes")
            if platform.system() == 'Windows':
                ps_cmd = 'tasklist /v /fo csv'
            else:
                ps_cmd = 'ps aux'
            
            result = subprocess.run(ps_cmd.split(), capture_output=True, text=True, timeout=30)
            
            processes_file = self.output_dir / f"running_processes_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(processes_file, 'w') as f:
                f.write(result.stdout)
            
            system_state['running_processes'] = {
                'output_file': str(processes_file),
                'collection_status': 'success'
            }
            
        except Exception as e:
            self.logger.error(f"Error collecting processes: {str(e)}")
        
        # Collect system services
        try:
            self.logger.info("Collecting system services")
            if platform.system() == 'Windows':
                services_cmd = 'sc query'
            else:
                services_cmd = 'systemctl list-units --type=service'
            
            result = subprocess.run(services_cmd.split(), capture_output=True, text=True, timeout=30)
            
            services_file = self.output_dir / f"system_services_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(services_file, 'w') as f:
                f.write(result.stdout)
            
            system_state['system_services'] = {
                'output_file': str(services_file),
                'collection_status': 'success'
            }
            
        except Exception as e:
            self.logger.error(f"Error collecting services: {str(e)}")
        
        return system_state

    def _extract_text_logs(self, log_file: Path, output_file: Path, cutoff_time: datetime):
        """Extract recent entries from text log files"""
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as infile:
            with open(output_file, 'w', encoding='utf-8') as outfile:
                for line in infile:
                    # Simple timestamp extraction (can be enhanced per log format)
                    if self._is_recent_log_entry(line, cutoff_time):
                        outfile.write(line)

    def _extract_json_logs(self, log_file: Path, output_file: Path, cutoff_time: datetime):
        """Extract recent entries from JSON log files"""
        with open(log_file, 'r', encoding='utf-8') as infile:
            with open(output_file, 'w', encoding='utf-8') as outfile:
                for line in infile:
                    try:
                        log_entry = json.loads(line)
                        timestamp_str = log_entry.get('timestamp', '')
                        if timestamp_str:
                            timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                            if timestamp >= cutoff_time:
                                outfile.write(line)
                    except json.JSONDecodeError:
                        continue

    def _is_recent_log_entry(self, log_line: str, cutoff_time: datetime) -> bool:
        """Check if a log entry is within the time range"""
        # Simple timestamp patterns - can be enhanced
        timestamp_patterns = [
            r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',  # 2024-01-01 12:00:00
            r'\w{3} \d{2} \d{2}:\d{2}:\d{2}',        # Jan 01 12:00:00
            r'\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}',  # 01/01/2024 12:00:00
        ]
        
        for pattern in timestamp_patterns:
            match = re.search(pattern, log_line)
            if match:
                try:
                    timestamp_str = match.group()
                    # Parse timestamp (simplified - would need more robust parsing)
                    if len(timestamp_str.split('-')) == 3:  # ISO format
                        timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                    elif len(timestamp_str.split('/')) == 3:  # US format
                        timestamp = datetime.strptime(timestamp_str, '%m/%d/%Y %H:%M:%S')
                    else:  # Syslog format
                        current_year = datetime.now().year
                        timestamp = datetime.strptime(f"{current_year} {timestamp_str}", '%Y %b %d %H:%M:%S')
                    
                    return timestamp >= cutoff_time
                except ValueError:
                    continue
        
        # If no timestamp found, include the line
        return True

    def _count_lines(self, file_path: Path) -> int:
        """Count lines in a file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return sum(1 for _ in f)
        except:
            return 0

    def _generate_collection_summary(self, collection_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a summary of the collection process"""
        summary = {
            'total_log_sources': len(collection_results['collected_logs']),
            'successful_collections': 0,
            'failed_collections': 0,
            'total_events': 0,
            'collection_errors': []
        }
        
        for log_name, log_info in collection_results['collected_logs'].items():
            if log_info.get('collection_status') == 'success':
                summary['successful_collections'] += 1
                # Add event counts
                if 'event_count' in log_info:
                    summary['total_events'] += log_info['event_count']
                elif 'line_count' in log_info:
                    summary['total_events'] += log_info['line_count']
            else:
                summary['failed_collections'] += 1
                if 'error' in log_info:
                    summary['collection_errors'].append({
                        'log_source': log_name,
                        'error': log_info['error']
                    })
        
        return summary

    def create_collection_archive(self, collection_results: Dict[str, Any]) -> Path:
        """Create a compressed archive of all collected logs"""
        archive_name = f"log_collection_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        archive_path = self.output_dir / archive_name
        
        with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Add all collected log files
            for log_name, log_info in collection_results['collected_logs'].items():
                if log_info.get('collection_status') == 'success':
                    for file_key in ['output_file', 'csv_file']:
                        if file_key in log_info:
                            file_path = Path(log_info[file_key])
                            if file_path.exists():
                                zipf.write(file_path, file_path.name)
            
            # Add collection results JSON
            results_json = json.dumps(collection_results, indent=2, default=str)
            zipf.writestr('collection_results.json', results_json)
        
        self.logger.info(f"Collection archive created: {archive_path}")
        return archive_path
