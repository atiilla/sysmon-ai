#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Threat Intelligence Module
Provides VirusTotal, AbuseIPDB, and other threat intelligence integrations
"""

import csv
import ipaddress
import logging
import os
import re
import requests
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import colorama
from colorama import Fore, Style

# Initialize colorama for colored terminal output
colorama.init()

class ThreatIntelligenceCollector:
    """Collects and analyzes threat intelligence from various sources"""
    
    def __init__(self, virustotal_api_key: Optional[str] = None, 
                 abuseipdb_api_key: Optional[str] = None,
                 output_dir: str = "output"):
        """Initialize threat intelligence collector
        
        Args:
            virustotal_api_key: VirusTotal API key
            abuseipdb_api_key: AbuseIPDB API key
            output_dir: Directory to store results
        """
        self.logger = logging.getLogger(__name__)
        self.vt_api_key = virustotal_api_key
        self.abuse_api_key = abuseipdb_api_key
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # API endpoints
        self.vt_base_url = "https://www.virustotal.com/api/v3"
        self.abuse_base_url = "https://api.abuseipdb.com/api/v2"
        
        # Known safe IPs to exclude
        self.safe_ips = [
            "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",  # Google & Cloudflare DNS
            "23.200.0.0/13", "104.64.0.0/10",            # Akamai CDN
            "13.107.0.0/16", "20.190.128.0/18",          # Microsoft O365
            "52.0.0.0/8", "54.0.0.0/8", "99.0.0.0/8",    # AWS IP Ranges
            "35.192.0.0/12", "34.80.0.0/12",             # GCP
            "40.74.0.0/16", "13.64.0.0/11",              # Azure
        ]
        
        # CSV file for results
        self.csv_file = self.output_dir / "threat_lookup_results.csv"
        
    def is_safe_ip(self, ip: str) -> bool:
        """Check if an IP is in the safe IP ranges"""
        try:
            check_ip = ipaddress.ip_address(ip)
            
            for safe_ip in self.safe_ips:
                if '/' in safe_ip:  # CIDR notation
                    if check_ip in ipaddress.ip_network(safe_ip):
                        return True
                else:  # Single IP
                    if check_ip == ipaddress.ip_address(safe_ip):
                        return True
            return False
        except Exception:
            return False  # Not a valid IP address
    
    def is_valid_ip(self, ip: str) -> bool:
        """Check if the input is a valid IP address"""
        pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        return re.match(pattern, ip) is not None
    
    def extract_ips_from_sysmon_logs(self, evtx_path: Optional[Path] = None) -> Tuple[List[str], Path]:
        """Extract IPs from Sysmon logs and filter out safe IPs"""
        filtered_ips = []
        
        self.logger.info("Extracting and filtering IPs from Sysmon logs...")
        
        # PowerShell command to extract IPs from Sysmon event logs
        eventlog_name = "Microsoft-Windows-Sysmon/Operational"
        ps_cmd = (
            f"Get-WinEvent -LogName '{eventlog_name}' | "
            f"Where-Object {{$_.Id -eq 3}} | "
            f"ForEach-Object {{ "
            f"$eventXml = [xml]$_.ToXml(); "
            f"$eventXml.Event.EventData.Data | "
            f"Where-Object {{ $_.Name -eq 'DestinationIp' }} | "
            f"Select-Object -ExpandProperty '#text' "
            f"}} | Sort-Object -Unique"
        )
        
        try:
            # Run PowerShell command to get IPs
            import subprocess
            result = subprocess.run(
                ["powershell", "-NoLogo", "-NoProfile", "-Command", ps_cmd],
                text=True, capture_output=True, check=True, timeout=300
            )
            
            raw_ips = result.stdout.strip().split('\n')
            
            # Filter out safe IPs
            for ip in raw_ips:
                ip = ip.strip()
                if ip and not self.is_safe_ip(ip):
                    filtered_ips.append(ip)
            
            # Save filtered IPs to file
            ip_output_path = self.output_dir / f"filtered_sysmon_ips_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(ip_output_path, 'w') as f:
                for ip in filtered_ips:
                    f.write(f"{ip}\n")
            
            self.logger.info(f"Extracted {len(filtered_ips)} unique filtered IPs from Sysmon logs")
            self.logger.info(f"Saved to {ip_output_path}")
            
            return filtered_ips, ip_output_path
            
        except subprocess.TimeoutExpired:
            self.logger.error("PowerShell command timed out while extracting IPs")
            return [], Path()
        except Exception as e:
            self.logger.error(f"Error extracting IPs from Sysmon logs: {e}")
            return [], Path()
    
    def query_virustotal(self, value: str) -> Optional[Dict[str, Any]]:
        """Perform a lookup using VirusTotal API"""
        if not self.vt_api_key:
            self.logger.warning("No VirusTotal API key found. Skipping VirusTotal lookup.")
            return None
            
        headers = {"x-apikey": self.vt_api_key}
        value = value.replace("[.]", ".")  # Ensure proper domain formatting

        if value.count(".") >= 1 and not value.replace(".", "").isdigit():
            endpoint = f"/domains/{value}"  # Domain
        elif value.replace(".", "").isdigit():
            endpoint = f"/ip_addresses/{value}"  # IP Address
        else:
            endpoint = f"/files/{value}"  # File Hash

        url = self.vt_base_url + endpoint
        
        try:
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                security_score = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                
                # Format Output
                formatted_results = (
                    f"\n📊 {Fore.CYAN}VirusTotal Results:{Style.RESET_ALL}"
                    f"\n{Fore.LIGHTBLACK_EX}────────────────────────────────────────{Style.RESET_ALL}"
                    f"\n🔹 {Fore.RED}{'Malicious'.ljust(12)}: {security_score.get('malicious', 0)}{Style.RESET_ALL}"
                    f"\n🔹 {Fore.YELLOW}{'Suspicious'.ljust(12)}: {security_score.get('suspicious', 0)}{Style.RESET_ALL}"
                    f"\n🔹 {Fore.BLUE}{'Undetected'.ljust(12)}: {security_score.get('undetected', 0)}{Style.RESET_ALL}"
                    f"\n🔹 {Fore.GREEN}{'Harmless'.ljust(12)}: {security_score.get('harmless', 0)}"
                    f"\n🔹 {Fore.MAGENTA}{'Timeout'.ljust(12)}: {security_score.get('timeout', 0)}{Style.RESET_ALL}"
                    f"\n{Fore.LIGHTBLACK_EX}────────────────────────────────────────{Style.RESET_ALL}"
                )
                
                print(formatted_results)
                return security_score
            elif response.status_code == 429:
                self.logger.warning("VirusTotal API rate limit exceeded. Waiting...")
                time.sleep(60)  # Wait 1 minute for rate limit
                return None
            else:
                error_msg = response.json().get('error', {}).get('message', 'Unknown Error')
                self.logger.error(f"VirusTotal API error: {response.status_code} - {error_msg}")
                return None
                
        except requests.RequestException as e:
            self.logger.error(f"Error querying VirusTotal: {e}")
            return None
    
    def query_abuseipdb(self, ip: str) -> Optional[Dict[str, Any]]:
        """Perform an AbuseIPDB lookup"""
        if not self.abuse_api_key:
            self.logger.warning("No AbuseIPDB API key found. Skipping AbuseIPDB lookup.")
            return None
            
        # Ensure the input is a valid IP address
        ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
        if not re.match(ip_pattern, ip):
            self.logger.warning(f"Skipping AbuseIPDB check: {ip} is not a valid IP address.")
            return None
        
        url = f"{self.abuse_base_url}/check?ipAddress={ip}&maxAgeInDays=90"
        headers = {
            "Key": self.abuse_api_key,
            "Accept": "application/json"
        }

        try:
            response = requests.get(url, headers=headers, timeout=30)

            if response.status_code == 200:
                data = response.json().get("data", {})
                abuse_score = data.get("abuseConfidenceScore", 0)
                total_reports = data.get("totalReports", 0)
                last_reported_raw = data.get("lastReportedAt", None)

                last_reported = (
                    datetime.strptime(last_reported_raw, "%Y-%m-%dT%H:%M:%S%z").strftime("%B %d, %Y at %I:%M %p %Z")
                    if last_reported_raw else "Never Reported"
                )

                # Format Output
                formatted_results = (
                    f"\n📊 {Fore.CYAN}AbuseIPDB Results:{Style.RESET_ALL}"
                    f"\n{Fore.LIGHTBLACK_EX}────────────────────────────────────────{Style.RESET_ALL}"
                    f"\n🔹 {Fore.YELLOW}IP Address   : {ip}{Style.RESET_ALL}"
                    f"\n🔹 {Fore.RED if abuse_score > 50 else Fore.GREEN}Abuse Score  : {abuse_score}{Style.RESET_ALL}"
                    f"\n🔹 {Fore.RED if total_reports > 50 else Fore.GREEN}Total Reports: {total_reports}{Style.RESET_ALL}"
                    f"\n🔹 {Fore.BLUE}Last Reported: {Fore.LIGHTCYAN_EX}{last_reported}{Style.RESET_ALL}"
                    f"\n{Fore.LIGHTBLACK_EX}────────────────────────────────────────{Style.RESET_ALL}"
                )

                print(formatted_results)
                return {
                    "abuseConfidenceScore": abuse_score,
                    "totalReports": total_reports,
                    "lastReportedAt": last_reported
                }
            elif response.status_code == 422:
                self.logger.warning(f"Invalid input format for AbuseIPDB: {ip}")
                return None
            elif response.status_code == 429:
                self.logger.warning("AbuseIPDB API rate limit exceeded. Waiting...")
                time.sleep(60)  # Wait 1 minute for rate limit
                return None
            else:
                error_msg = response.json().get('message', 'Unknown Error')
                self.logger.error(f"AbuseIPDB API error: {response.status_code} - {error_msg}")
                return None
                
        except requests.RequestException as e:
            self.logger.error(f"Error querying AbuseIPDB: {e}")
            return None
    
    def save_to_csv(self, input_value: str, vt_data: Optional[Dict] = None, 
                   abuse_data: Optional[Dict] = None):
        """Save results from VirusTotal and AbuseIPDB to a CSV file"""
        file_exists = self.csv_file.exists()

        with open(self.csv_file, mode="a", newline="", encoding="utf-8") as file:
            fieldnames = [
                "Date", "Input",
                "Malicious", "Harmless", "Undetected", "Suspicious", "Timeout",  # VirusTotal
                "Abuse Score", "Total Reports", "Last Reported"  # AbuseIPDB
            ]
            writer = csv.DictWriter(file, fieldnames=fieldnames)

            if not file_exists:
                writer.writeheader()

            # Ensure abuse_data is not None
            abuse_score = abuse_data["abuseConfidenceScore"] if abuse_data else "N/A"
            total_reports = abuse_data["totalReports"] if abuse_data else "N/A"
            last_reported = abuse_data["lastReportedAt"] if abuse_data else "N/A"

            # Ensure vt_data is not None
            row = {
                "Date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "Input": input_value,
                "Malicious": vt_data.get("malicious", "N/A") if vt_data else "N/A",
                "Harmless": vt_data.get("harmless", "N/A") if vt_data else "N/A",
                "Undetected": vt_data.get("undetected", "N/A") if vt_data else "N/A",
                "Suspicious": vt_data.get("suspicious", "N/A") if vt_data else "N/A",
                "Timeout": vt_data.get("timeout", "N/A") if vt_data else "N/A",
                "Abuse Score": abuse_score,
                "Total Reports": total_reports,
                "Last Reported": last_reported,
            }

            writer.writerow(row)
    
    def analyze_ip_list(self, ips_list: List[str]) -> Dict[str, Any]:
        """Process a list of IPs through VirusTotal and AbuseIPDB"""
        self.logger.info("Analyzing IPs with threat intelligence...")
        
        results = {
            "total_ips": len(ips_list),
            "vt_queries": 0,
            "abuse_queries": 0,
            "malicious_ips": [],
            "suspicious_ips": [],
            "errors": []
        }

        for ip in ips_list:
            print("\n" + "-" * 50)
            print(f"🔍 Processing: {Fore.CYAN}{ip}{Style.RESET_ALL}")

            vt_result, abuse_result = None, None

            # Query VirusTotal
            try:
                results["vt_queries"] += 1
                vt_result = self.query_virustotal(ip)
                
                # Check if IP is flagged as malicious
                if vt_result and vt_result.get("malicious", 0) > 0:
                    results["malicious_ips"].append({
                        "ip": ip,
                        "malicious_count": vt_result.get("malicious", 0),
                        "source": "VirusTotal"
                    })
                elif vt_result and vt_result.get("suspicious", 0) > 0:
                    results["suspicious_ips"].append({
                        "ip": ip,
                        "suspicious_count": vt_result.get("suspicious", 0),
                        "source": "VirusTotal"
                    })
                    
            except Exception as e:
                self.logger.error(f"Error querying VirusTotal for {ip}: {e}")
                results["errors"].append(f"VirusTotal error for {ip}: {e}")

            # Query AbuseIPDB for valid IPs
            if self.is_valid_ip(ip):
                try:
                    results["abuse_queries"] += 1
                    abuse_result = self.query_abuseipdb(ip)
                    
                    # Check if IP has high abuse score
                    if abuse_result and abuse_result.get("abuseConfidenceScore", 0) > 75:
                        results["malicious_ips"].append({
                            "ip": ip,
                            "abuse_score": abuse_result.get("abuseConfidenceScore", 0),
                            "source": "AbuseIPDB"
                        })
                    elif abuse_result and abuse_result.get("abuseConfidenceScore", 0) > 25:
                        results["suspicious_ips"].append({
                            "ip": ip,
                            "abuse_score": abuse_result.get("abuseConfidenceScore", 0),
                            "source": "AbuseIPDB"
                        })
                        
                except Exception as e:
                    self.logger.error(f"Error querying AbuseIPDB for {ip}: {e}")
                    results["errors"].append(f"AbuseIPDB error for {ip}: {e}")

            # Save results to CSV
            try:
                self.save_to_csv(ip, vt_data=vt_result, abuse_data=abuse_result)
            except Exception as e:
                self.logger.error(f"Error saving results for {ip}: {e}")
                results["errors"].append(f"CSV save error for {ip}: {e}")
            
            # Add small delay to respect API rate limits
            time.sleep(1)

        print("\n✅ Scan Completed:")
        print(f"🔹 Total Queries      : {len(ips_list)}")
        print(f"🔹 VirusTotal Queries : {results['vt_queries']}")
        print(f"🔹 AbuseIPDB Queries  : {results['abuse_queries']}")
        print(f"🔹 Malicious IPs      : {len(results['malicious_ips'])}")
        print(f"🔹 Suspicious IPs     : {len(results['suspicious_ips'])}")
        print(f"📂 Results saved to   : {self.csv_file}")
        
        return results
    
    def generate_pdf_report(self) -> Optional[Path]:
        """Generate a PDF report from CSV results"""
        try:
            from fpdf import FPDF
            import pandas as pd
        except ImportError:
            self.logger.warning("FPDF or pandas library not installed. Skipping PDF report generation.")
            print("Install with: pip install fpdf pandas")
            return None

        if not self.csv_file.exists() or self.csv_file.stat().st_size == 0:
            self.logger.warning("No CSV data available for PDF report")
            return None

        try:
            # Read CSV with proper encoding
            df = pd.read_csv(self.csv_file, encoding="utf-8-sig")

            pdf = FPDF(orientation='L', unit='mm', format='A4')  # Landscape mode
            pdf.set_auto_page_break(auto=True, margin=15)
            pdf.add_page()
            pdf.set_font("Arial", style="", size=8)

            # Define column widths
            col_widths = [35, 50, 20, 20, 20, 20, 20, 25, 25, 35]
            headers = df.columns.tolist()

            # Add Table Header
            pdf.set_fill_color(200, 200, 200)
            pdf.set_font("Arial", style="B", size=9)
            
            for i, header in enumerate(headers):
                pdf.cell(col_widths[i], 8, header.encode('latin-1', 'replace').decode('latin-1'), 
                        border=1, align="C", fill=True)
            pdf.ln()

            # Add Table Rows
            pdf.set_font("Arial", size=8)
            
            for _, row in df.iterrows():
                for i, cell in enumerate(row):
                    text = str(cell) if pd.notna(cell) else "N/A"
                    text = text.encode('latin-1', 'replace').decode('latin-1')
                    pdf.cell(col_widths[i], 8, text, border=1, align="C")
                pdf.ln()

            # Save PDF
            pdf_file = self.output_dir / f"Sysmon_Threat_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            pdf.output(str(pdf_file), 'F')
            self.logger.info(f"PDF report generated: {pdf_file}")
            return pdf_file
            
        except Exception as e:
            self.logger.error(f"Error generating PDF report: {e}")
            return None
