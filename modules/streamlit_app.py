#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sysmon AI Streamlit Web Interface
Interactive web UI for Sysmon log analysis and threat hunting
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
from datetime import datetime, timedelta
import json
import io
import sys
import os

# Add parent directory to path to ensure modules can be imported properly
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

# Import required modules
from modules.config import config
from modules.groq_analyzer import SysmonAnalyzer

def generate_threat_hunter_report(results, format_type="display"):
    """Generate comprehensive threat hunter report"""
    
    # Calculate risk metrics
    total_events = results.get('total_events', 0)
    suspicious_count = len(results.get('suspicious_events', []))
    risk_score = min(100, suspicious_count * 5)
    
    # MITRE ATT&CK mapping
    mitre_mapping = {
        'process_injection': 'T1055 - Process Injection',
        'powershell_obfuscation': 'T1059.001 - PowerShell',
        'privilege_escalation': 'T1068 - Exploitation for Privilege Escalation',
        'suspicious_network': 'T1071 - Application Layer Protocol',
        'file_modification': 'T1070 - Indicator Removal on Host',
        'registry_modification': 'T1112 - Modify Registry',
        'service_creation': 'T1543.003 - Windows Service'
    }
    
    # Generate IOCs
    iocs = extract_iocs_from_events(results.get('suspicious_events', []))
    
    report = f"""# 🛡️ COMPREHENSIVE THREAT HUNTING REPORT

## 📊 EXECUTIVE SUMMARY

**Classification:** CONFIDENTIAL  
**Analysis Date:** {datetime.now().strftime('%B %d, %Y at %H:%M UTC')}  
**Source File:** `{results.get('file_path', 'Unknown')}`  
**Analyst:** Sysmon AI Threat Hunting Platform  

---

### 🎯 KEY FINDINGS

- **Total Security Events:** {total_events:,}
- **Suspicious Activities Detected:** {suspicious_count}
- **Overall Risk Assessment:** {'🔴 HIGH' if risk_score > 70 else '🟡 MEDIUM' if risk_score > 30 else '🟢 LOW'} ({risk_score}/100)
- **MITRE ATT&CK Techniques Identified:** {len([t for t in results.get('threat_categories', {}).keys() if t in mitre_mapping])}

---

## 🚨 THREAT LANDSCAPE ANALYSIS

### Detected Threat Categories:
"""
    
    # Add threat categories with MITRE mapping
    for category, count in results.get('threat_categories', {}).items():
        mitre_tech = mitre_mapping.get(category, f'Unknown technique for {category}')
        severity = '🔴 CRITICAL' if count > 10 else '🟡 MEDIUM' if count > 3 else '🟢 LOW'
        report += f"- **{category.replace('_', ' ').title()}**: {count} events | {severity} | {mitre_tech}\n"
    
    report += f"""

---

## 🔍 DETAILED ANALYSIS

### Timeline Analysis
**Analysis Period:** {results.get('analysis_timestamp', 'Unknown')}

### Process Analysis
"""
    
    # Add process information
    processes = set()
    for event in results.get('suspicious_events', []):
        if 'process_info' in event and event['process_info'].get('process_name'):
            processes.add(event['process_info']['process_name'])
    
    if processes:
        report += "**Suspicious Processes Detected:**\n"
        for process in sorted(processes):
            report += f"- `{process}`\n"
    else:
        report += "No specific process information available.\n"
    
    report += f"""

### Network Activity Analysis
"""
    
    # Add network information
    network_connections = set()
    for event in results.get('suspicious_events', []):
        if 'network_info' in event:
            if event['network_info'].get('destination_ip'):
                network_connections.add(event['network_info']['destination_ip'])
    
    if network_connections:
        report += "**Suspicious Network Connections:**\n"
        for connection in sorted(network_connections):
            report += f"- `{connection}`\n"
    else:
        report += "No suspicious network connections detected.\n"
    
    report += f"""

---

## 🎯 INDICATORS OF COMPROMISE (IOCs)

### File Hashes
"""
    for file_hash in iocs.get('file_hashes', []):
        report += f"- `{file_hash}`\n"
    
    report += f"""
### IP Addresses
"""
    for ip in iocs.get('ip_addresses', []):
        report += f"- `{ip}`\n"
    
    report += f"""
### File Paths
"""
    for path in iocs.get('file_paths', []):
        report += f"- `{path}`\n"
    
    # Add AI Analysis if available
    if results.get('ai_analysis'):
        report += f"""

---

## 🤖 AI-POWERED ANALYSIS

{results['ai_analysis']}

---
"""
    
    report += f"""
## 📋 RECOMMENDATIONS

### Immediate Actions Required:
1. **Investigate High-Risk Events:** Review all events marked as critical severity
2. **Network Isolation:** Consider isolating affected systems if lateral movement is detected
3. **Credential Reset:** Reset credentials for any compromised accounts
4. **Patch Management:** Ensure all systems are updated with latest security patches

### Long-term Security Improvements:
1. **Enhanced Monitoring:** Implement additional logging for detected attack vectors
2. **User Training:** Conduct security awareness training based on identified threats
3. **Security Controls:** Review and strengthen security controls in affected areas
4. **Incident Response:** Update incident response procedures based on findings

---

## 🔧 TECHNICAL DETAILS

### Analysis Methodology:
- **Detection Engine:** Sysmon AI with pattern-based threat detection
- **MITRE ATT&CK Framework:** Used for threat categorization
- **Machine Learning:** {('Enabled' if results.get('ai_analysis') else 'Not Available')}
- **Confidence Level:** {('High' if suspicious_count > 5 else 'Medium' if suspicious_count > 0 else 'Low')}

### Event Summary:
"""
    
    # Add event summary
    event_ids = {}
    for event in results.get('suspicious_events', []):
        event_id = event.get('event_id', 'Unknown')
        event_ids[event_id] = event_ids.get(event_id, 0) + 1
    
    for event_id, count in sorted(event_ids.items()):
        report += f"- **Event ID {event_id}:** {count} occurrences\n"
    
    report += f"""

---

**Report Generated by:** Sysmon AI Threat Hunting Platform  
**Classification:** CONFIDENTIAL - Handle according to organizational security policies  
**Next Review Date:** {(datetime.now() + timedelta(days=7)).strftime('%B %d, %Y')}

---

*This report contains sensitive security information. Distribution should be limited to authorized security personnel only.*
"""
    
    return report

def generate_executive_summary(results):
    """Generate executive summary for management"""
    
    suspicious_count = len(results.get('suspicious_events', []))
    risk_score = min(100, suspicious_count * 5)
    
    summary = f"""EXECUTIVE SUMMARY - CYBERSECURITY THREAT ANALYSIS
================================================================

REPORT DATE: {datetime.now().strftime('%B %d, %Y')}
CLASSIFICATION: CONFIDENTIAL

KEY FINDINGS:
- Total Security Events Analyzed: {results.get('total_events', 0):,}
- Suspicious Activities Detected: {suspicious_count}
- Overall Risk Level: {'HIGH' if risk_score > 70 else 'MEDIUM' if risk_score > 30 else 'LOW'}
- Risk Score: {risk_score}/100

THREAT CATEGORIES DETECTED:
"""
    
    for category, count in results.get('threat_categories', {}).items():
        summary += f"- {category.replace('_', ' ').title()}: {count} incidents\n"
    
    summary += f"""
BUSINESS IMPACT ASSESSMENT:
- Security Posture: {'Compromised' if risk_score > 70 else 'At Risk' if risk_score > 30 else 'Stable'}
- Recommended Action Level: {'Immediate' if risk_score > 70 else 'Standard' if risk_score > 30 else 'Routine'}

RECOMMENDATIONS:
1. {'Initiate incident response procedures' if risk_score > 70 else 'Review and monitor identified threats'}
2. {'Consider system isolation and forensic analysis' if risk_score > 70 else 'Implement additional monitoring'}
3. Schedule follow-up security assessment within 7 days

This summary is intended for executive leadership and contains sensitive security information.
"""
    
    return summary

def extract_iocs_from_events(events):
    """Extract Indicators of Compromise from events"""
    iocs = {
        'file_hashes': set(),
        'ip_addresses': set(),
        'file_paths': set(),
        'registry_keys': set(),
        'process_names': set()
    }
    
    for event in events:
        # Extract file hashes
        if 'file_info' in event:
            if event['file_info'].get('hash'):
                iocs['file_hashes'].add(event['file_info']['hash'])
            if event['file_info'].get('path'):
                iocs['file_paths'].add(event['file_info']['path'])
        
        # Extract network IOCs
        if 'network_info' in event:
            if event['network_info'].get('destination_ip'):
                iocs['ip_addresses'].add(event['network_info']['destination_ip'])
        
        # Extract process IOCs
        if 'process_info' in event:
            if event['process_info'].get('process_name'):
                iocs['process_names'].add(event['process_info']['process_name'])
    
    # Convert sets to lists for JSON serialization
    return {k: list(v) for k, v in iocs.items()}

# Import additional modules
from modules.threat_hunter import ThreatHuntingAnalyzer 
from modules.report_generator import ThreatReportGenerator
from modules.log_collector import LogCollector

# This section is intentionally left empty as it has been moved to the main() function


def show_welcome_screen():
    """Display welcome screen when no analysis has been performed"""
    st.info("👆 Use the sidebar options to start your analysis")
    
    # Show sample analysis capabilities
    st.subheader("🔧 Analysis Capabilities")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        **Process Injection Detection**
        - CreateRemoteThread
        - VirtualAllocEx
        - WriteProcessMemory
        - SetWindowsHookEx
        """)
    
    with col2:
        st.markdown("""
        **PowerShell Obfuscation**
        - EncodedCommand
        - FromBase64String
        - Invoke-Expression
        - DownloadString
        """)
    
    with col3:
        st.markdown("""
        **Privilege Escalation**
        - SeDebugPrivilege
        - SeTakeOwnershipPrivilege
        - SeImpersonatePrivilege
        """)


def show_evtx_analysis_sidebar():
    """Show EVTX analysis sidebar"""
    st.subheader("📄 EVTX File Analysis")
    with st.form("evtx_analysis_form"):
        uploaded_file = st.file_uploader("Upload EVTX File", type=['evtx'], key="evtx_file_upload")
        simple_analysis = st.checkbox("Simple Analysis", value=False, help="Uncheck for detailed analysis (default)", key="evtx_simple")
        use_ai = st.checkbox("Use AI Analysis", value=True, help="Enable AI-powered threat analysis", key="evtx_ai")
        
        if use_ai:
            groq_api_key = st.text_input("Groq API Key", type="password", 
                                        value=config.GROQ_API_KEY if hasattr(config, 'GROQ_API_KEY') else "", 
                                        help="For AI-powered analysis", key="evtx_groq_key")
        else:
            groq_api_key = None
        
        submit_evtx = st.form_submit_button("Analyze EVTX", type="primary", disabled=not uploaded_file)
        
        if submit_evtx and uploaded_file:
            handle_evtx_analysis(uploaded_file, simple_analysis, groq_api_key)

def show_threat_intel_sidebar():
    """Show threat intelligence sidebar"""
    st.subheader("🔍 Threat Intelligence")
    
    # API Configuration
    st.write("**API Configuration**")
    vt_key = st.text_input("VirusTotal API Key", type="password", 
                          value=config.VIRUSTOTAL_API_KEY if hasattr(config, 'VIRUSTOTAL_API_KEY') else "",
                          help="For domain/IP/hash analysis")
    abuse_key = st.text_input("AbuseIPDB API Key", type="password",
                             value=config.ABUSEIPDB_API_KEY if hasattr(config, 'ABUSEIPDB_API_KEY') else "",
                             help="For IP reputation analysis")
    
    st.write("**Analysis Options**")
    intel_mode = st.selectbox(
        "Analysis Type",
        ["Extract IPs from Sysmon", "Upload IP List", "Single Indicator", "Generate PDF Report"],
        help="Choose threat intelligence analysis type"
    )
    
    if intel_mode == "Upload IP List":
        uploaded_ip_file = st.file_uploader("Upload IP List", type=['txt'], 
                                           help="Text file with one IP per line")
        if st.button("Analyze IP List", disabled=not uploaded_ip_file or (not vt_key and not abuse_key)):
            handle_ip_list_analysis(uploaded_ip_file, vt_key, abuse_key)
    
    elif intel_mode == "Single Indicator":
        indicator_type = st.selectbox("Indicator Type", ["IP Address", "Domain", "File Hash"])
        indicator_value = st.text_input(f"Enter {indicator_type}")
        if st.button(f"Analyze {indicator_type}", disabled=not indicator_value or (not vt_key and not abuse_key)):
            handle_single_indicator_analysis(indicator_type, indicator_value, vt_key, abuse_key)
    
    elif intel_mode == "Extract IPs from Sysmon":
        if st.button("Extract & Analyze Sysmon IPs", disabled=(not vt_key and not abuse_key)):
            handle_sysmon_ip_extraction(vt_key, abuse_key)
    
    elif intel_mode == "Generate PDF Report":
        if st.button("Generate PDF Report"):
            handle_pdf_generation()

def show_log_collection_sidebar():
    """Show log collection sidebar"""
    st.subheader("📋 Log Collection")
    
    with st.form("log_collection_form"):
        time_range = st.slider("Time Range (hours)", min_value=1, max_value=168, value=24)
        sysmon_only = st.checkbox("Sysmon Logs Only", value=True, help="Collect only Sysmon logs for faster processing")
        analyze_ips = st.checkbox("Analyze IPs", value=True, help="Extract and analyze IPs with threat intelligence")
        
        if analyze_ips:
            vt_key_collection = st.text_input("VirusTotal API Key", type="password",
                                             value=config.VIRUSTOTAL_API_KEY if hasattr(config, 'VIRUSTOTAL_API_KEY') else "")
            abuse_key_collection = st.text_input("AbuseIPDB API Key", type="password",
                                                value=config.ABUSEIPDB_API_KEY if hasattr(config, 'ABUSEIPDB_API_KEY') else "")
        
        submit_collection = st.form_submit_button("Start Collection", type="primary")
        
        if submit_collection:
            api_keys = {}
            if analyze_ips:
                api_keys['vt_key'] = vt_key_collection
                api_keys['abuse_key'] = abuse_key_collection
            handle_log_collection(time_range, sysmon_only, analyze_ips, api_keys)

def handle_evtx_analysis(uploaded_file, simple_analysis, groq_api_key):
    """Handle EVTX file analysis"""
    import tempfile
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.evtx')
    temp_file.write(uploaded_file.getbuffer())
    temp_file.close()
    
    with st.spinner("Analyzing EVTX file..."):
        analyzer = SysmonAnalyzer(groq_api_key=groq_api_key if groq_api_key else None)
        detailed = not simple_analysis
        results = analyzer.analyze_evtx(temp_file.name, detailed=detailed)
        st.session_state.results = results
        st.session_state.analysis_type = "evtx"
    
    try:
        os.unlink(temp_file.name)
    except:
        pass
        
    st.success("Analysis completed!")

def handle_ip_list_analysis(uploaded_file, vt_key, abuse_key):
    """Handle IP list analysis"""
    from modules.threat_intelligence import ThreatIntelligenceCollector
    
    content = uploaded_file.read().decode('utf-8')
    ips = [line.strip() for line in content.split('\n') if line.strip()]
    
    if not ips:
        st.error("No valid IPs found in file")
        return
    
    with st.spinner(f"Analyzing {len(ips)} IPs..."):
        threat_intel = ThreatIntelligenceCollector(
            virustotal_api_key=vt_key if vt_key else None,
            abuseipdb_api_key=abuse_key if abuse_key else None,
            output_dir=str(config.OUTPUT_DIR)
        )
        
        results = threat_intel.analyze_ip_list(ips)
        st.session_state.threat_intel_results = results
        st.session_state.analysis_type = "threat_intel"
        
        pdf_report = threat_intel.generate_pdf_report()
        if pdf_report:
            st.session_state.pdf_report_path = str(pdf_report)
    
    st.success(f"Analysis completed! Found {len(results.get('malicious_ips', []))} malicious and {len(results.get('suspicious_ips', []))} suspicious IPs")

def handle_single_indicator_analysis(indicator_type, value, vt_key, abuse_key):
    """Handle single indicator analysis"""
    from modules.threat_intelligence import ThreatIntelligenceCollector
    
    with st.spinner(f"Analyzing {indicator_type.lower()}: {value}"):
        threat_intel = ThreatIntelligenceCollector(
            virustotal_api_key=vt_key if vt_key else None,
            abuseipdb_api_key=abuse_key if abuse_key else None,
            output_dir=str(config.OUTPUT_DIR)
        )
        
        vt_result = threat_intel.query_virustotal(value)
        abuse_result = None
        
        if indicator_type == "IP Address" and threat_intel.is_valid_ip(value):
            abuse_result = threat_intel.query_abuseipdb(value)
        
        threat_intel.save_to_csv(value, vt_result, abuse_result)
        
        st.session_state.single_indicator_results = {
            'indicator': value,
            'type': indicator_type,
            'vt_result': vt_result,
            'abuse_result': abuse_result
        }
        st.session_state.analysis_type = "single_indicator"
    
    st.success(f"{indicator_type} analysis completed!")

def handle_sysmon_ip_extraction(vt_key, abuse_key):
    """Handle Sysmon IP extraction and analysis"""
    from modules.threat_intelligence import ThreatIntelligenceCollector
    
    with st.spinner("Extracting IPs from Sysmon logs..."):
        threat_intel = ThreatIntelligenceCollector(
            virustotal_api_key=vt_key if vt_key else None,
            abuseipdb_api_key=abuse_key if abuse_key else None,
            output_dir=str(config.OUTPUT_DIR)
        )
        
        ips_list, ip_file_path = threat_intel.extract_ips_from_sysmon_logs()
        
        if ips_list:
            st.write(f"Extracted {len(ips_list)} IPs from Sysmon logs")
            
            with st.spinner(f"Analyzing {len(ips_list)} IPs..."):
                results = threat_intel.analyze_ip_list(ips_list)
                st.session_state.threat_intel_results = results
                st.session_state.analysis_type = "threat_intel"
                
                pdf_report = threat_intel.generate_pdf_report()
                if pdf_report:
                    st.session_state.pdf_report_path = str(pdf_report)
            
            st.success(f"Analysis completed! Found {len(results.get('malicious_ips', []))} malicious and {len(results.get('suspicious_ips', []))} suspicious IPs")
        else:
            st.warning("No IPs extracted from Sysmon logs")

def handle_pdf_generation():
    """Handle PDF report generation"""
    from modules.threat_intelligence import ThreatIntelligenceCollector
    
    threat_intel = ThreatIntelligenceCollector(output_dir=str(config.OUTPUT_DIR))
    
    with st.spinner("Generating PDF report..."):
        pdf_report = threat_intel.generate_pdf_report()
        
        if pdf_report:
            st.session_state.pdf_report_path = str(pdf_report)
            st.success(f"PDF report generated: {pdf_report.name}")
        else:
            st.error("Failed to generate PDF report. Make sure you have analysis results in CSV format.")

def handle_log_collection(time_range, sysmon_only, analyze_ips, api_keys):
    """Handle log collection"""
    from modules.log_collector import LogCollector
    
    with st.spinner(f"Collecting logs for the past {time_range} hours..."):
        log_collector = LogCollector()
        
        if sysmon_only and analyze_ips and (api_keys.get('vt_key') or api_keys.get('abuse_key')):
            results = log_collector.collect_sysmon_with_ip_analysis(
                time_range_hours=time_range,
                analyze_ips=True
            )
        elif sysmon_only:
            # Collect only Sysmon logs
            logs = log_collector.collect_sysmon_logs(time_range=time_range)
            results = {"sysmon_logs": logs}
        else:
            # Collect all logs
            results = log_collector.collect_all_logs(time_range_hours=time_range)
        
        if results:
            st.session_state.collection_results = results
            st.session_state.analysis_type = "log_collection"
            st.success("Log collection completed!")
        else:
            st.error("Log collection failed or no logs found")

def display_main_content():
    """Display main content based on analysis type"""
    if 'results' in st.session_state and st.session_state.get('analysis_type') == 'evtx':
        display_evtx_results(st.session_state.results)
    elif 'threat_intel_results' in st.session_state and st.session_state.get('analysis_type') == 'threat_intel':
        display_threat_intel_results(st.session_state.threat_intel_results)
    elif 'single_indicator_results' in st.session_state and st.session_state.get('analysis_type') == 'single_indicator':
        display_single_indicator_results(st.session_state.single_indicator_results)
    elif 'collection_results' in st.session_state and st.session_state.get('analysis_type') == 'log_collection':
        display_collection_results(st.session_state.collection_results)
    else:
        display_welcome_screen()

def display_threat_intel_results(results):
    """Display threat intelligence analysis results"""
    st.header("🔍 Threat Intelligence Analysis Results")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total IPs Analyzed", results.get('total_ips', 0))
    
    with col2:
        st.metric("Malicious IPs", len(results.get('malicious_ips', [])))
    
    with col3:
        st.metric("Suspicious IPs", len(results.get('suspicious_ips', [])))
    
    with col4:
        st.metric("Total Queries", results.get('vt_queries', 0) + results.get('abuse_queries', 0))
    
    if results.get('malicious_ips'):
        st.subheader("🚨 Malicious IPs Found")
        malicious_df = pd.DataFrame(results['malicious_ips'])
        st.dataframe(malicious_df, use_container_width=True)
    
    if results.get('suspicious_ips'):
        st.subheader("⚠️ Suspicious IPs Found")
        suspicious_df = pd.DataFrame(results['suspicious_ips'])
        st.dataframe(suspicious_df, use_container_width=True)
    
    if results.get('errors'):
        st.subheader("❌ Errors Encountered")
        for error in results['errors']:
            st.error(error)
    
    if 'pdf_report_path' in st.session_state:
        with open(st.session_state.pdf_report_path, 'rb') as pdf_file:
            st.download_button(
                label="📄 Download PDF Report",
                data=pdf_file.read(),
                file_name=Path(st.session_state.pdf_report_path).name,
                mime="application/pdf"
            )

def display_single_indicator_results(results):
    """Display single indicator analysis results"""
    st.header(f"🔍 {results['type']} Analysis: {results['indicator']}")
    
    if results.get('vt_result'):
        st.subheader("📊 VirusTotal Results")
        vt_data = results['vt_result']
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Malicious", vt_data.get('malicious', 0))
        with col2:
            st.metric("Suspicious", vt_data.get('suspicious', 0))
        with col3:
            st.metric("Harmless", vt_data.get('harmless', 0))
        with col4:
            st.metric("Undetected", vt_data.get('undetected', 0))
    
    if results.get('abuse_result'):
        st.subheader("📊 AbuseIPDB Results")
        abuse_data = results['abuse_result']
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Abuse Score", f"{abuse_data.get('abuseConfidenceScore', 0)}%")
        with col2:
            st.metric("Total Reports", abuse_data.get('totalReports', 0))
        with col3:
            st.metric("Last Reported", abuse_data.get('lastReportedAt', 'Never'))

def display_collection_results(results):
    """Display log collection results"""
    st.header("📋 Log Collection Results")
    
    summary = results.get('summary', {})
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Successful Collections", summary.get('successful_collections', 0))
    with col2:
        st.metric("Total Events", summary.get('total_events', 0))
    with col3:
        st.metric("Failed Collections", summary.get('failed_collections', 0))
    
    if 'ip_analysis' in results:
        ip_results = results['ip_analysis']
        if ip_results.get('status') != 'error':
            st.subheader("🔍 IP Analysis Results")
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("IPs Analyzed", ip_results.get('total_ips_analyzed', 0))
            with col2:
                st.metric("Malicious IPs", ip_results.get('malicious_ips_found', 0))
            with col3:
                st.metric("Suspicious IPs", ip_results.get('suspicious_ips_found', 0))
            
            if 'analysis_results' in ip_results:
                analysis_data = ip_results['analysis_results']
                
                if analysis_data.get('malicious_ips'):
                    st.subheader("🚨 Malicious IPs Found")
                    malicious_df = pd.DataFrame(analysis_data['malicious_ips'])
                    st.dataframe(malicious_df, use_container_width=True)
                
                if analysis_data.get('suspicious_ips'):
                    st.subheader("⚠️ Suspicious IPs Found")
                    suspicious_df = pd.DataFrame(analysis_data['suspicious_ips'])
                    st.dataframe(suspicious_df, use_container_width=True)

def display_welcome_screen():
    """Display welcome screen with instructions"""
    st.header("Welcome to Sysmon AI")
    st.write("Select an analysis mode from the sidebar to get started.")
    
    st.subheader("Available Features:")
    st.write("🔍 **Threat Intelligence** - Analyze IPs, domains, and file hashes with VirusTotal and AbuseIPDB")
    st.write("📄 **EVTX Analysis** - Deep analysis of Windows event logs with AI-powered insights")
    st.write("📋 **Log Collection** - Collect and analyze system logs with automated threat intelligence")

def display_evtx_results(results):
    """Display EVTX analysis results"""
    # Overview metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Events", results.get('total_events', 0))
    with col2:
        st.metric("Suspicious Events", len(results.get('suspicious_events', [])))
    with col3:
        threat_types = len(results.get('threat_categories', {}))
        st.metric("Threat Categories", threat_types)
    with col4:
        risk_score = min(100, len(results.get('suspicious_events', [])) * 5)
        st.metric("Risk Score", f"{risk_score}/100")
    
    # Threat Categories Chart
    if results.get('threat_categories'):
        st.subheader("🎯 Threat Categories")
        
        threat_df = pd.DataFrame(
            list(results['threat_categories'].items()),
            columns=['Category', 'Count']
        )
        threat_df['Category'] = threat_df['Category'].str.replace('_', ' ').str.title()
        
        fig = px.bar(threat_df, x='Category', y='Count', 
                    title="Detected Threats by Category",
                    color='Count', color_continuous_scale='Reds')
        st.plotly_chart(fig, use_container_width=True)
    
    # Display suspicious events if available
    if results.get('suspicious_events'):
        st.subheader("🔍 Suspicious Events")
        
        events_data = []
        for i, event in enumerate(results['suspicious_events'], 1):
            events_data.append({
                '#': i,
                'Event ID': event.get('event_id', 'Unknown'),
                'Timestamp': event.get('timestamp', 'Unknown'),
                'Indicators': ', '.join(event.get('indicators', [])),
                'Category': event.get('category', 'Unknown')
            })
        
        if events_data:
            events_df = pd.DataFrame(events_data)
            st.dataframe(events_df, use_container_width=True)
    
    # AI Analysis
    if results.get('ai_analysis'):
        st.subheader("🤖 AI Analysis")
        st.text_area("Analysis Results", results['ai_analysis'], height=200)

def main():
    """Main entry point for Streamlit application"""
    st.set_page_config(
        page_title="Sysmon AI",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    st.title("🛡️ Sysmon AI - Advanced Threat Hunting Platform")
    st.markdown("AI-powered analysis tool with threat intelligence integration and comprehensive log analysis")
    
    # Setup sidebar navigation and options
    with st.sidebar:
        st.header("🔧 Analysis Mode")
        analysis_mode = st.selectbox(
            "Choose Analysis Mode",
            ["EVTX Analysis", "Threat Intelligence", "Log Collection"],
            help="Select the type of analysis to perform"
        )
        
        if analysis_mode == "EVTX Analysis":
            show_evtx_analysis_sidebar()
        elif analysis_mode == "Threat Intelligence":
            show_threat_intel_sidebar()
        elif analysis_mode == "Log Collection":
            show_log_collection_sidebar()
    
    # Display main content
    display_main_content()


if __name__ == "__main__":
    main()
