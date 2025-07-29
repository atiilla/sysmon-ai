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

# Add the modules directory to the path
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'modules'))
from groq_analyzer import SysmonAnalyzer

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

# Add the modules directory to the path
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'modules'))
from groq_analyzer import SysmonAnalyzer

st.set_page_config(
    page_title="Sysmon AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.title("🛡️ Sysmon AI - Event Log Analysis")
st.markdown("AI-powered analysis tool for Windows Sysmon event logs")

# Sidebar
with st.sidebar:
    st.header("Configuration")
    uploaded_file = st.file_uploader("Upload EVTX File", type=['evtx'])
    simple_analysis = st.checkbox("Simple Analysis", value=False, help="Uncheck for detailed analysis (default)")
    groq_api_key = st.text_input("Groq API Key (Optional)", type="password", help="For AI-powered analysis")
    
    if st.button("Analyze", type="primary", disabled=not uploaded_file):
        if uploaded_file:
            # Save uploaded file temporarily
            temp_path = Path("temp_upload.evtx")
            with open(temp_path, "wb") as f:
                f.write(uploaded_file.getbuffer())
            
            # Perform analysis
            with st.spinner("Analyzing EVTX file..."):
                analyzer = SysmonAnalyzer(groq_api_key=groq_api_key if groq_api_key else None)
                detailed = not simple_analysis
                results = analyzer.analyze_evtx(temp_path, detailed=detailed)
                st.session_state.results = results
            
            # Clean up temp file
            temp_path.unlink(missing_ok=True)
            st.success("Analysis completed!")

# Main content
if 'results' in st.session_state:
    results = st.session_state.results
    
    # Overview metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Events", results['total_events'])
    with col2:
        st.metric("Suspicious Events", len(results['suspicious_events']))
    with col3:
        threat_types = len(results['threat_categories'])
        st.metric("Threat Categories", threat_types)
    with col4:
        risk_score = min(100, len(results['suspicious_events']) * 5)
        st.metric("Risk Score", f"{risk_score}/100")
    
    # Threat Categories Chart
    if results['threat_categories']:
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
    
    # Timeline Analysis
    if results['suspicious_events']:
        st.subheader("📊 Timeline Analysis")
        
        # Create timeline data from events
        timeline_data = []
        for event in results['suspicious_events']:
            timestamp = event.get('timestamp', 'Unknown')
            if timestamp != 'Unknown':
                timeline_data.append({
                    'timestamp': timestamp,
                    'event_id': event.get('event_id', 'Unknown'),
                    'indicators': ', '.join(event.get('indicators', []))
                })
        
        if timeline_data:
            timeline_df = pd.DataFrame(timeline_data)
            timeline_df['timestamp'] = pd.to_datetime(timeline_df['timestamp'], errors='coerce')
            timeline_df = timeline_df.dropna(subset=['timestamp'])
            
            if not timeline_df.empty:
                fig = px.scatter(timeline_df, x='timestamp', y='event_id',
                               hover_data=['indicators'],
                               title="Suspicious Events Timeline")
                st.plotly_chart(fig, use_container_width=True)
    
    # AI Analysis
    if results.get('ai_analysis'):
        st.subheader("🤖 AI Analysis")
        st.text_area("Analysis Results", results['ai_analysis'], height=200)
    
    # Threat Intelligence Section
    st.subheader("🎯 Threat Intelligence Analysis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**MITRE ATT&CK Techniques Detected:**")
        mitre_mapping = {
            'process_injection': 'T1055 - Process Injection',
            'powershell_obfuscation': 'T1059.001 - PowerShell',
            'privilege_escalation': 'T1068 - Exploitation for Privilege Escalation',
            'suspicious_network': 'T1071 - Application Layer Protocol',
            'file_modification': 'T1070 - Indicator Removal on Host',
            'registry_modification': 'T1112 - Modify Registry',
            'service_creation': 'T1543.003 - Windows Service'
        }
        
        detected_techniques = []
        for category in results.get('threat_categories', {}).keys():
            if category in mitre_mapping:
                detected_techniques.append(mitre_mapping[category])
        
        if detected_techniques:
            for technique in detected_techniques:
                st.markdown(f"- {technique}")
        else:
            st.info("No specific MITRE ATT&CK techniques identified")
    
    with col2:
        st.markdown("**Risk Assessment:**")
        risk_score = min(100, len(results['suspicious_events']) * 5)
        
        if risk_score > 70:
            st.error(f"🔴 HIGH RISK ({risk_score}/100)")
            st.markdown("**Immediate action required**")
        elif risk_score > 30:
            st.warning(f"🟡 MEDIUM RISK ({risk_score}/100)")
            st.markdown("**Enhanced monitoring recommended**")
        else:
            st.success(f"🟢 LOW RISK ({risk_score}/100)")
            st.markdown("**Routine monitoring sufficient**")
        
        # IOCs Summary
        iocs = extract_iocs_from_events(results.get('suspicious_events', []))
        st.markdown("**Indicators of Compromise:**")
        st.metric("Suspicious IPs", len(iocs['ip_addresses']))
        st.metric("Suspicious Files", len(iocs['file_paths']))
        st.metric("Suspicious Processes", len(iocs['process_names']))
    
    # Detailed Events Table
    if results['suspicious_events']:
        st.subheader("🔍 Suspicious Events Details")
        
        events_data = []
        for i, event in enumerate(results['suspicious_events'], 1):
            events_data.append({
                '#': i,
                'Event ID': event.get('event_id', 'Unknown'),
                'Timestamp': event.get('timestamp', 'Unknown'),
                'Threat Indicators': ', '.join(event.get('indicators', [])),
                'Raw Data Preview': event.get('raw_xml', '')[:100] + '...' if event.get('raw_xml') else ''
            })
        
        events_df = pd.DataFrame(events_data)
        st.dataframe(events_df, use_container_width=True)
        
        # Show detailed IOCs if available
        if results['suspicious_events']:
            st.subheader("🚨 Indicators of Compromise (IOCs)")
            
            iocs = extract_iocs_from_events(results['suspicious_events'])
            
            ioc_tabs = st.tabs(["IP Addresses", "File Paths", "Process Names", "Network IOCs"])
            
            with ioc_tabs[0]:
                if iocs['ip_addresses']:
                    ip_df = pd.DataFrame(iocs['ip_addresses'], columns=['IP Address'])
                    ip_df['Type'] = 'Suspicious Network Connection'
                    ip_df['Risk Level'] = 'Medium'
                    st.dataframe(ip_df, use_container_width=True)
                else:
                    st.info("No suspicious IP addresses detected")
            
            with ioc_tabs[1]:
                if iocs['file_paths']:
                    file_df = pd.DataFrame(iocs['file_paths'], columns=['File Path'])
                    file_df['Type'] = 'Suspicious File Activity'
                    file_df['Risk Level'] = 'High'
                    st.dataframe(file_df, use_container_width=True)
                else:
                    st.info("No suspicious file paths detected")
            
            with ioc_tabs[2]:
                if iocs['process_names']:
                    proc_df = pd.DataFrame(iocs['process_names'], columns=['Process Name'])
                    proc_df['Type'] = 'Suspicious Process Execution'
                    proc_df['Risk Level'] = 'High'
                    st.dataframe(proc_df, use_container_width=True)
                else:
                    st.info("No suspicious processes detected")
            
            with ioc_tabs[3]:
                network_summary = []
                for event in results['suspicious_events']:
                    if 'network_info' in event and event['network_info']:
                        network_summary.append({
                            'Source IP': event['network_info'].get('source_ip', 'Unknown'),
                            'Destination IP': event['network_info'].get('destination_ip', 'Unknown'),
                            'Port': event['network_info'].get('destination_port', 'Unknown'),
                            'Protocol': event['network_info'].get('protocol', 'Unknown'),
                            'Timestamp': event.get('timestamp', 'Unknown')
                        })
                
                if network_summary:
                    network_df = pd.DataFrame(network_summary)
                    st.dataframe(network_df, use_container_width=True)
                else:
                    st.info("No network IOCs detected")
    
    # Comprehensive Threat Hunter Report
    st.subheader("🎯 Comprehensive Threat Hunter Report")
    
    with st.expander("📋 Full Threat Hunting Analysis", expanded=False):
        # Generate comprehensive threat hunter report
        report_content = generate_threat_hunter_report(results)
        st.markdown(report_content)
    
    # Export Options
    st.subheader("📥 Export Results")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("Download JSON Report"):
            json_str = json.dumps(results, indent=2)
            st.download_button(
                label="Download JSON",
                data=json_str,
                file_name="sysmon_analysis.json",
                mime="application/json"
            )
    
    with col2:
        if st.button("Download Threat Hunter Report"):
            # Generate comprehensive threat hunter report
            threat_report = generate_threat_hunter_report(results, format_type="download")
            st.download_button(
                label="Download Threat Report",
                data=threat_report,
                file_name=f"threat_hunting_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                mime="text/markdown"
            )
    
    with col3:
        if st.button("Download Executive Summary"):
            # Generate executive summary
            exec_summary = generate_executive_summary(results)
            st.download_button(
                label="Download Executive Summary",
                data=exec_summary,
                file_name=f"executive_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain"
            )

else:
    st.info("👆 Upload an EVTX file in the sidebar to begin analysis")
    
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
