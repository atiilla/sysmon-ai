import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
import json
import io
import sys
import os

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
    
    # Export Options
    st.subheader("📥 Export Results")
    col1, col2 = st.columns(2)
    
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
        if st.button("Download Text Report"):
            # Generate text report
            report = f"""Sysmon AI Analysis Report
========================

File: {results['file_path']}
Analysis Time: {results['analysis_timestamp']}
Total Events: {results['total_events']}
Suspicious Events: {len(results['suspicious_events'])}

Threat Categories:
"""
            for category, count in results['threat_categories'].items():
                report += f"- {category.replace('_', ' ').title()}: {count}\n"
            
            if results.get('ai_analysis'):
                report += f"\nAI Analysis:\n{results['ai_analysis']}"
            
            st.download_button(
                label="Download Text",
                data=report,
                file_name="sysmon_analysis.txt",
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
