#!/usr/bin/env python3
"""
Sysmon AI - Advanced Threat Hunting Platform
Comprehensive multi-platform log analysis and threat hunting tool for cybersecurity professionals
"""

import argparse
import json
import logging
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from modules.groq_analyzer import SysmonAnalyzer
from modules.log_collector import LogCollector
from modules.threat_hunter import ThreatHuntingAnalyzer
from modules.report_generator import ThreatReportGenerator

def launch_streamlit_app(port: int = 8501):
    """Launch the Streamlit web interface"""
    try:
        # Check if streamlit_app.py exists
        app_path = Path(__file__).parent / "modules/streamlit_app.py"
        if not app_path.exists():
            print("Creating Streamlit app...")
            create_streamlit_app()
        
        print(f"Launching Streamlit web interface on port {port}...")
        print(f"Open your browser to: http://localhost:{port}")
        
        # Launch Streamlit
        subprocess.run([
            sys.executable, "-m", "streamlit", "run", 
            str(app_path), "--server.port", str(port)
        ])
    except Exception as e:
        print(f"Error launching Streamlit: {e}")
        print("Make sure Streamlit is installed: pip install streamlit")

def create_streamlit_app():
    """Create the Streamlit web application file"""
    streamlit_code = '''import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
import json
import io
from groq_analyzer import SysmonAnalyzer

st.set_page_config(
    page_title="Sysmon AI",
    page_icon="�",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.title("� Sysmon AI - Event Log Analysis")
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
                report += f"- {category.replace('_', ' ').title()}: {count}\\n"
            
            if results.get('ai_analysis'):
                report += f"\\nAI Analysis:\\n{results['ai_analysis']}"
            
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
'''
    
    with open("streamlit_app.py", "w", encoding='utf-8') as f:
        f.write(streamlit_code)

def setup_logging():
    """Configure logging for the application"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('sysmon_ai.log'),
            logging.StreamHandler()
        ]
    )

def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(
        description='Sysmon AI - Advanced Threat Hunting Platform',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic EVTX analysis
  python app.py sample.evtx --output results.json
  
  # Comprehensive threat hunting with log collection
  python app.py --hunt --collect-logs --time-range 48 --output-dir ./hunt_results
  
  # Multi-platform analysis with AI insights
  python app.py --hunt --groq-key YOUR_KEY --report-type full
  
  # Web interface for interactive analysis
  python app.py --web --port 8501
        """
    )
    
    # File input options
    parser.add_argument('evtx_file', nargs='?', help='Path to EVTX file to analyze')
    parser.add_argument('--output', '-o', help='Output file for analysis results')
    parser.add_argument('--output-dir', help='Output directory for comprehensive analysis')
    
    # Analysis modes
    parser.add_argument('--hunt', action='store_true', 
                       help='Enable advanced threat hunting mode')
    parser.add_argument('--collect-logs', action='store_true',
                       help='Collect system logs before analysis')
    parser.add_argument('--simple', '-s', action='store_true', 
                       help='Generate simple analysis report (default is detailed)')
    
    # Web interface
    parser.add_argument('--web', '-w', action='store_true', 
                       help='Launch Streamlit web interface')
    parser.add_argument('--port', '-p', type=int, default=8501, 
                       help='Port for web interface (default: 8501)')
    
    # Configuration options
    parser.add_argument('--verbose', '-v', action='store_true', 
                       help='Enable verbose logging')
    parser.add_argument('--groq-key', help='Groq API key for AI analysis')
    parser.add_argument('--time-range', type=int, default=24,
                       help='Time range in hours for log collection (default: 24)')
    
    # Report generation
    parser.add_argument('--report-type', choices=['executive', 'technical', 'full'], 
                       default='full', help='Type of report to generate')
    parser.add_argument('--report-format', choices=['json', 'html', 'markdown'], 
                       default='json', help='Report output format')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    setup_logging()
    logger = logging.getLogger(__name__)
    
    # Launch web interface if requested
    if args.web:
        launch_streamlit_app(args.port)
        return 0
    
    # Comprehensive threat hunting mode
    if args.hunt:
        return run_threat_hunting_mode(args, logger)
    
    # Traditional EVTX analysis mode
    if not args.evtx_file:
        parser.error("EVTX file is required for CLI analysis. Use --web for web interface or --hunt for comprehensive analysis.")
    
    # Validate input file
    evtx_path = Path(args.evtx_file)
    if not evtx_path.exists():
        logger.error(f"EVTX file not found: {evtx_path}")
        return 1
    
    logger.info(f"Starting analysis of {evtx_path}")
    
    try:
        # Initialize analyzer with Groq API key
        analyzer = SysmonAnalyzer(groq_api_key=args.groq_key)
        
        # Perform analysis (detailed by default, simple if requested)
        detailed = not args.simple
        results = analyzer.analyze_evtx(evtx_path, detailed=detailed)
        
        # Output results
        if args.output:
            analyzer.save_results(results, args.output, detailed=detailed)
            logger.info(f"Results saved to {args.output}")
        else:
            analyzer.print_results(results, detailed=detailed)
        
        logger.info("Analysis completed successfully")
        return 0
        
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")
        return 1


def run_threat_hunting_mode(args, logger):
    """Run comprehensive threat hunting analysis"""
    logger.info("🔍 Starting Advanced Threat Hunting Mode")
    
    # Set up output directory
    output_dir = Path(args.output_dir) if args.output_dir else Path("threat_hunt_results")
    output_dir.mkdir(exist_ok=True)
    
    logger.info(f"Output directory: {output_dir}")
    
    try:
        # Step 1: Collect logs if requested
        log_collection_results = {}
        if args.collect_logs:
            logger.info("📊 Phase 1: Collecting system logs...")
            collector = LogCollector(str(output_dir / "collected_logs"))
            log_collection_results = collector.collect_all_logs(
                time_range_hours=args.time_range,
                include_network=True
            )
            
            # Create archive of collected logs
            archive_path = collector.create_collection_archive(log_collection_results)
            logger.info(f"Log collection archive created: {archive_path}")
        
        # Step 2: Perform threat hunting analysis
        logger.info("🎯 Phase 2: Advanced threat hunting analysis...")
        threat_hunter = ThreatHuntingAnalyzer(groq_api_key=args.groq_key)
        
        if log_collection_results:
            # Analyze collected logs
            analysis_results = threat_hunter.analyze_collected_logs(log_collection_results)
        elif args.evtx_file:
            # Analyze single EVTX file with advanced features
            evtx_path = Path(args.evtx_file)
            if not evtx_path.exists():
                logger.error(f"EVTX file not found: {evtx_path}")
                return 1
            
            # Create minimal log collection structure for single file
            log_collection_results = {
                'system_info': {'platform': 'Windows', 'hostname': 'localhost'},
                'collected_logs': {
                    'sysmon': {
                        'output_file': str(evtx_path),
                        'collection_status': 'success'
                    }
                },
                'summary': {'total_events': 0}
            }
            
            analysis_results = threat_hunter.analyze_collected_logs(log_collection_results)
        else:
            logger.error("Either --collect-logs or an EVTX file must be specified for threat hunting mode")
            return 1
        
        # Step 3: Generate comprehensive reports
        logger.info("📋 Phase 3: Generating threat hunting reports...")
        report_generator = ThreatReportGenerator(str(output_dir / "reports"))
        
        report_files = report_generator.generate_comprehensive_report(
            analysis_results=analysis_results,
            log_collection_results=log_collection_results,
            report_type=args.report_type,
            classification="CONFIDENTIAL"
        )
        
        # Step 4: Save analysis results
        analysis_file = output_dir / f"threat_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(analysis_file, 'w', encoding='utf-8') as f:
            json.dump(analysis_results, f, indent=2, default=str)
        
        # Display summary
        logger.info("🎉 Threat hunting analysis completed!")
        logger.info(f"📁 Results directory: {output_dir}")
        logger.info("📊 Generated files:")
        
        for file_type, file_path in report_files.items():
            logger.info(f"  - {file_type}: {file_path}")
        
        logger.info(f"  - Full analysis: {analysis_file}")
        
        # Print executive summary
        if analysis_results.get('executive_summary'):
            summary = analysis_results['executive_summary']
            print(f"\n🎯 EXECUTIVE SUMMARY")
            print(f"{'='*50}")
            print(f"Overall Risk Level: {summary.get('overall_risk_level', 'UNKNOWN')}")
            print(f"Total Threats Detected: {summary.get('total_threats_detected', 0)}")
            print(f"Critical Findings: {summary.get('critical_findings', 0)}")
            print(f"High Severity Findings: {summary.get('high_severity_findings', 0)}")
            
            if summary.get('key_findings'):
                print(f"\nKey Findings:")
                for finding in summary['key_findings']:
                    print(f"  • {finding}")
            
            if summary.get('immediate_actions_required'):
                print(f"\nImmediate Actions Required:")
                for action in summary['immediate_actions_required']:
                    print(f"  • {action}")
        
        return 0
        
    except Exception as e:
        logger.error(f"Threat hunting analysis failed: {str(e)}")
        import traceback
        logger.debug(traceback.format_exc())
        return 1

if __name__ == "__main__":
    exit(main())