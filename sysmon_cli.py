#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sysmon AI - Command Line Interface
A user-friendly CLI tool for Sysmon log collection, analysis, and reporting
"""

import argparse
import sys
import os
import subprocess
import logging
from pathlib import Path
from datetime import datetime

# Add the current directory to Python path to ensure modules can be imported
sys.path.insert(0, str(Path(__file__).parent))

# Import configuration
from modules.config import config
from modules.log_collector import LogCollector
from modules.threat_hunter import ThreatHuntingAnalyzer
from modules.groq_analyzer import SysmonAnalyzer
from modules.report_generator import ThreatReportGenerator


class SysmonCLI:
    """Command-line interface for Sysmon AI tools"""
    
    def __init__(self):
        """Initialize the CLI tool"""
        self.log_collector = LogCollector()
        self.threat_hunter = ThreatHuntingAnalyzer(groq_api_key=config.GROQ_API_KEY)
        self.analyzer = SysmonAnalyzer(groq_api_key=config.GROQ_API_KEY)
        self.report_generator = ThreatReportGenerator()
        self.logger = config.logger
    
    def parse_args(self):
        """Parse command-line arguments"""
        parser = argparse.ArgumentParser(
            description="Sysmon AI - Advanced Threat Hunting Platform",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Basic EVTX analysis
  python sysmon_cli.py analyze sample.evtx --output results.json
  
  # Comprehensive threat hunting with log collection
  python sysmon_cli.py hunt --collect-logs --time-range 48
  
  # Analyze logs with AI insights
  python sysmon_cli.py analyze sample.evtx --ai
  
  # Web interface for interactive analysis
  python sysmon_cli.py web --port 8501
            """
        )
        
        subparsers = parser.add_subparsers(dest="command", help="Command to execute")
        
        # Analyze command
        analyze_parser = subparsers.add_parser("analyze", help="Analyze existing EVTX file")
        analyze_parser.add_argument("evtx_file", help="Path to EVTX file to analyze")
        analyze_parser.add_argument("--output", "-o", help="Output file for analysis results")
        analyze_parser.add_argument("--format", choices=config.REPORT_FORMATS, default="json", 
                                  help="Output format (default: json)")
        analyze_parser.add_argument("--ai", action="store_true", help="Use AI-powered analysis")
        analyze_parser.add_argument("--simple", "-s", action="store_true", 
                                  help="Generate simple analysis report")
        
        # Collect command
        collect_parser = subparsers.add_parser("collect", help="Collect Sysmon logs")
        collect_parser.add_argument("--time-range", "-t", type=int, default=24,
                                  help="Time range in hours for log collection (default: 24)")
        collect_parser.add_argument("--output", "-o", help="Output directory for collected logs")
        collect_parser.add_argument("--no-analyze", action="store_true", 
                                  help="Skip analysis after collection")
        collect_parser.add_argument("--analyze-ips", action="store_true",
                                  help="Extract and analyze IPs with threat intelligence")
        collect_parser.add_argument("--sysmon-only", action="store_true",
                                  help="Collect only Sysmon logs (faster)")
        
        # Threat Intel command
        intel_parser = subparsers.add_parser("intel", help="Threat intelligence analysis")
        intel_parser.add_argument("--ip-file", help="File containing IPs to analyze (one per line)")
        intel_parser.add_argument("--extract-ips", action="store_true",
                                help="Extract IPs from existing Sysmon logs")
        intel_parser.add_argument("--generate-pdf", action="store_true",
                                help="Generate PDF report from existing CSV results")
        intel_parser.add_argument("--single-ip", help="Analyze a single IP address")
        intel_parser.add_argument("--single-domain", help="Analyze a single domain")
        intel_parser.add_argument("--single-hash", help="Analyze a single file hash")
        
        # Hunt command
        hunt_parser = subparsers.add_parser("hunt", help="Advanced threat hunting")
        hunt_parser.add_argument("--evtx-file", help="Path to existing EVTX file (optional)")
        hunt_parser.add_argument("--collect-logs", action="store_true", 
                               help="Collect logs before hunting")
        hunt_parser.add_argument("--time-range", "-t", type=int, default=24,
                               help="Time range in hours for log collection (default: 24)")
        hunt_parser.add_argument("--report-type", choices=["executive", "technical", "full"], 
                               default="full", help="Type of report to generate")
        hunt_parser.add_argument("--format", choices=config.REPORT_FORMATS,
                               default="markdown", help="Report output format")
        hunt_parser.add_argument("--no-ai", action="store_true", 
                               help="Skip AI-powered analysis")
        
        # Web interface command
        web_parser = subparsers.add_parser("web", help="Launch web interface")
        web_parser.add_argument("--port", "-p", type=int, default=config.WEB_PORT, 
                              help=f"Port for web interface (default: {config.WEB_PORT})")
        web_parser.add_argument("--host", default=config.WEB_HOST,
                              help=f"Host for web interface (default: {config.WEB_HOST})")
        
        # Setup command
        setup_parser = subparsers.add_parser("setup", help="Setup Sysmon and configure environment")
        setup_parser.add_argument("--install-sysmon", action="store_true",
                                help="Install Sysmon with the default configuration")
        setup_parser.add_argument("--sysmon-config", default=str(config.SYSMON_CFG),
                                help="Path to Sysmon configuration XML file")
        setup_parser.add_argument("--uninstall", action="store_true",
                                help="Uninstall Sysmon")
        
        args = parser.parse_args()
        
        if not args.command:
            parser.print_help()
            sys.exit(1)
            
        return args
    
    def analyze_evtx(self, evtx_file, output=None, format="json", use_ai=False, simple=False):
        """Analyze an EVTX file"""
        self.logger.info(f"Analyzing EVTX file: {evtx_file}")
        
        try:
            # Validate file exists
            evtx_path = Path(evtx_file)
            if not evtx_path.exists():
                self.logger.error(f"EVTX file not found: {evtx_file}")
                return False
                
            # Perform analysis
            results = self.analyzer.analyze_evtx(
                evtx_path, 
                detailed=(not simple),
                use_ai=use_ai
            )
            
            # Generate output file if specified
            if output:
                output_path = Path(output)
                if format == "json":
                    with open(output_path, "w") as f:
                        import json
                        json.dump(results, f, indent=2, default=str)
                else:
                    # Use report generator for other formats
                    report = self.report_generator.generate_comprehensive_report(
                        {"analysis_results": results},
                        {"log_collection_results": {"file_path": str(evtx_path)}},
                        report_type="technical"
                    )
                    
                    report_path = config.get_report_path("analysis", format)
                    with open(report_path, "w", encoding="utf-8") as f:
                        f.write(report)
                    output_path = report_path
                
                self.logger.info(f"Analysis results saved to: {output_path}")
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error analyzing EVTX file: {e}")
            import traceback
            self.logger.debug(traceback.format_exc())
            return False
    
    def collect_logs(self, time_range=24, output_dir=None, analyze=True, 
                    analyze_ips=False, sysmon_only=False):
        """Collect Sysmon logs with optional IP analysis"""
        self.logger.info(f"Collecting logs for the past {time_range} hours")
        
        try:
            # Set output directory if specified
            if output_dir:
                original_logs_dir = config.LOGS_DIR
                config.LOGS_DIR = Path(output_dir)
                config.LOGS_DIR.mkdir(exist_ok=True)
            
            # Choose collection method based on options
            if sysmon_only and analyze_ips:
                # Use the enhanced Sysmon collection with IP analysis
                results = self.log_collector.collect_sysmon_with_ip_analysis(
                    time_range_hours=time_range,
                    analyze_ips=True
                )
            elif sysmon_only:
                # Collect only Sysmon logs
                logs = self.log_collector.collect_sysmon_logs(time_range=time_range)
                results = {"sysmon_logs": logs}
            else:
                # Collect all logs
                results = self.log_collector.collect_all_logs(time_range_hours=time_range)
            
            if results:
                self.logger.info("Log collection completed successfully")
                
                # Display IP analysis results if available
                if 'ip_analysis' in results:
                    ip_results = results['ip_analysis']
                    if ip_results.get('status') != 'error':
                        self.logger.info(f"IP Analysis Results:")
                        self.logger.info(f"  - Total IPs analyzed: {ip_results.get('total_ips_analyzed', 0)}")
                        self.logger.info(f"  - Malicious IPs found: {ip_results.get('malicious_ips_found', 0)}")
                        self.logger.info(f"  - Suspicious IPs found: {ip_results.get('suspicious_ips_found', 0)}")
                        if ip_results.get('csv_results'):
                            self.logger.info(f"  - Results saved to: {ip_results['csv_results']}")
                        if ip_results.get('pdf_report'):
                            self.logger.info(f"  - PDF report: {ip_results['pdf_report']}")
                    else:
                        self.logger.error(f"IP analysis error: {ip_results.get('error', 'Unknown error')}")
                
                # Display collection summary
                if 'summary' in results:
                    summary = results['summary']
                    self.logger.info(f"Collection Summary:")
                    self.logger.info(f"  - Successful collections: {summary.get('successful_collections', 0)}")
                    self.logger.info(f"  - Total events: {summary.get('total_events', 0)}")
                    self.logger.info(f"  - Failed collections: {summary.get('failed_collections', 0)}")
                
                # Analyze logs if requested and we have EVTX files
                if analyze and not sysmon_only:
                    # Try to find the most recent EVTX file
                    evtx_files = list(config.LOGS_DIR.glob("*.evtx"))
                    if evtx_files:
                        latest_evtx = max(evtx_files, key=lambda x: x.stat().st_mtime)
                        self.analyze_evtx(latest_evtx)
                
                return True
            else:
                self.logger.warning("No logs collected")
                return False
                
        except Exception as e:
            self.logger.error(f"Error collecting logs: {e}")
            import traceback
            self.logger.debug(traceback.format_exc())
            return False
    
    def threat_intel_analysis(self, ip_file=None, extract_ips=False, generate_pdf=False,
                            single_ip=None, single_domain=None, single_hash=None):
        """Perform threat intelligence analysis"""
        from modules.threat_intelligence import ThreatIntelligenceCollector
        
        try:
            # Initialize threat intelligence collector
            threat_intel = ThreatIntelligenceCollector(
                virustotal_api_key=config.VIRUSTOTAL_API_KEY,
                abuseipdb_api_key=config.ABUSEIPDB_API_KEY,
                output_dir=str(config.OUTPUT_DIR)
            )
            
            # Check if we have any API keys
            if not config.has_threat_intel_keys():
                self.logger.error("No threat intelligence API keys configured")
                self.logger.info("Please set VIRUSTOTAL_API_KEY and/or ABUSEIPDB_API_KEY environment variables")
                return False
            
            if generate_pdf:
                # Generate PDF from existing CSV results
                pdf_report = threat_intel.generate_pdf_report()
                if pdf_report:
                    self.logger.info(f"PDF report generated: {pdf_report}")
                    return True
                else:
                    self.logger.error("Failed to generate PDF report")
                    return False
            
            if extract_ips:
                # Extract IPs from Sysmon logs
                ips_list, ip_file_path = threat_intel.extract_ips_from_sysmon_logs()
                if ips_list:
                    self.logger.info(f"Extracted {len(ips_list)} IPs from Sysmon logs")
                    # Analyze the extracted IPs
                    results = threat_intel.analyze_ip_list(ips_list)
                    threat_intel.generate_pdf_report()
                    return True
                else:
                    self.logger.warning("No IPs extracted from Sysmon logs")
                    return False
            
            if single_ip:
                # Analyze a single IP
                self.logger.info(f"Analyzing single IP: {single_ip}")
                vt_result = threat_intel.query_virustotal(single_ip)
                abuse_result = threat_intel.query_abuseipdb(single_ip) if threat_intel.is_valid_ip(single_ip) else None
                threat_intel.save_to_csv(single_ip, vt_result, abuse_result)
                return True
            
            if single_domain:
                # Analyze a single domain
                self.logger.info(f"Analyzing single domain: {single_domain}")
                vt_result = threat_intel.query_virustotal(single_domain)
                threat_intel.save_to_csv(single_domain, vt_result, None)
                return True
            
            if single_hash:
                # Analyze a single file hash
                self.logger.info(f"Analyzing single hash: {single_hash}")
                vt_result = threat_intel.query_virustotal(single_hash)
                threat_intel.save_to_csv(single_hash, vt_result, None)
                return True
            
            if ip_file:
                # Analyze IPs from file
                ip_file_path = Path(ip_file)
                if not ip_file_path.exists():
                    self.logger.error(f"IP file not found: {ip_file}")
                    return False
                
                # Read IPs from file
                with open(ip_file_path, 'r') as f:
                    ips_list = [line.strip() for line in f if line.strip()]
                
                if ips_list:
                    self.logger.info(f"Analyzing {len(ips_list)} IPs from file")
                    results = threat_intel.analyze_ip_list(ips_list)
                    threat_intel.generate_pdf_report()
                    return True
                else:
                    self.logger.warning("No valid IPs found in file")
                    return False
            
            self.logger.error("No analysis option specified")
            return False
            
        except Exception as e:
            self.logger.error(f"Error during threat intelligence analysis: {e}")
            import traceback
            self.logger.debug(traceback.format_exc())
            return False
    
    def hunt_threats(self, evtx_file=None, collect_logs=False, time_range=24, 
                    report_type="full", format="markdown", use_ai=True):
        """Perform advanced threat hunting"""
        self.logger.info("Starting advanced threat hunting")
        
        try:
            # Collect logs if requested or use provided EVTX file
            if collect_logs:
                self.collect_logs(time_range=time_range, analyze=False)
                evtx_path = sorted(config.LOGS_DIR.glob("*.evtx"))[-1]  # Get latest EVTX file
            elif evtx_file:
                evtx_path = Path(evtx_file)
                if not evtx_path.exists():
                    self.logger.error(f"EVTX file not found: {evtx_file}")
                    return False
            else:
                self.logger.error("No EVTX file provided and log collection not requested")
                return False
            
            # Perform threat hunting analysis
            self.logger.info(f"Hunting threats in: {evtx_path}")
            hunting_results = self.threat_hunter.analyze_evtx(
                evtx_path,
                use_ai=use_ai
            )
            
            # Generate report
            report_path = config.get_report_path("threat_hunt", format)
            
            self.logger.info(f"Generating {report_type} report in {format} format")
            report = self.threat_hunter.generate_threat_report(
                hunting_results,
                output_format=format
            )
            
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(report)
            
            self.logger.info(f"Threat hunting report saved to: {report_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error during threat hunting: {e}")
            import traceback
            self.logger.debug(traceback.format_exc())
            return False
    
    def launch_web_interface(self, port=None, host=None):
        """Launch the Streamlit web interface"""
        try:
            port = port or config.WEB_PORT
            host = host or config.WEB_HOST
            
            # Check if streamlit_app.py exists
            app_path = Path(__file__).parent / "modules/streamlit_app.py"
            if not app_path.exists():
                self.logger.warning("Streamlit app not found, creating it...")
                self._create_streamlit_app()
            
            self.logger.info(f"Launching Streamlit web interface on {host}:{port}")
            print(f"Open your browser to: http://{host}:{port}")
            
            # Launch Streamlit
            subprocess.run([
                sys.executable, "-m", "streamlit", "run", 
                str(app_path), "--server.port", str(port), "--server.address", host
            ])
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error launching web interface: {e}")
            print("Make sure Streamlit is installed: pip install streamlit")
            import traceback
            self.logger.debug(traceback.format_exc())
            return False
    
    def setup_environment(self, install_sysmon=False, sysmon_config=None, uninstall=False):
        """Setup Sysmon and configure the environment"""
        try:
            if uninstall:
                self.logger.info("Uninstalling Sysmon...")
                # Use log_collector to uninstall Sysmon
                self.log_collector.uninstall_sysmon()
                return True
                
            if install_sysmon:
                sysmon_config = sysmon_config or config.SYSMON_CFG
                self.logger.info(f"Installing Sysmon with configuration: {sysmon_config}")
                # Use log_collector to install Sysmon
                self.log_collector.install_sysmon(sysmon_config)
                return True
                
            # Check for missing API keys
            missing_keys = config.validate_api_keys()
            if missing_keys:
                self.logger.warning(f"Missing API keys: {', '.join(missing_keys)}")
                print(f"Please set the following environment variables or create a .env file:")
                for key in missing_keys:
                    print(f"  {key}=your_api_key_here")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error setting up environment: {e}")
            import traceback
            self.logger.debug(traceback.format_exc())
            return False
    
    def _create_streamlit_app(self):
        """Create the Streamlit web application file"""
        # Import here to avoid circular imports
        from modules.streamlit_app import create_streamlit_app
        create_streamlit_app()
    
    def run(self):
        """Run the CLI tool based on command-line arguments"""
        args = self.parse_args()
        
        if args.command == "analyze":
            self.analyze_evtx(
                args.evtx_file,
                output=args.output,
                format=args.format,
                use_ai=args.ai,
                simple=args.simple
            )
        elif args.command == "collect":
            self.collect_logs(
                time_range=args.time_range,
                output_dir=args.output,
                analyze=not args.no_analyze,
                analyze_ips=args.analyze_ips,
                sysmon_only=args.sysmon_only
            )
        elif args.command == "intel":
            self.threat_intel_analysis(
                ip_file=args.ip_file,
                extract_ips=args.extract_ips,
                generate_pdf=args.generate_pdf,
                single_ip=args.single_ip,
                single_domain=args.single_domain,
                single_hash=args.single_hash
            )
        elif args.command == "hunt":
            self.hunt_threats(
                evtx_file=args.evtx_file,
                collect_logs=args.collect_logs,
                time_range=args.time_range,
                report_type=args.report_type,
                format=args.format,
                use_ai=not args.no_ai
            )
        elif args.command == "web":
            self.launch_web_interface(
                port=args.port,
                host=args.host
            )
        elif args.command == "setup":
            self.setup_environment(
                install_sysmon=args.install_sysmon,
                sysmon_config=args.sysmon_config,
                uninstall=args.uninstall
            )


if __name__ == "__main__":
    cli = SysmonCLI()
    cli.run()
