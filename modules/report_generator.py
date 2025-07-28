#!/usr/bin/env python3
"""
Comprehensive Threat Hunting Report Generator
Advanced reporting capabilities for cybersecurity professionals
"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
import base64
from collections import Counter, defaultdict
import hashlib

try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    import pandas as pd
    import numpy as np
    from wordcloud import WordCloud
    import plotly.graph_objects as go
    import plotly.express as px
    from plotly.offline import plot
    import networkx as nx
except ImportError as e:
    logging.warning(f"Some visualization libraries not available: {e}")

class ThreatReportGenerator:
    """Advanced threat hunting report generator"""
    
    def __init__(self, output_dir: str = "reports"):
        """Initialize the report generator
        
        Args:
            output_dir: Directory to store generated reports
        """
        self.logger = logging.getLogger(__name__)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Report templates
        self.executive_template = """
# CYBERSECURITY THREAT HUNTING REPORT
## EXECUTIVE SUMMARY

**Report Classification:** {classification}
**Analysis Period:** {analysis_period}
**Report Generated:** {report_date}
**Analyst:** Sysmon AI - Advanced Threat Hunting Platform

---

### 🎯 KEY FINDINGS

{key_findings}

### ⚠️ CRITICAL ALERTS

{critical_alerts}

### 📊 THREAT LANDSCAPE OVERVIEW

- **Total Security Events Analyzed:** {total_events:,}
- **Suspicious Activities Detected:** {suspicious_count:,}
- **High-Risk Indicators:** {high_risk_count}
- **Systems Affected:** {affected_systems}
- **Overall Risk Score:** {risk_score}/100

### 🚨 IMMEDIATE ACTIONS REQUIRED

{immediate_actions}

---

*This report contains sensitive security information and should be handled according to your organization's data classification policies.*
"""

        # MITRE ATT&CK framework mapping
        self.mitre_tactics = {
            'TA0001': 'Initial Access',
            'TA0002': 'Execution',
            'TA0003': 'Persistence',
            'TA0004': 'Privilege Escalation',
            'TA0005': 'Defense Evasion',
            'TA0006': 'Credential Access',
            'TA0007': 'Discovery',
            'TA0008': 'Lateral Movement',
            'TA0009': 'Collection',
            'TA0010': 'Exfiltration',
            'TA0011': 'Command and Control'
        }

    def generate_comprehensive_report(self, 
                                    analysis_results: Dict[str, Any],
                                    log_collection_results: Dict[str, Any],
                                    report_type: str = 'full',
                                    classification: str = 'CONFIDENTIAL') -> Dict[str, str]:
        """Generate comprehensive threat hunting report
        
        Args:
            analysis_results: Results from threat analysis
            log_collection_results: Results from log collection
            report_type: Type of report ('executive', 'technical', 'full')
            classification: Security classification level
            
        Returns:
            Dictionary containing report file paths
        """
        self.logger.info(f"Generating {report_type} threat hunting report")
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_files = {}
        
        # Generate different report formats
        if report_type in ['executive', 'full']:
            # Executive Summary (PDF-ready)
            executive_report = self._generate_executive_report(
                analysis_results, log_collection_results, classification
            )
            exec_file = self.output_dir / f"executive_summary_{timestamp}.md"
            with open(exec_file, 'w', encoding='utf-8') as f:
                f.write(executive_report)
            report_files['executive_summary'] = str(exec_file)
        
        if report_type in ['technical', 'full']:
            # Technical Analysis Report
            technical_report = self._generate_technical_report(
                analysis_results, log_collection_results
            )
            tech_file = self.output_dir / f"technical_analysis_{timestamp}.html"
            with open(tech_file, 'w', encoding='utf-8') as f:
                f.write(technical_report)
            report_files['technical_analysis'] = str(tech_file)
            
            # IOC Report (CSV format for threat intelligence platforms)
            ioc_report = self._generate_ioc_report(analysis_results)
            ioc_file = self.output_dir / f"ioc_indicators_{timestamp}.csv"
            with open(ioc_file, 'w', encoding='utf-8') as f:
                f.write(ioc_report)
            report_files['ioc_indicators'] = str(ioc_file)
            
            # MISP Event (JSON format for MISP threat intelligence)
            misp_event = self._generate_misp_event(analysis_results)
            misp_file = self.output_dir / f"misp_event_{timestamp}.json"
            with open(misp_file, 'w', encoding='utf-8') as f:
                f.write(misp_event)
            report_files['misp_event'] = str(misp_file)
        
        # Generate visualizations
        if 'matplotlib' in globals():
            viz_files = self._generate_visualizations(analysis_results, timestamp)
            report_files.update(viz_files)
        
        # Generate hunting playbooks
        playbook = self._generate_hunting_playbook(analysis_results)
        playbook_file = self.output_dir / f"hunting_playbook_{timestamp}.md"
        with open(playbook_file, 'w', encoding='utf-8') as f:
            f.write(playbook)
        report_files['hunting_playbook'] = str(playbook_file)
        
        # Generate SIEM rules
        siem_rules = self._generate_siem_rules(analysis_results)
        rules_file = self.output_dir / f"siem_rules_{timestamp}.txt"
        with open(rules_file, 'w', encoding='utf-8') as f:
            f.write(siem_rules)
        report_files['siem_rules'] = str(rules_file)
        
        self.logger.info(f"Report generation completed. Files: {list(report_files.keys())}")
        return report_files

    def _generate_executive_report(self, 
                                  analysis_results: Dict[str, Any],
                                  log_collection_results: Dict[str, Any],
                                  classification: str) -> str:
        """Generate executive summary report"""
        
        # Extract key metrics
        total_events = log_collection_results.get('summary', {}).get('total_events', 0)
        suspicious_count = len(analysis_results.get('threat_detections', []))
        risk_score = analysis_results.get('risk_assessment', {}).get('total_risk_score', 0)
        
        # Critical findings
        critical_detections = [d for d in analysis_results.get('threat_detections', []) 
                             if d.get('severity') == 'critical']
        high_risk_count = len([d for d in analysis_results.get('threat_detections', []) 
                              if d.get('severity') in ['critical', 'high']])
        
        # Affected systems analysis
        affected_systems = set()
        for detection in analysis_results.get('threat_detections', []):
            if 'log_source' in detection:
                affected_systems.add(detection['log_source'])
        
        # Key findings
        key_findings = []
        if analysis_results.get('lateral_movement_analysis', {}).get('detected_movement'):
            key_findings.append("🔴 **LATERAL MOVEMENT DETECTED** - Attackers have moved across network boundaries")
        
        if analysis_results.get('persistence_analysis', {}).get('persistence_methods'):
            key_findings.append("🔴 **PERSISTENCE MECHANISMS IDENTIFIED** - Attackers have established foothold")
        
        if len(analysis_results.get('ioc_extraction', {}).get('suspicious_domains', [])) > 10:
            key_findings.append("🟡 **EXTENSIVE C2 COMMUNICATION** - Multiple suspicious domains contacted")
        
        if not key_findings:
            key_findings.append("🟢 **NO CRITICAL THREATS DETECTED** - Systems appear secure within analysis period")
        
        # Critical alerts
        critical_alerts = []
        for detection in critical_detections[:5]:  # Top 5 critical
            critical_alerts.append(f"- **{detection.get('threat_category', 'Unknown').title()}**: {detection.get('matched_content', '')[:100]}...")
        
        if not critical_alerts:
            critical_alerts.append("- No critical-severity threats detected in current analysis")
        
        # Immediate actions
        immediate_actions = []
        if critical_detections:
            immediate_actions.extend([
                "1. **ISOLATE AFFECTED SYSTEMS** - Immediately quarantine systems showing critical indicators",
                "2. **RESET CREDENTIALS** - Force password resets for potentially compromised accounts",
                "3. **ACTIVATE INCIDENT RESPONSE** - Escalate to incident response team",
                "4. **PRESERVE EVIDENCE** - Capture memory dumps and disk images of affected systems"
            ])
        elif high_risk_count > 0:
            immediate_actions.extend([
                "1. **ENHANCE MONITORING** - Increase logging verbosity on affected systems",
                "2. **VALIDATE FINDINGS** - Manually verify suspicious activities",
                "3. **UPDATE DEFENSES** - Deploy additional detection rules",
                "4. **USER AWARENESS** - Alert users to potential phishing campaigns"
            ])
        else:
            immediate_actions.extend([
                "1. **MAINTAIN VIGILANCE** - Continue regular monitoring activities",
                "2. **UPDATE SIGNATURES** - Refresh threat detection rules",
                "3. **SECURITY REVIEW** - Conduct routine security posture assessment"
            ])
        
        # Analysis period
        analysis_period = f"{datetime.now() - timedelta(hours=24):%Y-%m-%d} to {datetime.now():%Y-%m-%d}"
        
        return self.executive_template.format(
            classification=classification,
            analysis_period=analysis_period,
            report_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
            key_findings='\n'.join(key_findings),
            critical_alerts='\n'.join(critical_alerts),
            total_events=total_events,
            suspicious_count=suspicious_count,
            high_risk_count=high_risk_count,
            affected_systems=len(affected_systems),
            risk_score=risk_score,
            immediate_actions='\n'.join(immediate_actions)
        )

    def _generate_technical_report(self, 
                                  analysis_results: Dict[str, Any],
                                  log_collection_results: Dict[str, Any]) -> str:
        """Generate detailed technical analysis report"""
        
        html_report = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Hunting Technical Analysis</title>
    <style>
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 0; 
            padding: 20px; 
            background-color: #f5f5f5; 
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .section {{
            background: white;
            margin: 20px 0;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .metric-card {{
            display: inline-block;
            background: #f8f9fa;
            padding: 15px;
            margin: 10px;
            border-radius: 8px;
            border-left: 4px solid #007bff;
            min-width: 150px;
        }}
        .critical {{ border-left-color: #dc3545; }}
        .high {{ border-left-color: #fd7e14; }}
        .medium {{ border-left-color: #ffc107; }}
        .low {{ border-left-color: #28a745; }}
        .detection-item {{
            background: #f8f9fa;
            margin: 10px 0;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #6c757d;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th, td {{
            border: 1px solid #dee2e6;
            padding: 12px;
            text-align: left;
        }}
        th {{
            background-color: #e9ecef;
            font-weight: bold;
        }}
        .code {{
            background: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            border: 1px solid #e9ecef;
            overflow-x: auto;
        }}
        .mitre-tactic {{
            display: inline-block;
            background: #007bff;
            color: white;
            padding: 4px 8px;
            margin: 2px;
            border-radius: 12px;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Advanced Threat Hunting Analysis</h1>
        <p>Technical Deep-Dive Report</p>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        <p><strong>Analysis Engine:</strong> Sysmon AI v0.1</p>
    </div>

    <div class="section">
        <h2>📊 Analysis Overview</h2>
        <div class="metric-card">
            <h3>{len(analysis_results.get('threat_detections', []))}</h3>
            <p>Total Detections</p>
        </div>
        <div class="metric-card critical">
            <h3>{len([d for d in analysis_results.get('threat_detections', []) if d.get('severity') == 'critical'])}</h3>
            <p>Critical Threats</p>
        </div>
        <div class="metric-card high">
            <h3>{len([d for d in analysis_results.get('threat_detections', []) if d.get('severity') == 'high'])}</h3>
            <p>High Severity</p>
        </div>
        <div class="metric-card">
            <h3>{analysis_results.get('risk_assessment', {}).get('total_risk_score', 0)}/100</h3>
            <p>Risk Score</p>
        </div>
    </div>

    <div class="section">
        <h2>🎯 MITRE ATT&CK Mapping</h2>
        <p>Detected tactics and techniques mapped to the MITRE ATT&CK framework:</p>
        {self._generate_mitre_section(analysis_results)}
    </div>

    <div class="section">
        <h2>🚨 Threat Detections</h2>
        {self._generate_detections_section(analysis_results)}
    </div>

    <div class="section">
        <h2>🔗 Lateral Movement Analysis</h2>
        {self._generate_lateral_movement_section(analysis_results)}
    </div>

    <div class="section">
        <h2>💾 Persistence Analysis</h2>
        {self._generate_persistence_section(analysis_results)}
    </div>

    <div class="section">
        <h2>🌐 Network Activity Analysis</h2>
        {self._generate_network_section(analysis_results)}
    </div>

    <div class="section">
        <h2>📋 Indicators of Compromise (IOCs)</h2>
        {self._generate_ioc_section(analysis_results)}
    </div>

    <div class="section">
        <h2>🎯 Hunting Recommendations</h2>
        {self._generate_hunting_recommendations(analysis_results)}
    </div>

    <div class="section">
        <h2>🔧 System Information</h2>
        {self._generate_system_info_section(log_collection_results)}
    </div>

</body>
</html>
"""
        return html_report

    def _generate_mitre_section(self, analysis_results: Dict[str, Any]) -> str:
        """Generate MITRE ATT&CK mapping section"""
        tactics_found = defaultdict(list)
        
        for detection in analysis_results.get('threat_detections', []):
            for tactic in detection.get('mitre_tactics', []):
                tactics_found[tactic].append(detection)
        
        if not tactics_found:
            return "<p>No MITRE ATT&CK tactics detected in current analysis.</p>"
        
        mitre_html = "<div style='margin: 20px 0;'>"
        for tactic_id, detections in tactics_found.items():
            tactic_name = self.mitre_tactics.get(tactic_id, f"Unknown ({tactic_id})")
            mitre_html += f"""
            <div style="margin: 15px 0; padding: 15px; background: #f8f9fa; border-radius: 8px;">
                <span class="mitre-tactic">{tactic_id}</span>
                <strong>{tactic_name}</strong> - {len(detections)} detection(s)
                <ul>
            """
            for detection in detections[:3]:  # Show first 3
                mitre_html += f"<li>{detection.get('threat_category', 'Unknown').replace('_', ' ').title()}</li>"
            if len(detections) > 3:
                mitre_html += f"<li><em>... and {len(detections) - 3} more</em></li>"
            mitre_html += "</ul></div>"
        
        mitre_html += "</div>"
        return mitre_html

    def _generate_detections_section(self, analysis_results: Dict[str, Any]) -> str:
        """Generate threat detections section"""
        detections = analysis_results.get('threat_detections', [])
        
        if not detections:
            return "<p>No threat detections found in current analysis.</p>"
        
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        detections.sort(key=lambda x: severity_order.get(x.get('severity', 'low'), 3))
        
        html = ""
        for i, detection in enumerate(detections[:20], 1):  # Show top 20
            severity = detection.get('severity', 'unknown')
            html += f"""
            <div class="detection-item {severity}">
                <h4>Detection #{i} - {detection.get('threat_category', 'Unknown').replace('_', ' ').title()}</h4>
                <p><strong>Severity:</strong> {severity.upper()}</p>
                <p><strong>Source:</strong> {detection.get('log_source', 'Unknown')}</p>
                <p><strong>Pattern:</strong> <code>{detection.get('pattern_matched', 'N/A')}</code></p>
                <p><strong>Content:</strong></p>
                <div class="code">{detection.get('matched_content', 'N/A')[:500]}{'...' if len(detection.get('matched_content', '')) > 500 else ''}</div>
            </div>
            """
        
        if len(detections) > 20:
            html += f"<p><em>... and {len(detections) - 20} more detections (see full JSON report for complete list)</em></p>"
        
        return html

    def _generate_lateral_movement_section(self, analysis_results: Dict[str, Any]) -> str:
        """Generate lateral movement analysis section"""
        lateral_analysis = analysis_results.get('lateral_movement_analysis', {})
        
        if not lateral_analysis.get('detected_movement'):
            return "<p>✅ No lateral movement detected in current analysis.</p>"
        
        html = f"""
        <div style="background: #fff3cd; padding: 15px; border-radius: 8px; border-left: 4px solid #ffc107;">
            <h4>⚠️ Lateral Movement Detected</h4>
            <p><strong>Compromised Hosts:</strong> {len(lateral_analysis.get('compromised_hosts', []))}</p>
            <p><strong>Movement Techniques:</strong></p>
            <ul>
        """
        
        for technique, count in lateral_analysis.get('movement_techniques', {}).items():
            html += f"<li><code>{technique}</code> - {count} occurrence(s)</li>"
        
        html += """
            </ul>
        </div>
        
        <h4>Affected Systems:</h4>
        <ul>
        """
        
        for host in lateral_analysis.get('compromised_hosts', []):
            html += f"<li><code>{host}</code></li>"
        
        html += "</ul>"
        return html

    def _generate_persistence_section(self, analysis_results: Dict[str, Any]) -> str:
        """Generate persistence analysis section"""
        persistence_analysis = analysis_results.get('persistence_analysis', {})
        
        if not persistence_analysis.get('persistence_methods'):
            return "<p>✅ No persistence mechanisms detected.</p>"
        
        html = f"""
        <div style="background: #f8d7da; padding: 15px; border-radius: 8px; border-left: 4px solid #dc3545;">
            <h4>🚨 Persistence Mechanisms Detected</h4>
            <p>Attackers have established persistence on compromised systems.</p>
        </div>
        
        <h4>Persistence Methods:</h4>
        <table>
            <tr><th>Method</th><th>Occurrences</th></tr>
        """
        
        for method, count in persistence_analysis.get('persistence_methods', {}).items():
            html += f"<tr><td><code>{method}</code></td><td>{count}</td></tr>"
        
        html += "</table>"
        
        if persistence_analysis.get('registry_modifications'):
            html += f"<p><strong>Registry Modifications:</strong> {len(persistence_analysis['registry_modifications'])}</p>"
        
        if persistence_analysis.get('scheduled_tasks'):
            html += f"<p><strong>Scheduled Tasks:</strong> {len(persistence_analysis['scheduled_tasks'])}</p>"
        
        return html

    def _generate_network_section(self, analysis_results: Dict[str, Any]) -> str:
        """Generate network activity analysis section"""
        network_analysis = analysis_results.get('data_flow_analysis', {})
        
        html = "<h4>Suspicious Network Activity:</h4>"
        
        if network_analysis.get('suspicious_domains'):
            html += f"""
            <p><strong>Suspicious Domains ({len(network_analysis['suspicious_domains'])}):</strong></p>
            <ul>
            """
            for domain in network_analysis['suspicious_domains'][:10]:
                html += f"<li><code>{domain}</code></li>"
            if len(network_analysis['suspicious_domains']) > 10:
                html += f"<li><em>... and {len(network_analysis['suspicious_domains']) - 10} more</em></li>"
            html += "</ul>"
        
        if network_analysis.get('network_connections'):
            html += f"""
            <p><strong>Suspicious IP Connections:</strong></p>
            <table>
                <tr><th>IP Address</th><th>Connections</th></tr>
            """
            for ip, count in list(network_analysis['network_connections'].items())[:10]:
                html += f"<tr><td><code>{ip}</code></td><td>{count}</td></tr>"
            html += "</table>"
        
        return html

    def _generate_ioc_section(self, analysis_results: Dict[str, Any]) -> str:
        """Generate IOC section"""
        iocs = analysis_results.get('ioc_extraction', {})
        
        html = """
        <table>
            <tr><th>IOC Type</th><th>Count</th><th>Examples</th></tr>
        """
        
        for ioc_type, ioc_list in iocs.items():
            if ioc_list:
                examples = ', '.join(list(ioc_list)[:3])
                if len(ioc_list) > 3:
                    examples += f", ... (+{len(ioc_list) - 3} more)"
                html += f"""
                <tr>
                    <td>{ioc_type.replace('_', ' ').title()}</td>
                    <td>{len(ioc_list)}</td>
                    <td><code>{examples}</code></td>
                </tr>
                """
        
        html += "</table>"
        return html

    def _generate_hunting_recommendations(self, analysis_results: Dict[str, Any]) -> str:
        """Generate hunting recommendations section"""
        recommendations = []
        
        # Base recommendations
        recommendations.extend([
            "Implement continuous monitoring for detected IOCs",
            "Review and update security policies based on findings",
            "Enhance logging for critical system events",
            "Conduct regular threat hunting exercises"
        ])
        
        # Specific recommendations based on findings
        if analysis_results.get('lateral_movement_analysis', {}).get('detected_movement'):
            recommendations.extend([
                "Deploy network segmentation to limit lateral movement",
                "Implement privileged access management (PAM) solutions",
                "Enable advanced network monitoring and analytics"
            ])
        
        if analysis_results.get('persistence_analysis', {}).get('persistence_methods'):
            recommendations.extend([
                "Implement application whitelisting",
                "Monitor registry and startup folder modifications",
                "Deploy endpoint detection and response (EDR) solutions"
            ])
        
        html = "<ul>"
        for rec in recommendations:
            html += f"<li>{rec}</li>"
        html += "</ul>"
        
        return html

    def _generate_system_info_section(self, log_collection_results: Dict[str, Any]) -> str:
        """Generate system information section"""
        system_info = log_collection_results.get('system_info', {})
        
        html = f"""
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Platform</td><td>{system_info.get('platform', 'Unknown')}</td></tr>
            <tr><td>Architecture</td><td>{system_info.get('architecture', 'Unknown')}</td></tr>
            <tr><td>Hostname</td><td>{system_info.get('hostname', 'Unknown')}</td></tr>
            <tr><td>Analysis Duration</td><td>{log_collection_results.get('time_range_hours', 24)} hours</td></tr>
            <tr><td>Log Sources</td><td>{log_collection_results.get('summary', {}).get('successful_collections', 0)}</td></tr>
        </table>
        """
        
        return html

    def _generate_ioc_report(self, analysis_results: Dict[str, Any]) -> str:
        """Generate CSV IOC report for threat intelligence platforms"""
        csv_content = "IOC_Type,IOC_Value,First_Seen,Confidence,Description\n"
        
        iocs = analysis_results.get('ioc_extraction', {})
        timestamp = datetime.now().isoformat()
        
        for ioc_type, ioc_list in iocs.items():
            for ioc in ioc_list:
                confidence = "Medium"  # Could be enhanced with ML confidence scoring
                description = f"Extracted from threat hunting analysis - {ioc_type}"
                csv_content += f'"{ioc_type}","{ioc}","{timestamp}","{confidence}","{description}"\n'
        
        return csv_content

    def _generate_misp_event(self, analysis_results: Dict[str, Any]) -> str:
        """Generate MISP event JSON for threat intelligence sharing"""
        event_uuid = hashlib.md5(f"{datetime.now().isoformat()}".encode()).hexdigest()
        
        misp_event = {
            "Event": {
                "uuid": event_uuid,
                "info": f"Threat Hunting Analysis - {datetime.now().strftime('%Y-%m-%d')}",
                "date": datetime.now().strftime('%Y-%m-%d'),
                "threat_level_id": "2",  # Medium
                "published": False,
                "analysis": "1",  # Ongoing
                "distribution": "1",  # This community only
                "Attribute": []
            }
        }
        
        # Add IOCs as attributes
        iocs = analysis_results.get('ioc_extraction', {})
        for ioc_type, ioc_list in iocs.items():
            for ioc in ioc_list[:50]:  # Limit to prevent huge events
                attribute = {
                    "type": self._map_ioc_to_misp_type(ioc_type),
                    "value": ioc,
                    "category": "Network activity",
                    "to_ids": True,
                    "distribution": "1"
                }
                misp_event["Event"]["Attribute"].append(attribute)
        
        return json.dumps(misp_event, indent=2)

    def _map_ioc_to_misp_type(self, ioc_type: str) -> str:
        """Map internal IOC types to MISP attribute types"""
        mapping = {
            'ip_addresses': 'ip-dst',
            'domains': 'domain',
            'urls': 'url',
            'file_hashes': 'md5',
            'email_addresses': 'email-src'
        }
        return mapping.get(ioc_type, 'text')

    def _generate_hunting_playbook(self, analysis_results: Dict[str, Any]) -> str:
        """Generate threat hunting playbook"""
        
        playbook = f"""# Threat Hunting Playbook
## Generated from Analysis Results

### Overview
This playbook was automatically generated based on threat hunting analysis results.
Use these procedures to investigate similar threats in your environment.

### Threat Signatures Detected
"""
        
        # Group detections by category
        detections_by_category = defaultdict(list)
        for detection in analysis_results.get('threat_detections', []):
            detections_by_category[detection.get('threat_category', 'unknown')].append(detection)
        
        for category, detections in detections_by_category.items():
            playbook += f"""
#### {category.replace('_', ' ').title()} ({len(detections)} detections)

**Investigation Steps:**
1. Search for additional instances of detected patterns
2. Correlate with user activity and system events
3. Check for related network connections
4. Validate against known threat intelligence

**Search Queries:**
"""
            # Add sample queries for each detection pattern
            unique_patterns = set(d.get('pattern_matched', '') for d in detections)
            for pattern in list(unique_patterns)[:3]:  # Top 3 patterns
                playbook += f"""
- **Pattern:** `{pattern}`
- **Splunk:** `index=* "{pattern}" | stats count by host, user`
- **Elastic:** `"query": {{"regexp": {{"message": "{pattern}"}}}}`
- **Windows Event Log:** `Get-WinEvent | Where-Object {{$_.Message -like "*{pattern}*"}}`

"""
        
        playbook += f"""
### Recommended Actions

#### Immediate Response
1. **Isolate** affected systems if critical threats detected
2. **Preserve** evidence for forensic analysis
3. **Reset** credentials for potentially compromised accounts
4. **Monitor** for additional malicious activity

#### Investigation
1. **Timeline Analysis** - Reconstruct attack sequence
2. **Lateral Movement** - Check for spread to other systems
3. **Data Impact** - Assess what data may have been accessed
4. **Persistence** - Look for backdoors and persistence mechanisms

#### Recovery
1. **Patch Systems** - Apply security updates
2. **Update Rules** - Deploy new detection signatures
3. **User Training** - Educate users on threats found
4. **Process Improvement** - Update incident response procedures

### IOC Watchlist

Monitor your environment for these indicators:

#### IP Addresses
"""
        
        # Add IOCs to watchlist
        for ip in analysis_results.get('ioc_extraction', {}).get('ip_addresses', [])[:20]:
            playbook += f"- `{ip}`\n"
        
        playbook += "\n#### Domains\n"
        for domain in analysis_results.get('ioc_extraction', {}).get('domains', [])[:20]:
            playbook += f"- `{domain}`\n"
        
        playbook += f"""
### Additional Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [SANS Digital Forensics](https://www.sans.org/digital-forensics-incident-response/)

---
*Generated by Sysmon AI - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""
        
        return playbook

    def _generate_siem_rules(self, analysis_results: Dict[str, Any]) -> str:
        """Generate SIEM detection rules"""
        
        rules = f"""# SIEM Detection Rules
# Generated from Threat Hunting Analysis
# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

"""
        
        # Generate rules for detected patterns
        rule_id = 1
        for detection in analysis_results.get('threat_detections', []):
            pattern = detection.get('pattern_matched', '')
            category = detection.get('threat_category', 'unknown')
            severity = detection.get('severity', 'medium')
            
            # Splunk rules
            rules += f"""
## Rule {rule_id}: {category.replace('_', ' ').title()}

### Splunk
```
index=* "{pattern}"
| eval severity="{severity}"
| eval threat_category="{category}"
| stats count by host, user, threat_category
| where count > 0
```

### Elastic (ECS)
```json
{{
  "query": {{
    "bool": {{
      "must": [
        {{
          "regexp": {{
            "message": "{pattern}"
          }}
        }}
      ]
    }}
  }},
  "sort": [
    {{
      "@timestamp": {{
        "order": "desc"
      }}
    }}
  ]
}}
```

### Sigma Rule
```yaml
title: {category.replace('_', ' ').title()} Detection
description: Detects {category.replace('_', ' ')} based on pattern analysis
status: experimental
level: {severity}
detection:
    selection:
        EventLog: "*{pattern}*"
    condition: selection
falsepositives:
    - Administrative activity
    - Software updates
fields:
    - EventID
    - ProcessName
    - CommandLine
```

"""
            rule_id += 1
            if rule_id > 10:  # Limit number of rules
                break
        
        # Add IOC-based rules
        rules += """
## IOC-Based Detection Rules

### IP Address Monitoring (Splunk)
```
index=* ("""
        
        suspicious_ips = analysis_results.get('data_flow_analysis', {}).get('network_connections', {})
        if suspicious_ips:
            ip_list = '" OR "'.join(list(suspicious_ips.keys())[:20])
            rules += f'"{ip_list}"'
        
        rules += """)
| eval threat_type="suspicious_ip"
| stats count by src_ip, dest_ip, threat_type
```

### Domain Monitoring (Elastic)
```json
{
  "query": {
    "terms": {
      "dns.question.name": ["""
        
        suspicious_domains = analysis_results.get('data_flow_analysis', {}).get('suspicious_domains', [])
        if suspicious_domains:
            domain_list = '", "'.join(suspicious_domains[:20])
            rules += f'"{domain_list}"'
        
        rules += """
      ]
    }
  }
}
```

---
*Generated by Sysmon AI Threat Hunting Platform*
"""
        
        return rules

    def _generate_visualizations(self, analysis_results: Dict[str, Any], timestamp: str) -> Dict[str, str]:
        """Generate visualization charts"""
        viz_files = {}
        
        try:
            # Threat severity distribution
            severity_counts = Counter()
            for detection in analysis_results.get('threat_detections', []):
                severity_counts[detection.get('severity', 'unknown')] += 1
            
            if severity_counts:
                plt.figure(figsize=(10, 6))
                colors = {'critical': '#dc3545', 'high': '#fd7e14', 'medium': '#ffc107', 'low': '#28a745'}
                
                severities = list(severity_counts.keys())
                counts = list(severity_counts.values())
                bar_colors = [colors.get(s, '#6c757d') for s in severities]
                
                plt.bar(severities, counts, color=bar_colors)
                plt.title('Threat Detections by Severity Level')
                plt.xlabel('Severity')
                plt.ylabel('Count')
                plt.xticks(rotation=45)
                plt.tight_layout()
                
                severity_chart = self.output_dir / f"threat_severity_{timestamp}.png"
                plt.savefig(severity_chart, dpi=300, bbox_inches='tight')
                plt.close()
                viz_files['threat_severity_chart'] = str(severity_chart)
            
            # Threat categories pie chart
            category_counts = Counter()
            for detection in analysis_results.get('threat_detections', []):
                category_counts[detection.get('threat_category', 'unknown')] += 1
            
            if category_counts:
                plt.figure(figsize=(12, 8))
                categories = list(category_counts.keys())
                counts = list(category_counts.values())
                
                # Clean up category names
                clean_categories = [cat.replace('_', ' ').title() for cat in categories]
                
                plt.pie(counts, labels=clean_categories, autopct='%1.1f%%', startangle=90)
                plt.title('Threat Categories Distribution')
                plt.axis('equal')
                
                category_chart = self.output_dir / f"threat_categories_{timestamp}.png"
                plt.savefig(category_chart, dpi=300, bbox_inches='tight')
                plt.close()
                viz_files['threat_categories_chart'] = str(category_chart)
            
            # Timeline heatmap (if we have timeline data)
            timeline_events = analysis_results.get('attack_timeline', [])
            if timeline_events and len(timeline_events) > 10:
                # Create hourly heatmap
                hours = [0] * 24
                for event in timeline_events:
                    try:
                        event_time = datetime.fromisoformat(event.get('timestamp', '').replace('Z', '+00:00'))
                        hours[event_time.hour] += 1
                    except:
                        continue
                
                if sum(hours) > 0:
                    plt.figure(figsize=(15, 3))
                    plt.imshow([hours], cmap='Reds', aspect='auto')
                    plt.colorbar(label='Event Count')
                    plt.title('Attack Activity Timeline (24-hour heatmap)')
                    plt.xlabel('Hour of Day')
                    plt.xticks(range(24), [f"{i:02d}:00" for i in range(24)], rotation=45)
                    plt.yticks([])
                    plt.tight_layout()
                    
                    timeline_chart = self.output_dir / f"attack_timeline_{timestamp}.png"
                    plt.savefig(timeline_chart, dpi=300, bbox_inches='tight')
                    plt.close()
                    viz_files['attack_timeline_chart'] = str(timeline_chart)
        
        except Exception as e:
            self.logger.error(f"Error generating visualizations: {str(e)}")
        
        return viz_files
