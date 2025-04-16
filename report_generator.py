"""
Report Generator module for SSH Log Analyzer
Creates HTML reports with analysis results and visualizations
"""

import pandas as pd
import os
import logging
from datetime import datetime
import socket
import html

logger = logging.getLogger(__name__)

class ReportGenerator:
    """
    Generates comprehensive reports of SSH authentication log analysis
    """
    
    def __init__(self):
        """Initialize the report generator"""
        pass
    
    def generate_report(self, log_entries, attack_data, visualizer, output_path, analysis_params):
        """
        Generate an HTML report with analysis results
        
        Args:
            log_entries (DataFrame): Parsed log entries from LogParser
            attack_data (DataFrame): Attack information from AttackDetector
            visualizer (Visualizer): Visualizer object with generated plots
            output_path (str): Path to save the report
            analysis_params (dict): Parameters used for analysis
            
        Returns:
            str: Path to the generated report
        """
        logger.info(f"Generating report to {output_path}")
        
        # Generate HTML content
        html_content = self._generate_html_content(log_entries, attack_data, visualizer, analysis_params)
        
        try:
            # Write to file
            with open(output_path, 'w') as f:
                f.write(html_content)
            
            logger.info(f"Report successfully generated at {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Error writing report to {output_path}: {str(e)}", exc_info=True)
            
            # Try to write to a fallback location
            fallback_path = f"ssh_attack_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            logger.info(f"Attempting to write report to fallback location: {fallback_path}")
            
            try:
                with open(fallback_path, 'w') as f:
                    f.write(html_content)
                return fallback_path
            except Exception as e2:
                logger.error(f"Error writing report to fallback location: {str(e2)}", exc_info=True)
                raise
    
    def _generate_html_content(self, log_entries, attack_data, visualizer, analysis_params):
        """
        Generate HTML content for the report
        
        Args:
            log_entries (DataFrame): Parsed log entries from LogParser
            attack_data (DataFrame): Attack information from AttackDetector
            visualizer (Visualizer): Visualizer object with generated plots
            analysis_params (dict): Parameters used for analysis
            
        Returns:
            str: HTML content for the report
        """
        # Get statistics for the summary
        stats = self._calculate_statistics(log_entries, attack_data)
        
        # Build HTML
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSH Authentication Log Analysis Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        header {{
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        header h1 {{
            color: white;
            margin: 0;
        }}
        .summary-box {{
            background-color: #f8f9fa;
            border-left: 4px solid #2c3e50;
            margin-bottom: 20px;
            padding: 15px;
            border-radius: 4px;
        }}
        .alert {{
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
        }}
        .alert-danger {{
            background-color: #f8d7da;
            border-color: #f5c6cb;
            color: #721c24;
        }}
        .alert-warning {{
            background-color: #fff3cd;
            border-color: #ffeeba;
            color: #856404;
        }}
        .alert-success {{
            background-color: #d4edda;
            border-color: #c3e6cb;
            color: #155724;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
        .visualization {{
            margin-bottom: 30px;
            text-align: center;
        }}
        .severity-critical {{
            background-color: #f8d7da;
        }}
        .severity-high {{
            background-color: #fff3cd;
        }}
        .severity-medium {{
            background-color: #e2f0d9;
        }}
        .footer {{
            margin-top: 40px;
            border-top: 1px solid #ddd;
            padding-top: 10px;
            font-size: 12px;
            color: #666;
        }}
        .params-table {{
            width: auto;
            margin-bottom: 20px;
        }}
        .params-table th, .params-table td {{
            padding: 5px 10px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>SSH Authentication Log Analysis Report</h1>
            <p>Generated on {analysis_params.get('analysis_time', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))}</p>
        </header>

        <section>
            <h2>Analysis Summary</h2>
            <div class="summary-box">
                <p><strong>Log File:</strong> {analysis_params.get('log_file', 'Unknown')}</p>
                <p><strong>Analysis Period:</strong> {stats['earliest_date']} to {stats['latest_date']}</p>
                <p><strong>Failed Login Attempts:</strong> {stats['total_failures']:,}</p>
                <p><strong>Unique Source IPs:</strong> {stats['unique_ips']:,}</p>
                <p><strong>Unique Usernames:</strong> {stats['unique_usernames']:,}</p>
                <p><strong>Potential Attacks Detected:</strong> {stats['attack_count']:,}</p>
            </div>

            <h3>Analysis Parameters</h3>
            <table class="params-table">
                <tr><th>Parameter</th><th>Value</th></tr>
                <tr><td>Attack Threshold</td><td>{analysis_params.get('threshold', 'N/A')} attempts</td></tr>
                <tr><td>Time Window</td><td>{analysis_params.get('window', 'N/A')} minutes</td></tr>
                <tr><td>IP Filter</td><td>{analysis_params.get('ip_filter', 'None')}</td></tr>
                <tr><td>Username Filter</td><td>{analysis_params.get('user_filter', 'None')}</td></tr>
                <tr><td>Date Range</td><td>{analysis_params.get('from_date', 'All')} to {analysis_params.get('to_date', 'All')}</td></tr>
            </table>

            <div class="alert {stats['overall_alert_class']}">
                <strong>{stats['overall_alert_heading']}</strong> {stats['overall_alert_message']}
            </div>
        </section>
"""

        # Add visualizations if available
        if visualizer and hasattr(visualizer, 'plots') and visualizer.plots:
            html += """
        <section>
            <h2>Visualizations</h2>
"""
            
            # Add each plot if it exists
            for plot_name, plot_data in visualizer.plots.items():
                if plot_data:
                    title = ' '.join(word.capitalize() for word in plot_name.split('_'))
                    html += f"""
            <div class="visualization">
                <h3>{title}</h3>
                <img src="data:image/png;base64,{plot_data}" alt="{title}">
            </div>
"""
            
            html += """
        </section>
"""

        # Add attack details if any attacks were detected
        if not attack_data.empty:
            html += """
        <section>
            <h2>Detected Attack Patterns</h2>
            <p>The following table details potential brute-force attacks detected based on the specified threshold and time window.</p>
            <table>
                <tr>
                    <th>Source IP</th>
                    <th>Primary Username</th>
                    <th>Start Time</th>
                    <th>End Time</th>
                    <th>Attempts</th>
                    <th>Frequency (attempts/min)</th>
                    <th>Severity</th>
                </tr>
"""
            
            # Add each attack row
            for _, attack in attack_data.iterrows():
                severity_class = f"severity-{attack['attack_severity'].lower()}" if attack['attack_severity'] in ['Critical', 'High'] else ""
                frequency = f"{attack['max_frequency']:.2f}" if attack['max_frequency'] > 0 else "N/A"
                
                html += f"""
                <tr class="{severity_class}">
                    <td>{html.escape(str(attack['source_ip']))}</td>
                    <td>{html.escape(str(attack['username']))}</td>
                    <td>{attack['start_time'].strftime('%Y-%m-%d %H:%M:%S')}</td>
                    <td>{attack['end_time'].strftime('%Y-%m-%d %H:%M:%S')}</td>
                    <td>{attack['attempt_count']}</td>
                    <td>{frequency}</td>
                    <td>{attack['attack_severity']}</td>
                </tr>
"""
            
            html += """
            </table>
        </section>
"""

            # Add detailed attack analysis
            html += self._generate_attack_analysis_section(attack_data)

        # Add top offenders section
        html += self._generate_top_offenders_section(log_entries)

        # Add recommendations based on findings
        html += self._generate_recommendations_section(stats, attack_data)

        # Close the HTML document
        html += f"""
        <div class="footer">
            <p>Generated by SSH Log Analyzer on {socket.gethostname()} | Report time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
    </div>
</body>
</html>
"""
        
        return html
    
    def _calculate_statistics(self, log_entries, attack_data):
        """
        Calculate statistics for the summary section
        
        Args:
            log_entries (DataFrame): Parsed log entries from LogParser
            attack_data (DataFrame): Attack information from AttackDetector
            
        Returns:
            dict: Statistics for the report
        """
        stats = {
            'total_failures': len(log_entries),
            'unique_ips': log_entries['source_ip'].nunique(),
            'unique_usernames': log_entries['username'].nunique(),
            'attack_count': len(attack_data),
            'earliest_date': log_entries['timestamp'].min().strftime('%Y-%m-%d %H:%M:%S') if not log_entries.empty else 'N/A',
            'latest_date': log_entries['timestamp'].max().strftime('%Y-%m-%d %H:%M:%S') if not log_entries.empty else 'N/A'
        }
        
        # Determine overall security alert level
        if not attack_data.empty:
            if any(attack_data['attack_severity'] == 'Critical'):
                stats['overall_alert_class'] = 'alert-danger'
                stats['overall_alert_heading'] = 'Critical Security Concern:'
                stats['overall_alert_message'] = f"Detected {len(attack_data[attack_data['attack_severity'] == 'Critical'])} critical severity attack patterns that require immediate attention!"
            elif any(attack_data['attack_severity'] == 'High'):
                stats['overall_alert_class'] = 'alert-warning'
                stats['overall_alert_heading'] = 'Security Warning:'
                stats['overall_alert_message'] = f"Detected {len(attack_data[attack_data['attack_severity'] == 'High'])} high severity attack patterns that should be investigated."
            elif any(attack_data['attack_severity'].isin(['Medium', 'Low'])):
                stats['overall_alert_class'] = 'alert-warning'
                stats['overall_alert_heading'] = 'Security Notice:'
                stats['overall_alert_message'] = 'Detected potential brute-force attack patterns with medium to low severity.'
            else:
                stats['overall_alert_class'] = 'alert-success'
                stats['overall_alert_heading'] = 'Security Status:'
                stats['overall_alert_message'] = 'No significant attack patterns detected during the analysis period.'
        else:
            if stats['total_failures'] > 100:
                stats['overall_alert_class'] = 'alert-warning'
                stats['overall_alert_heading'] = 'Security Notice:'
                stats['overall_alert_message'] = f"Found {stats['total_failures']} failed login attempts, but no attack patterns met the detection threshold."
            else:
                stats['overall_alert_class'] = 'alert-success'
                stats['overall_alert_heading'] = 'Security Status:'
                stats['overall_alert_message'] = 'No attack patterns detected during the analysis period.'
        
        return stats
    
    def _generate_attack_analysis_section(self, attack_data):
        """
        Generate HTML for attack analysis section
        
        Args:
            attack_data (DataFrame): Attack information from AttackDetector
            
        Returns:
            str: HTML content for attack analysis
        """
        # Skip if no attacks
        if attack_data.empty:
            return ""
        
        # Calculate some statistics
        critical_attacks = len(attack_data[attack_data['attack_severity'] == 'Critical'])
        high_attacks = len(attack_data[attack_data['attack_severity'] == 'High'])
        medium_attacks = len(attack_data[attack_data['attack_severity'] == 'Medium'])
        low_attacks = len(attack_data[attack_data['attack_severity'] == 'Low'])
        
        # Get top attacking IPs
        top_ips = attack_data['source_ip'].value_counts().head(5)
        
        html = """
        <section>
            <h2>Attack Analysis</h2>
            <div class="summary-box">
"""
        
        # Add attack severity breakdown
        html += f"""
                <h3>Attack Severity Breakdown</h3>
                <ul>
                    <li><strong>Critical:</strong> {critical_attacks} attacks</li>
                    <li><strong>High:</strong> {high_attacks} attacks</li>
                    <li><strong>Medium:</strong> {medium_attacks} attacks</li>
                    <li><strong>Low:</strong> {low_attacks} attacks</li>
                </ul>
"""
        
        # Add top attacking IPs
        html += """
                <h3>Most Active Attacking IPs</h3>
                <ul>
"""
        
        for ip, count in top_ips.items():
            html += f"""
                    <li><strong>{html.escape(str(ip))}:</strong> {count} attack patterns</li>
"""
        
        html += """
                </ul>
            </div>
        </section>
"""
        
        return html
    
    def _generate_top_offenders_section(self, log_entries):
        """
        Generate HTML for top offenders section
        
        Args:
            log_entries (DataFrame): Parsed log entries from LogParser
            
        Returns:
            str: HTML content for top offenders
        """
        if log_entries.empty:
            return ""
        
        # Get top IPs by failure count
        top_ips = log_entries['source_ip'].value_counts().head(10)
        
        # Get top targeted usernames
        top_usernames = log_entries['username'].value_counts().head(10)
        
        html = """
        <section>
            <h2>Top Offenders</h2>
            <div class="row">
                <div class="col">
                    <h3>Top 10 Source IPs by Failed Attempts</h3>
                    <table>
                        <tr>
                            <th>IP Address</th>
                            <th>Failed Attempts</th>
                            <th>Percentage</th>
                        </tr>
"""
        
        # Add top IPs
        total_failures = len(log_entries)
        for ip, count in top_ips.items():
            percentage = (count / total_failures) * 100
            html += f"""
                        <tr>
                            <td>{html.escape(str(ip))}</td>
                            <td>{count}</td>
                            <td>{percentage:.2f}%</td>
                        </tr>
"""
        
        html += """
                    </table>
                </div>
                
                <div class="col">
                    <h3>Top 10 Targeted Usernames</h3>
                    <table>
                        <tr>
                            <th>Username</th>
                            <th>Failed Attempts</th>
                            <th>Percentage</th>
                        </tr>
"""
        
        # Add top usernames
        for username, count in top_usernames.items():
            percentage = (count / total_failures) * 100
            html += f"""
                        <tr>
                            <td>{html.escape(str(username))}</td>
                            <td>{count}</td>
                            <td>{percentage:.2f}%</td>
                        </tr>
"""
        
        html += """
                    </table>
                </div>
            </div>
        </section>
"""
        
        return html
    
    def _generate_recommendations_section(self, stats, attack_data):
        """
        Generate HTML for security recommendations based on findings
        
        Args:
            stats (dict): Statistics from _calculate_statistics
            attack_data (DataFrame): Attack information from AttackDetector
            
        Returns:
            str: HTML content for recommendations
        """
        html = """
        <section>
            <h2>Security Recommendations</h2>
            <div class="summary-box">
                <ul>
"""
        
        # Add recommendations based on findings
        if stats['attack_count'] > 0:
            html += """
                    <li><strong>Implement Fail2Ban</strong> to automatically block IPs with multiple failed login attempts.</li>
                    <li><strong>Configure SSH to use key-based authentication only</strong> and disable password authentication.</li>
                    <li><strong>Change the default SSH port</strong> to reduce automated scanning.</li>
"""
            
            # Add recommendation for IP blocking if critical attacks found
            if 'overall_alert_class' in stats and stats['overall_alert_class'] == 'alert-danger':
                html += """
                    <li><strong>Consider immediately blocking</strong> the IPs associated with critical severity attacks.</li>
"""
        
        # General recommendations
        html += """
                    <li><strong>Use strong, unique passwords</strong> for all accounts.</li>
                    <li><strong>Implement Multi-Factor Authentication (MFA)</strong> for SSH access where possible.</li>
                    <li><strong>Regularly update and patch</strong> your SSH server software.</li>
                    <li><strong>Restrict SSH access</strong> to specific IP addresses or networks when possible.</li>
                    <li><strong>Set up regular log monitoring</strong> to quickly detect and respond to potential attacks.</li>
"""
        
        html += """
                </ul>
            </div>
        </section>
"""
        
        return html
