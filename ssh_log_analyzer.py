#!/usr/bin/env python3
"""
SSH Log Analyzer - Main module
A tool for analyzing SSH authentication logs to detect and report brute-force attacks
"""

import os
import sys
import argparse
import logging
from datetime import datetime

# Internal modules
from log_parser import LogParser
from attack_detector import AttackDetector
from visualizer import Visualizer
from report_generator import ReportGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def setup_argparse():
    """Set up command-line argument parsing"""
    parser = argparse.ArgumentParser(
        description='Analyze SSH authentication logs to detect brute-force attacks',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        '-f', '--file',
        default='/var/log/auth.log',
        help='Path to the auth.log file'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='ssh_attack_report.html',
        help='Output file for the report'
    )
    
    parser.add_argument(
        '-t', '--threshold',
        type=int,
        default=5,
        help='Number of failed attempts to consider as an attack'
    )
    
    parser.add_argument(
        '-w', '--window',
        type=int,
        default=60,
        help='Time window in minutes to consider consecutive failures'
    )
    
    parser.add_argument(
        '-i', '--ip',
        help='Filter results for a specific IP address'
    )
    
    parser.add_argument(
        '-u', '--user',
        help='Filter results for a specific username'
    )
    
    parser.add_argument(
        '--from-date',
        help='Start date for analysis (format: YYYY-MM-DD)'
    )
    
    parser.add_argument(
        '--to-date',
        help='End date for analysis (format: YYYY-MM-DD)'
    )
    
    parser.add_argument(
        '--no-viz',
        action='store_true',
        help='Disable visualization generation'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    return parser

def main():
    """Main function to orchestrate the log analysis process"""
    parser = setup_argparse()
    args = parser.parse_args()
    
    # Set logging level based on verbosity
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    logger.info(f"Starting SSH log analysis on {args.file}")
    
    # Check if the log file exists
    if not os.path.isfile(args.file):
        logger.error(f"Log file not found: {args.file}")
        sys.exit(1)
    
    try:
        # Parse logs
        log_parser = LogParser(args.file)
        log_entries = log_parser.parse()
        
        # Apply date filters if specified
        if args.from_date:
            from_date = datetime.strptime(args.from_date, "%Y-%m-%d")
            log_entries = log_entries[log_entries['timestamp'] >= from_date]
        
        if args.to_date:
            to_date = datetime.strptime(args.to_date, "%Y-%m-%d")
            to_date = to_date.replace(hour=23, minute=59, second=59)
            log_entries = log_entries[log_entries['timestamp'] <= to_date]
        
        # Detect attacks
        detector = AttackDetector(
            threshold=args.threshold, 
            time_window_minutes=args.window
        )
        
        attack_data = detector.detect_attacks(log_entries)
        
        # Apply IP and username filters if specified
        if args.ip:
            attack_data = attack_data[attack_data['source_ip'] == args.ip]
        
        if args.user:
            attack_data = attack_data[attack_data['username'] == args.user]
        
        # Generate visualizations
        viz = None
        if not args.no_viz:
            viz = Visualizer()
            viz.prepare_visualizations(log_entries, attack_data)
        
        # Generate report
        report_gen = ReportGenerator()
        report_path = report_gen.generate_report(
            log_entries, 
            attack_data,
            viz,
            args.output,
            {
                'threshold': args.threshold,
                'window': args.window,
                'ip_filter': args.ip,
                'user_filter': args.user,
                'from_date': args.from_date,
                'to_date': args.to_date,
                'log_file': args.file,
                'analysis_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        )
        
        logger.info(f"Analysis complete! Report saved to: {report_path}")
        
        # Print summary to stdout
        total_attacks = len(attack_data)
        total_unique_ips = attack_data['source_ip'].nunique() if not attack_data.empty else 0
        
        print("\n===== SSH Attack Analysis Summary =====")
        print(f"Log file analyzed: {args.file}")
        print(f"Attack threshold: {args.threshold} attempts within {args.window} minutes")
        print(f"Total attack patterns detected: {total_attacks}")
        print(f"Unique attacking IPs: {total_unique_ips}")
        print(f"Detailed report saved to: {report_path}")
        print("=====================================\n")
        
    except Exception as e:
        logger.error(f"Error during analysis: {str(e)}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
