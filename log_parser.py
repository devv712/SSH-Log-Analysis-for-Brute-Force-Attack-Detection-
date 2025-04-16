"""
Log Parser module for SSH Log Analyzer
Handles parsing and extraction of relevant data from auth.log files
"""

import re
import pandas as pd
import logging
from datetime import datetime
import os

logger = logging.getLogger(__name__)

class LogParser:
    """
    Parser for SSH authentication logs
    Extracts failed login attempts and related information
    """
    
    def __init__(self, log_file):
        """
        Initialize the log parser
        
        Args:
            log_file (str): Path to the auth.log file
        """
        self.log_file = log_file
        
        # Regular expressions for parsing different log entry formats
        self.patterns = {
            # Failed password for <user> from <ip> port <port> ssh2
            'failed_password': re.compile(
                r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd\[\d+\]:\s+Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+).*'
            ),
            
            # authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=<ip>
            'auth_failure': re.compile(
                r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd\[\d+\]:\s+.*authentication failure.*rhost=(\S+)(?:.*user=(\S+))?'
            ),
            
            # Disconnected from invalid user <user> <ip> port <port>
            'disconnect_invalid': re.compile(
                r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd\[\d+\]:\s+Disconnected from invalid user (\S+) (\S+) port (\d+)'
            ),
            
            # Connection closed by invalid user <user> <ip> port <port>
            'connection_closed': re.compile(
                r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd\[\d+\]:\s+Connection closed by invalid user (\S+) (\S+) port (\d+)'
            ),
            
            # Invalid user <user> from <ip> port <port>
            'invalid_user': re.compile(
                r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd\[\d+\]:\s+Invalid user (\S+) from (\S+) port (\d+)'
            ),
            
            # Received disconnect from <ip> port <port>:11: [preauth]
            'received_disconnect': re.compile(
                r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd\[\d+\]:\s+Received disconnect from (\S+) port (\d+):.*\[preauth\]'
            ),
            
            # Connection closed by <ip> port <port> [preauth]
            'connection_closed_preauth': re.compile(
                r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd\[\d+\]:\s+Connection closed by (\S+) port (\d+) \[preauth\]'
            ),
            
            # Failed <method> for <user> from <ip> port <port> ssh2
            'failed_method': re.compile(
                r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd\[\d+\]:\s+Failed (\S+) for (?:invalid user )?(\S+) from (\S+) port (\d+).*'
            ),
            
            # error: maximum authentication attempts exceeded for <user> from <ip> port <port> ssh2 [preauth]
            'max_auth': re.compile(
                r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd\[\d+\]:\s+error: maximum authentication attempts exceeded for (?:invalid user )?(\S+) from (\S+) port (\d+).*'
            ),
        }
    
    def _parse_timestamp(self, timestamp_str, year=None):
        """
        Parse timestamp from log entry
        
        Args:
            timestamp_str (str): Timestamp string from log (e.g., "Jan  7 10:32:24")
            year (int, optional): Year to use (defaults to current if None)
            
        Returns:
            datetime: Parsed timestamp with year
        """
        if not year:
            # If year not specified, use current year
            year = datetime.now().year
        
        # Handle different timestamp formats
        try:
            # Try to parse timestamp with standard format
            dt = datetime.strptime(f"{year} {timestamp_str}", "%Y %b %d %H:%M:%S")
            
            # Check if date is in the future, if so use previous year
            if dt > datetime.now():
                dt = datetime.strptime(f"{year-1} {timestamp_str}", "%Y %b %d %H:%M:%S")
                
            return dt
        except ValueError:
            logger.warning(f"Failed to parse timestamp: {timestamp_str}")
            return None
    
    def parse(self):
        """
        Parse the log file and extract failed login attempts
        
        Returns:
            DataFrame: Parsed log entries with columns:
                - timestamp
                - source_ip
                - username (if available)
                - port (if available)
                - log_type
                - raw_log
        """
        logger.info(f"Parsing log file: {self.log_file}")
        
        # Check file size before reading to avoid memory issues
        file_size = os.path.getsize(self.log_file)
        logger.debug(f"Log file size: {file_size/1024/1024:.2f} MB")
        
        entries = []
        current_year = datetime.now().year
        lines_processed = 0
        
        try:
            with open(self.log_file, 'r', errors='replace') as f:
                for line in f:
                    lines_processed += 1
                    
                    # Show progress for large files
                    if lines_processed % 100000 == 0:
                        logger.debug(f"Processed {lines_processed} lines...")
                    
                    # Skip non-SSH related logs
                    if 'sshd' not in line:
                        continue
                    
                    # Try each pattern to see if it matches the current line
                    matched = False
                    
                    for pattern_type, pattern in self.patterns.items():
                        match = pattern.match(line)
                        if match:
                            matched = True
                            
                            # Extract data based on pattern type
                            if pattern_type == 'failed_password':
                                timestamp_str, username, source_ip, port = match.groups()
                                entry = {
                                    'timestamp': self._parse_timestamp(timestamp_str, current_year),
                                    'source_ip': source_ip,
                                    'username': username,
                                    'port': port,
                                    'log_type': 'failed_password',
                                    'raw_log': line.strip()
                                }
                                entries.append(entry)
                                
                            elif pattern_type == 'auth_failure':
                                timestamp_str, source_ip, username = match.groups()
                                entry = {
                                    'timestamp': self._parse_timestamp(timestamp_str, current_year),
                                    'source_ip': source_ip,
                                    'username': username if username else 'unknown',
                                    'port': 'unknown',
                                    'log_type': 'auth_failure',
                                    'raw_log': line.strip()
                                }
                                entries.append(entry)
                                
                            elif pattern_type == 'disconnect_invalid':
                                timestamp_str, username, source_ip, port = match.groups()
                                entry = {
                                    'timestamp': self._parse_timestamp(timestamp_str, current_year),
                                    'source_ip': source_ip,
                                    'username': username,
                                    'port': port,
                                    'log_type': 'disconnect_invalid',
                                    'raw_log': line.strip()
                                }
                                entries.append(entry)
                                
                            elif pattern_type == 'connection_closed':
                                timestamp_str, username, source_ip, port = match.groups()
                                entry = {
                                    'timestamp': self._parse_timestamp(timestamp_str, current_year),
                                    'source_ip': source_ip,
                                    'username': username,
                                    'port': port,
                                    'log_type': 'connection_closed',
                                    'raw_log': line.strip()
                                }
                                entries.append(entry)
                                
                            elif pattern_type == 'invalid_user':
                                timestamp_str, username, source_ip, port = match.groups()
                                entry = {
                                    'timestamp': self._parse_timestamp(timestamp_str, current_year),
                                    'source_ip': source_ip,
                                    'username': username,
                                    'port': port,
                                    'log_type': 'invalid_user',
                                    'raw_log': line.strip()
                                }
                                entries.append(entry)
                                
                            elif pattern_type == 'received_disconnect':
                                timestamp_str, source_ip, port = match.groups()
                                entry = {
                                    'timestamp': self._parse_timestamp(timestamp_str, current_year),
                                    'source_ip': source_ip,
                                    'username': 'unknown',
                                    'port': port,
                                    'log_type': 'received_disconnect',
                                    'raw_log': line.strip()
                                }
                                entries.append(entry)
                                
                            elif pattern_type == 'connection_closed_preauth':
                                timestamp_str, source_ip, port = match.groups()
                                entry = {
                                    'timestamp': self._parse_timestamp(timestamp_str, current_year),
                                    'source_ip': source_ip,
                                    'username': 'unknown',
                                    'port': port,
                                    'log_type': 'connection_closed_preauth',
                                    'raw_log': line.strip()
                                }
                                entries.append(entry)
                                
                            elif pattern_type == 'failed_method':
                                timestamp_str, method, username, source_ip, port = match.groups()
                                entry = {
                                    'timestamp': self._parse_timestamp(timestamp_str, current_year),
                                    'source_ip': source_ip,
                                    'username': username,
                                    'port': port,
                                    'log_type': f'failed_{method}',
                                    'raw_log': line.strip()
                                }
                                entries.append(entry)
                                
                            elif pattern_type == 'max_auth':
                                timestamp_str, username, source_ip, port = match.groups()
                                entry = {
                                    'timestamp': self._parse_timestamp(timestamp_str, current_year),
                                    'source_ip': source_ip,
                                    'username': username,
                                    'port': port,
                                    'log_type': 'max_auth_attempts',
                                    'raw_log': line.strip()
                                }
                                entries.append(entry)
                    
                    # For SSH-related logs that didn't match any pattern
                    if not matched and ('Failed' in line or 'Invalid' in line or 'Authentication failure' in line):
                        logger.debug(f"Unmatched SSH failure line: {line.strip()}")
            
            logger.info(f"Parsing complete. Extracted {len(entries)} relevant log entries from {lines_processed} lines.")
            
            # Create DataFrame from entries
            if entries:
                df = pd.DataFrame(entries)
                
                # Sort by timestamp
                df = df.sort_values('timestamp')
                
                # Remove entries with None timestamps
                df = df.dropna(subset=['timestamp'])
                
                return df
            else:
                logger.warning("No relevant SSH log entries found.")
                return pd.DataFrame(columns=[
                    'timestamp', 'source_ip', 'username', 'port', 'log_type', 'raw_log'
                ])
                
        except Exception as e:
            logger.error(f"Error parsing log file: {str(e)}", exc_info=True)
            raise
