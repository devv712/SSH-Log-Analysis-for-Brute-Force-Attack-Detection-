"""
Attack Detector module for SSH Log Analyzer
Detects potential brute-force attacks based on patterns in log entries
"""

import pandas as pd
import numpy as np
from datetime import timedelta
import logging
import ipaddress

logger = logging.getLogger(__name__)

class AttackDetector:
    """
    Detects potential brute-force attacks based on failed login attempts
    """
    
    def __init__(self, threshold=5, time_window_minutes=60):
        """
        Initialize the attack detector
        
        Args:
            threshold (int): Number of failed attempts to consider as an attack
            time_window_minutes (int): Time window in minutes to consider consecutive failures
        """
        self.threshold = threshold
        self.time_window = timedelta(minutes=time_window_minutes)
    
    def is_valid_ip(self, ip_str):
        """
        Check if a string is a valid IP address
        
        Args:
            ip_str (str): IP address to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    def detect_attacks(self, log_entries):
        """
        Detect potential brute-force attacks in the log entries
        
        Args:
            log_entries (DataFrame): Parsed log entries from LogParser
            
        Returns:
            DataFrame: Detected attack information
        """
        if log_entries.empty:
            logger.warning("No log entries to analyze for attacks")
            return pd.DataFrame(columns=[
                'source_ip', 'username', 'start_time', 'end_time', 
                'attempt_count', 'max_frequency', 'usernames_tried', 'attack_severity'
            ])
        
        logger.info(f"Detecting attacks with threshold={self.threshold} attempts within {self.time_window.total_seconds()/60} minutes")
        
        # Filter to include only valid IPs
        valid_ip_mask = log_entries['source_ip'].apply(self.is_valid_ip)
        if not valid_ip_mask.all():
            invalid_count = (~valid_ip_mask).sum()
            logger.warning(f"Found {invalid_count} entries with invalid IP addresses, excluding them from analysis")
            log_entries = log_entries[valid_ip_mask]
        
        if log_entries.empty:
            logger.warning("No valid log entries left after filtering")
            return pd.DataFrame(columns=[
                'source_ip', 'username', 'start_time', 'end_time', 
                'attempt_count', 'max_frequency', 'usernames_tried', 'attack_severity'
            ])
        
        # Sort by timestamp to ensure chronological order
        log_entries = log_entries.sort_values('timestamp')
        
        # Group by source IP to identify potential attackers
        ip_groups = log_entries.groupby('source_ip')
        
        attack_list = []
        
        for ip, group in ip_groups:
            # Look for patterns with multiple failed attempts
            if len(group) < self.threshold:
                continue
            
            # Get timestamps for this IP
            ip_timestamps = group['timestamp'].sort_values().reset_index(drop=True)
            
            # Track attack sequences
            attack_start_idx = 0
            i = 0
            
            while i < len(ip_timestamps):
                # Look for a window of time with enough attempts
                window_end = ip_timestamps[i] + self.time_window
                
                # Find all attempts within the time window
                attempts_in_window = ip_timestamps[(ip_timestamps >= ip_timestamps[i]) & 
                                                   (ip_timestamps <= window_end)]
                
                if len(attempts_in_window) >= self.threshold:
                    # We found a potential attack pattern
                    attack_entries = group[(group['timestamp'] >= ip_timestamps[i]) & 
                                           (group['timestamp'] <= window_end)]
                    
                    # Calculate time differences between consecutive attempts
                    if len(attempts_in_window) > 1:
                        time_diffs = attempts_in_window.diff().dropna().dt.total_seconds()
                        max_frequency = 60 / time_diffs.min() if time_diffs.min() > 0 else 0  # attempts per minute
                    else:
                        max_frequency = 0
                    
                    # Calculate unique usernames tried
                    usernames = attack_entries['username'].unique().tolist()
                    username_count = len(usernames)
                    
                    # Calculate primary target username (most attempts)
                    if username_count > 0:
                        username_counts = attack_entries['username'].value_counts()
                        primary_username = username_counts.index[0]
                    else:
                        primary_username = 'unknown'
                    
                    # Determine attack severity
                    severity = self._calculate_severity(
                        attempt_count=len(attempts_in_window),
                        time_span=(attempts_in_window.max() - attempts_in_window.min()).total_seconds() / 60,
                        username_count=username_count,
                        max_frequency=max_frequency
                    )
                    
                    attack_info = {
                        'source_ip': ip,
                        'username': primary_username,
                        'start_time': attempts_in_window.min(),
                        'end_time': attempts_in_window.max(),
                        'attempt_count': len(attempts_in_window),
                        'max_frequency': max_frequency,
                        'usernames_tried': usernames,
                        'unique_username_count': username_count,
                        'attack_severity': severity
                    }
                    
                    attack_list.append(attack_info)
                    
                    # Move to the end of this attack window
                    attack_start_idx = ip_timestamps.searchsorted(window_end)
                    i = attack_start_idx
                else:
                    i += 1
        
        # Create DataFrame from attack list
        if attack_list:
            attacks_df = pd.DataFrame(attack_list)
            
            # Clean up and sort
            attacks_df = attacks_df.sort_values('start_time')
            
            # Convert usernames_tried list to comma-separated string
            attacks_df['usernames_tried'] = attacks_df['usernames_tried'].apply(lambda x: ', '.join(x))
            
            logger.info(f"Detected {len(attacks_df)} potential brute-force attacks")
            return attacks_df
        else:
            logger.info("No potential attacks detected based on current threshold and time window")
            return pd.DataFrame(columns=[
                'source_ip', 'username', 'start_time', 'end_time', 
                'attempt_count', 'max_frequency', 'usernames_tried', 
                'unique_username_count', 'attack_severity'
            ])
    
    def _calculate_severity(self, attempt_count, time_span, username_count, max_frequency):
        """
        Calculate attack severity score based on various factors
        
        Args:
            attempt_count (int): Number of login attempts
            time_span (float): Time span in minutes
            username_count (int): Number of unique usernames tried
            max_frequency (float): Maximum attempt frequency (attempts/minute)
            
        Returns:
            str: Severity level ('Low', 'Medium', 'High', 'Critical')
        """
        # Base score starts from 0
        score = 0
        
        # More attempts increase severity
        if attempt_count >= 100:
            score += 4
        elif attempt_count >= 50:
            score += 3
        elif attempt_count >= 20:
            score += 2
        elif attempt_count >= 10:
            score += 1
        
        # Short time span (high intensity) increases severity
        if time_span > 0:
            intensity = attempt_count / time_span  # attempts per minute
            if intensity >= 10:
                score += 3
            elif intensity >= 5:
                score += 2
            elif intensity >= 1:
                score += 1
        
        # Multiple usernames tried indicates a more sophisticated attack
        if username_count >= 10:
            score += 3
        elif username_count >= 5:
            score += 2
        elif username_count >= 2:
            score += 1
        
        # High frequency attempts indicate automated tools
        if max_frequency >= 30:  # more than 30 attempts per minute
            score += 3
        elif max_frequency >= 10:
            score += 2
        elif max_frequency >= 5:
            score += 1
        
        # Determine severity level based on score
        if score >= 8:
            return 'Critical'
        elif score >= 5:
            return 'High'
        elif score >= 3:
            return 'Medium'
        else:
            return 'Low'
