"""
Visualizer module for SSH Log Analyzer
Creates visual representations of attack patterns and statistics
"""

import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from matplotlib.dates import DateFormatter
import io
import base64
import logging
from matplotlib.ticker import MaxNLocator

logger = logging.getLogger(__name__)

class Visualizer:
    """
    Creates visualizations for SSH authentication log analysis
    """
    
    def __init__(self):
        """Initialize visualizer with default style settings"""
        sns.set_style('darkgrid')
        self.plots = {}
    
    def _fig_to_base64(self, fig):
        """
        Convert matplotlib figure to base64 encoded string for HTML embedding
        
        Args:
            fig: Matplotlib figure
            
        Returns:
            str: Base64 encoded string
        """
        buf = io.BytesIO()
        fig.savefig(buf, format='png', dpi=100, bbox_inches='tight')
        buf.seek(0)
        img_str = base64.b64encode(buf.read()).decode('utf-8')
        buf.close()
        plt.close(fig)
        return img_str
    
    def prepare_visualizations(self, log_entries, attack_data):
        """
        Create visualizations for the report
        
        Args:
            log_entries (DataFrame): Parsed log entries from LogParser
            attack_data (DataFrame): Attack information from AttackDetector
            
        Returns:
            dict: Dictionary of plot names and their base64 encoded images
        """
        logger.info("Generating visualizations...")
        
        if log_entries.empty:
            logger.warning("No log entries to visualize")
            return {}
        
        # Generate plots
        self.plots['attempts_over_time'] = self._plot_attempts_over_time(log_entries)
        self.plots['top_source_ips'] = self._plot_top_source_ips(log_entries)
        self.plots['top_usernames'] = self._plot_top_usernames(log_entries)
        self.plots['hourly_distribution'] = self._plot_hourly_distribution(log_entries)
        
        if not attack_data.empty:
            self.plots['attack_severity'] = self._plot_attack_severity(attack_data)
            self.plots['username_diversity'] = self._plot_username_diversity(attack_data)
        
        logger.info(f"Generated {len(self.plots)} visualizations")
        return self.plots
    
    def _plot_attempts_over_time(self, log_entries):
        """Plot failed login attempts over time"""
        try:
            fig, ax = plt.subplots(figsize=(12, 6))
            
            # Resample data by hour and count events
            attempts_ts = log_entries.set_index('timestamp')
            attempts_by_hour = attempts_ts.resample('1H').size()
            
            # Plot time series
            ax.plot(attempts_by_hour.index, attempts_by_hour.values, '-o', markersize=4)
            
            # Format plot
            ax.set_title('Failed Login Attempts Over Time', fontsize=16)
            ax.set_xlabel('Date and Time', fontsize=12)
            ax.set_ylabel('Number of Failed Attempts', fontsize=12)
            ax.xaxis.set_major_formatter(DateFormatter('%Y-%m-%d %H:%M'))
            plt.xticks(rotation=45)
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            
            return self._fig_to_base64(fig)
        except Exception as e:
            logger.error(f"Error creating attempts over time plot: {str(e)}", exc_info=True)
            return None
    
    def _plot_top_source_ips(self, log_entries, top_n=10):
        """Plot top source IPs with most failed attempts"""
        try:
            top_ips = log_entries['source_ip'].value_counts().nlargest(top_n)
            
            if top_ips.empty:
                logger.warning("No IP data available for visualization")
                return None
            
            fig, ax = plt.subplots(figsize=(12, 6))
            bars = ax.bar(top_ips.index, top_ips.values, color=sns.color_palette("mako", len(top_ips)))
            
            # Format plot
            ax.set_title(f'Top {top_n} Source IPs by Failed Login Attempts', fontsize=16)
            ax.set_xlabel('IP Address', fontsize=12)
            ax.set_ylabel('Number of Failed Attempts', fontsize=12)
            plt.xticks(rotation=45, ha='right')
            
            # Add count labels on bars
            for bar in bars:
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                        f'{height:.0f}', ha='center', va='bottom')
            
            plt.tight_layout()
            
            return self._fig_to_base64(fig)
        except Exception as e:
            logger.error(f"Error creating top source IPs plot: {str(e)}", exc_info=True)
            return None
    
    def _plot_top_usernames(self, log_entries, top_n=10):
        """Plot top usernames with most failed attempts"""
        try:
            # Filter out 'unknown' usernames
            filtered_entries = log_entries[log_entries['username'] != 'unknown']
            
            if filtered_entries.empty:
                logger.warning("No username data available for visualization")
                return None
            
            top_usernames = filtered_entries['username'].value_counts().nlargest(top_n)
            
            fig, ax = plt.subplots(figsize=(12, 6))
            bars = ax.bar(top_usernames.index, top_usernames.values, color=sns.color_palette("viridis", len(top_usernames)))
            
            # Format plot
            ax.set_title(f'Top {top_n} Usernames by Failed Login Attempts', fontsize=16)
            ax.set_xlabel('Username', fontsize=12)
            ax.set_ylabel('Number of Failed Attempts', fontsize=12)
            plt.xticks(rotation=45, ha='right')
            
            # Add count labels on bars
            for bar in bars:
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                        f'{height:.0f}', ha='center', va='bottom')
            
            plt.tight_layout()
            
            return self._fig_to_base64(fig)
        except Exception as e:
            logger.error(f"Error creating top usernames plot: {str(e)}", exc_info=True)
            return None
    
    def _plot_hourly_distribution(self, log_entries):
        """Plot hourly distribution of failed login attempts"""
        try:
            hourly_counts = log_entries['timestamp'].dt.hour.value_counts().sort_index()
            hours = list(range(24))
            counts = [hourly_counts.get(hour, 0) for hour in hours]
            
            fig, ax = plt.subplots(figsize=(12, 6))
            ax.bar(hours, counts, color=sns.color_palette("rocket", 24))
            
            # Format plot
            ax.set_title('Hourly Distribution of Failed Login Attempts', fontsize=16)
            ax.set_xlabel('Hour of Day (24h format)', fontsize=12)
            ax.set_ylabel('Number of Failed Attempts', fontsize=12)
            ax.set_xticks(range(0, 24, 2))
            ax.set_xlim(-0.5, 23.5)
            
            plt.tight_layout()
            
            return self._fig_to_base64(fig)
        except Exception as e:
            logger.error(f"Error creating hourly distribution plot: {str(e)}", exc_info=True)
            return None
    
    def _plot_attack_severity(self, attack_data):
        """Plot attack severity distribution"""
        try:
            if 'attack_severity' not in attack_data.columns or attack_data.empty:
                logger.warning("No attack severity data available for visualization")
                return None
            
            severity_counts = attack_data['attack_severity'].value_counts()
            
            # Define order and colors for severity levels
            severity_order = ['Low', 'Medium', 'High', 'Critical']
            severity_colors = {'Low': '#4575b4', 'Medium': '#fee090', 'High': '#fdae61', 'Critical': '#d73027'}
            
            # Filter to include only severity levels that exist in the data
            available_severities = [s for s in severity_order if s in severity_counts.index]
            ordered_counts = severity_counts.reindex(available_severities).fillna(0)
            
            colors = [severity_colors[s] for s in ordered_counts.index]
            
            fig, ax = plt.subplots(figsize=(10, 6))
            bars = ax.bar(ordered_counts.index, ordered_counts.values, color=colors)
            
            # Format plot
            ax.set_title('Attack Severity Distribution', fontsize=16)
            ax.set_xlabel('Severity Level', fontsize=12)
            ax.set_ylabel('Number of Attacks', fontsize=12)
            
            # Add count labels on bars
            for bar in bars:
                height = bar.get_height()
                if height > 0:
                    ax.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                            f'{height:.0f}', ha='center', va='bottom')
            
            plt.tight_layout()
            
            return self._fig_to_base64(fig)
        except Exception as e:
            logger.error(f"Error creating attack severity plot: {str(e)}", exc_info=True)
            return None
    
    def _plot_username_diversity(self, attack_data):
        """Plot username diversity in attacks"""
        try:
            if 'unique_username_count' not in attack_data.columns or attack_data.empty:
                logger.warning("No username diversity data available for visualization")
                return None
            
            # Group by the number of unique usernames tried
            diversity_counts = attack_data['unique_username_count'].value_counts().sort_index()
            
            fig, ax = plt.subplots(figsize=(10, 6))
            ax.bar(diversity_counts.index.astype(str), diversity_counts.values, 
                   color=sns.color_palette("mako_r", len(diversity_counts)))
            
            # Format plot
            ax.set_title('Username Diversity in Attacks', fontsize=16)
            ax.set_xlabel('Number of Unique Usernames Tried', fontsize=12)
            ax.set_ylabel('Number of Attacks', fontsize=12)
            ax.xaxis.set_major_locator(MaxNLocator(integer=True))
            
            plt.tight_layout()
            
            return self._fig_to_base64(fig)
        except Exception as e:
            logger.error(f"Error creating username diversity plot: {str(e)}", exc_info=True)
            return None
