# SSH Log Analyzer

A Python-based tool for analyzing SSH authentication logs to detect and report potential brute-force attacks.

## Features

- Parses `/var/log/auth.log` files for failed SSH login attempts
- Detects patterns indicating potential brute-force attacks
- Generates comprehensive HTML reports with attack statistics
- Visualizes attack patterns (source IPs, timestamps, frequency)
- Filters and searches for specific attack vectors
- Command-line interface for analysis operations

## Requirements

- Python 3.6+
- pandas for data manipulation
- matplotlib/seaborn for visualization
- (Installation via pip: `pip install pandas matplotlib seaborn`)

## Usage

Basic usage:

```bash
python ssh_log_analyzer.py
