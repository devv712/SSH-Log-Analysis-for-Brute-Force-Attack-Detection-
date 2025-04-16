from flask import Flask, render_template, request, send_file, flash, redirect, url_for
import os
import logging
import tempfile
import pandas as pd
from datetime import datetime
from werkzeug.utils import secure_filename

# Import the SSH Log Analyzer modules
from log_parser import LogParser
from attack_detector import AttackDetector
from visualizer import Visualizer
from report_generator import ReportGenerator

# Configure logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "ssh-log-analyzer-secret")

# Configure upload folder
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

ALLOWED_EXTENSIONS = {'log', 'txt'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    # Check if a file was uploaded
    if 'log_file' not in request.files:
        flash('No file selected')
        return redirect(url_for('index'))
    
    file = request.files['log_file']
    
    # If no file selected
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('index'))
    
    # Check file type
    if not allowed_file(file.filename):
        flash('Invalid file type. Only .log and .txt files allowed.')
        return redirect(url_for('index'))
    
    try:
        # Save uploaded file
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Get analysis parameters
        threshold = int(request.form.get('threshold', 5))
        time_window = int(request.form.get('time_window', 60))
        ip_filter = request.form.get('ip_filter', '')
        user_filter = request.form.get('user_filter', '')
        from_date = request.form.get('from_date', '')
        to_date = request.form.get('to_date', '')
        
        # Create temporary file for the report
        report_file = tempfile.NamedTemporaryFile(delete=False, suffix='.html').name
        
        # Process the log file
        log_parser = LogParser(file_path)
        log_entries = log_parser.parse()
        
        # Apply date filters if specified
        if from_date:
            from_date_obj = datetime.strptime(from_date, "%Y-%m-%d")
            log_entries = log_entries[log_entries['timestamp'] >= from_date_obj]
        
        if to_date:
            to_date_obj = datetime.strptime(to_date, "%Y-%m-%d")
            to_date_obj = to_date_obj.replace(hour=23, minute=59, second=59)
            log_entries = log_entries[log_entries['timestamp'] <= to_date_obj]
        
        # Detect attacks
        detector = AttackDetector(threshold=threshold, time_window_minutes=time_window)
        attack_data = detector.detect_attacks(log_entries)
        
        # Apply IP and username filters if specified
        if ip_filter:
            attack_data = attack_data[attack_data['source_ip'] == ip_filter]
        
        if user_filter:
            attack_data = attack_data[attack_data['username'] == user_filter]
        
        # Generate visualizations
        viz = Visualizer()
        viz.prepare_visualizations(log_entries, attack_data)
        
        # Generate report
        report_gen = ReportGenerator()
        report_path = report_gen.generate_report(
            log_entries, 
            attack_data,
            viz,
            report_file,
            {
                'threshold': threshold,
                'window': time_window,
                'ip_filter': ip_filter if ip_filter else None,
                'user_filter': user_filter if user_filter else None,
                'from_date': from_date if from_date else None,
                'to_date': to_date if to_date else None,
                'log_file': file_path,
                'analysis_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        )
        
        # Get report statistics for display
        stats = {
            'total_failures': len(log_entries),
            'unique_ips': log_entries['source_ip'].nunique() if not log_entries.empty else 0,
            'unique_usernames': log_entries['username'].nunique() if not log_entries.empty else 0,
            'attack_count': len(attack_data),
            'earliest_date': log_entries['timestamp'].min().strftime('%Y-%m-%d %H:%M:%S') if not log_entries.empty else 'N/A',
            'latest_date': log_entries['timestamp'].max().strftime('%Y-%m-%d %H:%M:%S') if not log_entries.empty else 'N/A'
        }
        
        # Remove the uploaded file to save space
        os.remove(file_path)
        
        return render_template('results.html', 
                              report_path=report_path,
                              filename=os.path.basename(report_path),
                              stats=stats,
                              attack_data=attack_data.to_dict('records') if not attack_data.empty else [],
                              parameters={
                                  'threshold': threshold,
                                  'time_window': time_window,
                                  'ip_filter': ip_filter,
                                  'user_filter': user_filter,
                                  'from_date': from_date,
                                  'to_date': to_date
                              })
    
    except Exception as e:
        logger.error(f"Error analyzing log file: {str(e)}", exc_info=True)
        flash(f'Error during analysis: {str(e)}')
        return redirect(url_for('index'))

@app.route('/download/<filename>')
def download_report(filename):
    return send_file(filename, as_attachment=True)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/help')
def help_page():
    return render_template('help.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)