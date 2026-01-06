from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from pymongo import MongoClient
from bson import ObjectId
from datetime import datetime
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps

from dotenv import load_dotenv
import os

load_dotenv()

from mangum import Mangum

app = Flask(__name__, template_folder="../templates", static_folder="../static")
app.secret_key = secrets.token_hex(32)

MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client['url_shortener_db']
urls_collection = db['urls']
otps_collection = db['otps']

# Admin password
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL')

SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = os.getenv('SMTP_PORT')
SMTP_EMAIL = os.getenv('SMTP_EMAIL')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')

def send_otp_email(otp):
    """Send OTP to admin email"""
    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_EMAIL
        msg['To'] = ADMIN_EMAIL
        msg['Subject'] = 'URL Shortener Admin Login OTP'
        
        body = f'Your OTP for admin login is: {otp}\n\nThis OTP is valid for 10 minutes.'
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_EMAIL, SMTP_PASSWORD)
        text = msg.as_string()
        server.sendmail(SMTP_EMAIL, ADMIN_EMAIL, text)
        server.quit()
        return True
    except Exception as e:
        print(f"Error sending OTP: {e}")
        return False

def login_required(f):
    """Decorator to require admin login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    """Main page - show 404 when no short URL"""
    return render_template('not_found.html'), 404

@app.route('/<short_url>')
def redirect_url(short_url):
    """Redirect short URL to destination"""
    url_doc = urls_collection.find_one({'short_url': short_url})
    
    if url_doc:
        # Update click count
        urls_collection.update_one(
            {'_id': url_doc['_id']},
            {
                '$inc': {'clicks': 1},
                '$set': {'last_accessed': datetime.utcnow()}
            }
        )
        return redirect(url_doc['destination_url'])
    
    return render_template('not_found.html'), 404

# Admin routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login page"""
    if request.method == 'POST':
        password = request.form.get('password')
        
        if password == ADMIN_PASSWORD:
            # Generate OTP
            otp = secrets.token_hex(3).upper()  # 6-character OTP
            
            # Store OTP in database
            otps_collection.delete_many({})  # Clear old OTPs
            otps_collection.insert_one({
                'otp': otp,
                'created_at': datetime.utcnow()
            })
            
            # Send OTP
            if send_otp_email(otp):
                session['otp_verified'] = False
                flash('OTP sent to your device!', 'success')
                return redirect(url_for('verify_otp'))
            else:
                flash('Error sending OTP. Check device configuration.', 'error')
        else:
            flash('Invalid password', 'error')
    
    return render_template('admin_login.html')

@app.route('/admin/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    """Verify OTP page"""
    if request.method == 'POST':
        entered_otp = request.form.get('otp', '').upper()
        
        # Check OTP from database
        stored_otp = otps_collection.find_one()
        
        if stored_otp and stored_otp['otp'] == entered_otp:
            # Check if OTP is still valid (10 minutes)
            time_diff = (datetime.utcnow() - stored_otp['created_at']).total_seconds()
            if time_diff < 600:  # 10 minutes
                session['admin_logged_in'] = True
                otps_collection.delete_many({})  # Clear OTP
                return redirect(url_for('admin_dashboard'))
            else:
                flash('OTP expired. Please login again.', 'error')
                return redirect(url_for('admin_login'))
        else:
            flash('Invalid OTP', 'error')
    
    return render_template('verify_otp.html')

@app.route('/admin/logout')
def admin_logout():
    """Logout admin"""
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
def admin_dashboard():
    """Admin dashboard"""
    urls = list(urls_collection.find().sort('created_at', -1))
    return render_template('admin_dashboard.html', urls=urls)

@app.route('/admin/url/create', methods=['POST'])
@login_required
def create_url():
    """Create new short URL"""
    short_url = request.form.get('short_url', '').strip()
    destination_url = request.form.get('destination_url', '').strip()
    
    if not destination_url:
        flash('Destination URL is required', 'error')
        return redirect(url_for('admin_dashboard'))
    
    # Add http:// if no protocol specified
    if not destination_url.startswith(('http://', 'https://')):
        destination_url = 'https://' + destination_url
    
    # Check if short URL already exists
    if short_url and urls_collection.find_one({'short_url': short_url}):
        flash(f'Short URL "{short_url}" already exists', 'error')
        return redirect(url_for('admin_dashboard'))
    
    # Generate short URL if not provided
    if not short_url:
        short_url = secrets.token_hex(2)  # 4-character hex
        # Ensure uniqueness
        while urls_collection.find_one({'short_url': short_url}):
            short_url = secrets.token_hex(2)
    
    urls_collection.insert_one({
        'short_url': short_url,
        'destination_url': destination_url,
        'clicks': 0,
        'created_at': datetime.utcnow(),
        'last_accessed': None
    })
    
    flash(f'Short URL created: x.aadi.zip/{short_url}', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/url/<url_id>/edit', methods=['POST'])
@login_required
def edit_url(url_id):
    """Edit URL"""
    short_url = request.form.get('short_url', '').strip()
    destination_url = request.form.get('destination_url', '').strip()
    
    if not short_url or not destination_url:
        flash('Both fields are required', 'error')
        return redirect(url_for('admin_dashboard'))
    
    # Add http:// if no protocol specified
    if not destination_url.startswith(('http://', 'https://')):
        destination_url = 'https://' + destination_url
    
    # Check if new short URL conflicts with another entry
    existing = urls_collection.find_one({
        'short_url': short_url,
        '_id': {'$ne': ObjectId(url_id)}
    })
    
    if existing:
        flash(f'Short URL "{short_url}" already exists', 'error')
        return redirect(url_for('admin_dashboard'))
    
    urls_collection.update_one(
        {'_id': ObjectId(url_id)},
        {'$set': {
            'short_url': short_url,
            'destination_url': destination_url
        }}
    )
    
    flash('URL updated successfully', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/url/<url_id>/delete', methods=['POST'])
@login_required
def delete_url(url_id):
    """Delete URL"""
    urls_collection.delete_one({'_id': ObjectId(url_id)})
    flash('URL deleted successfully', 'success')
    return redirect(url_for('admin_dashboard'))

# API endpoint to generate random short URL
@app.route('/api/generate-short-url')
@login_required
def generate_short_url():
    """Generate a random 4-character short URL"""
    short_url = secrets.token_hex(2)  # 4-character hex
    
    # Ensure uniqueness
    while urls_collection.find_one({'short_url': short_url}):
        short_url = secrets.token_hex(2)
    
    return jsonify({'short_url': short_url})

handler = Mangum(app)

# if __name__ == '__main__':
#     app.run(debug=True, port=5001)