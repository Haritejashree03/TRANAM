from fileinput import filename
from flask import Flask, make_response, render_template, request, redirect, send_from_directory, url_for, session, flash, jsonify
import requests
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from flask_cors import CORS
import random
import secrets
import os, shutil
from datetime import datetime, timedelta
from models import AlertHistory, Guardian, SystemSetting, Video, db, User, Admin, Notification
import sqlite3
import threading
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from urllib.parse import urlencode

def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
        
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret')
app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", 'sqlite:///' + os.path.join(BASE_DIR, 'women_safety.db'))
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'static', 'uploads', 'profile_pics')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['VIDEOS_FOLDER'] = 'static/videos'

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'pavaniharitejashree@gmail.com'  # replace with your email
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')      # use App Password (not your real password)
app.config['MAIL_DEFAULT_SENDER'] = ('TRANAM', 'pavaniharitejashree@gmail.com')

mail = Mail(app)
app.config['MAIL_DEBUG'] = True

# Create videos directory if it doesn't exist
os.makedirs(app.config['VIDEOS_FOLDER'], exist_ok=True)

# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Allowed file extensions for profile pictures
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

CORS(app)
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.context_processor
def inject_user_data():
    """Provide logged-in user data globally"""
    current_user = None
    profile_image = url_for('static', filename='images/default-profile.png')

    if 'user_id' in session and session.get('user_type') == 'user':
        current_user = User.query.get(session['user_id'])
        if current_user and current_user.profile_pic:
            profile_image = url_for('static', filename=f'uploads/profile_pics/{current_user.profile_pic}')

    return dict(current_user=current_user, profile_image=profile_image)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def initialize_database():
    """Initialize the database with required tables and default admin user"""
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Check if admin user already exists
        admin = Admin.query.filter_by(username='admin').first()
        if not admin:
            # Create default admin user
            default_admin = Admin(
                username='admin',
                password=generate_password_hash('admin123')
            )
            db.session.add(default_admin)
            db.session.commit()
            print("Default admin user created: username='admin', password='admin123'")
        
        # Check if we have any sample users for testing (optional)
        if User.query.count() == 0:
            print("No users found in database. You can register new users through the application.")
        
        print("Database initialized successfully!")

# Initialize database when app starts
initialize_database()
verification_store = {}

def to_ist(utc_dt):
    if utc_dt is None:
        return None
    return utc_dt + timedelta(hours=5, minutes=30)

@app.route('/')
def index():
    # Always start with splash
    return redirect(url_for('splash'))


@app.route('/splash')
def splash():
    # Always show splash, then JS inside splash.html will decide where to go
    return render_template('splash.html')


@app.route('/onboarding')
def onboarding():
    # Auto-skip onboarding if user already visited or logged in
    if request.cookies.get('seen_onboarding'):
        # If already logged in, go directly to dashboard
        if 'user_type' in session:
            if session['user_type'] == 'user':
                return redirect(url_for('user_dashboard'))
            elif session['user_type'] == 'admin':
                return redirect(url_for('admin_dashboard'))
        # Otherwise go to login page
        return redirect(url_for('user_login'))

    # Show onboarding and mark as seen
    response = make_response(render_template('onboarding.html'))
    response.set_cookie('seen_onboarding', 'true', max_age=60*60*24*30)  # Remember for 30 days
    return response

# User Routes

@app.route('/user/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_type'] = 'user'
            flash('Login successful!', 'success')
            return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid email or password', 'danger')
    
    return render_template('user/login.html')

@app.route('/user/register', methods=['GET', 'POST'])
def user_register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        guardian_no = request.form['guardian_no']
        address = request.form['address']
        gender = request.form['gender']
        password = request.form['password']
        confirm_password = request.form.get('confirm_password')
        
        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('user/register.html')
        
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return render_template('user/register.html')
        
        # Handle profile picture upload
        profile_pic = None
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                profile_pic = filename
        
        # Create new user
        new_user = User(
            name=name,
            email=email,
            phone=phone,
            guardian_no=guardian_no,
            address=address,
            gender=gender,
            profile_pic=profile_pic,
            password=generate_password_hash(password)
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('user_login'))
    
    return render_template('user/register.html')

@app.route('/user/dashboard')
def user_dashboard():
    if 'user_id' not in session or session['user_type'] != 'user':
        return redirect(url_for('user_login'))
    
    user = User.query.get(session['user_id'])
    # Count videos (you can modify this based on your video storage logic)
    video_count = Video.query.filter_by(user_id=session['user_id']).count() 
    
    return render_template('user/dashboard.html', user=user, video_count=video_count)

@app.route('/user/videos')
def user_videos():
    if 'user_id' not in session or session['user_type'] != 'user':
        return redirect(url_for('user_login'))

    user_id = session["user_id"]

    user_folder = os.path.join("static/videos/user_" + str(user_id))

    videos = []
    allowed_ext = {".mp4", ".webm", ".avi", ".mov", ".mkv"}

    if os.path.exists(user_folder):
        for filename in os.listdir(user_folder):
            if any(filename.lower().endswith(ext) for ext in allowed_ext):

                filepath = os.path.join(user_folder, filename)

                videos.append({
                    "filename": f"user_{user_id}/{filename}",
                    "name": os.path.splitext(filename)[0].replace("_", " ").title(),
                    "duration": "0:10"  # static duration (optional)
                })

    return render_template("user/videos.html", videos=videos)

# Route to serve video files
@app.route("/videos/<int:user_id>/<filename>")
def serve_user_video(user_id, filename):
    folder = os.path.join(app.config['VIDEOS_FOLDER'], f"user_{user_id}")
    return send_from_directory(folder, filename)

# Route to download videos
@app.route('/download-video/<filename>')
def download_video(filename):
    # User must be logged in
    if 'user_id' not in session or session['user_type'] != 'user':
        return redirect(url_for('user_login'))

    user_id = session['user_id']

    # Path to user's video folder
    user_video_dir = os.path.join(app.config['VIDEOS_FOLDER'], f"user_{user_id}")

    # Full file path
    file_path = os.path.join(user_video_dir, filename)

    # Check if file exists in user's directory only
    if not os.path.exists(file_path):
        return "File not found or access denied", 404

    # Serve file as download
    return send_from_directory(user_video_dir, filename, as_attachment=True)


@app.route('/user/update-profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session or session.get('user_type') != 'user':
        return redirect(url_for('user_login'))

    user = User.query.get(session['user_id'])
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('user_dashboard'))

    # update simple fields
    user.name = request.form.get('name')
    user.phone = request.form.get('phone')
    user.gender = request.form.get('gender')
    user.address = request.form.get('address')

    # --- profile picture upload (short, absolute, safe) ---
    if 'profile_pic' in request.files:
        file = request.files['profile_pic']
        if file and file.filename:
            if not allowed_file(file.filename):
                flash("Invalid file type. Please upload PNG, JPG, JPEG, or GIF.", "danger")
                return redirect(url_for('user_dashboard'))

            # Build absolute upload dir (…/your_app/static/uploads/profile_pics)
            upload_dir = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'])
            os.makedirs(upload_dir, exist_ok=True)

            # Keep only the extension; make a short random name to avoid MAX_PATH issues
            _, ext = os.path.splitext(file.filename)
            ext = ext.lower()[:6]  # safety
            short_name = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(6)}{ext}"

            save_path = os.path.join(upload_dir, short_name)

            # Delete old file if exists (and was a real uploaded file)
            if user.profile_pic:
                old_path = os.path.join(upload_dir, user.profile_pic)
                try:
                    if os.path.isfile(old_path):
                        os.remove(old_path)
                except Exception as e:
                    # Non-fatal; just log
                    print(f"Could not remove old profile pic: {e}")

            # Save new file
            file.save(save_path)
            user.profile_pic = short_name

    db.session.commit()
    flash("Profile updated successfully!", "success")
    return redirect(url_for('user_dashboard'))

# -------------------------------
# 🧩 GUARDIAN MANAGEMENT ROUTES
# -------------------------------

@app.route('/user/guardian')
def user_guardian():
    """Display user's guardians."""
    if 'user_id' not in session or session['user_type'] != 'user':
        return redirect(url_for('user_login'))

    user = User.query.get(session['user_id'])
    guardians = Guardian.query.filter_by(user_id=user.id).order_by(Guardian.id.desc()).all()

    return render_template('user/guardian.html', user=user, guardians=guardians)


@app.route('/user/add-guardian', methods=['POST'])
def add_guardian():
    """Add a secondary guardian contact."""
    if 'user_id' not in session or session.get('user_type') != 'user':
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid data format'}), 400

    name = data.get('name')
    phone = data.get('phone')
    relationship = data.get('relationship')
    email = data.get('email')  # optional

    if not name or not phone or not relationship:
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        guardian = Guardian(
            user_id=session['user_id'],
            name=name,
            phone=phone,
            relationship=relationship,
            email=email
        )
        db.session.add(guardian)
        db.session.commit()
        print(f"✅ Guardian added: {name}, {phone}, {relationship}")
        return jsonify({'message': 'Guardian added successfully!'}), 200
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error adding guardian: {e}")
        return jsonify({'error': 'Error adding guardian to database.'}), 500
    
@app.route('/user/update-guardian/<int:guardian_id>', methods=['POST'])
def update_guardian(guardian_id):
    """Update a guardian's details."""
    if 'user_id' not in session or session['user_type'] != 'user':
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid data format'}), 400

    name = data.get('name')
    phone = data.get('phone')
    relationship = data.get('relationship')
    email = data.get('email')

    guardian = Guardian.query.get(guardian_id)

    if not guardian:
        return jsonify({'error': 'Guardian not found'}), 404

    if guardian.user_id != session['user_id']:
        return jsonify({'error': 'Permission denied'}), 403

    try:
        guardian.name = name
        guardian.phone = phone
        guardian.relationship = relationship
        guardian.email = email
        db.session.commit()
        print(f"✅ Guardian updated: {guardian.id}")
        return jsonify({'message': 'Guardian updated successfully!'}), 200

    except Exception as e:
        db.session.rollback()
        print("❌ Error updating guardian:", e)
        return jsonify({'error': 'Server error while updating guardian.'}), 500

@app.route('/user/delete-guardian/<int:guardian_id>', methods=['POST'])
def delete_guardian(guardian_id):
    """Delete a guardian contact."""
    if 'user_id' not in session or session['user_type'] != 'user':
        return jsonify({'error': 'Unauthorized'}), 403

    guardian = Guardian.query.get(guardian_id)

    if not guardian:
        return jsonify({'error': 'Guardian not found'}), 404
    if guardian.user_id != session['user_id']:
        return jsonify({'error': 'Permission denied'}), 403

    try:
        db.session.delete(guardian)
        db.session.commit()
        print(f"🗑️ Guardian deleted: {guardian.name}")
        return jsonify({'message': 'Guardian deleted successfully!'}), 200
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error deleting guardian: {e}")
        return jsonify({'error': 'Failed to delete guardian.'}), 500


# ------------------------------
# UPDATE PRIMARY GUARDIAN (USER)
# ------------------------------
@app.route('/user/update-primary-guardian', methods=['POST'])
def user_update_primary_guardian():

    if 'user_id' not in session or session.get('user_type') != 'user':
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}

    user = User.query.get(session['user_id'])

    user.guardian_name = data.get("guardian_name", user.guardian_name)
    user.guardian_no = data.get("guardian_no", user.guardian_no)
    user.guardian_email = data.get("guardian_email", user.guardian_email)

    try:
        db.session.commit()
        return jsonify({"message": "Guardian information updated successfully!"})
    except Exception as e:
        db.session.rollback()
        print("DB ERROR:", e)
        return jsonify({"error": "Database update failed"}), 500
  
@app.route('/admin/update-primary-guardian/<int:user_id>', methods=['POST'])
def admin_update_primary_guardian(user_id):
    user = User.query.get_or_404(user_id)

    user.guardian_name = request.form.get("guardian_name")
    user.guardian_no = request.form.get("guardian_no")
    user.guardian_email = request.form.get("guardian_email")

    db.session.commit()

    flash("Primary guardian updated successfully!", "success")
    return redirect(url_for("admin_user_details", user_id=user.id))
    
@app.route('/user/alert-history')
def user_alert_history():
    if 'user_id' not in session or session['user_type'] != 'user':
        return jsonify([])

    alerts = AlertHistory.query.filter_by(
        user_id=session['user_id']
    ).order_by(AlertHistory.timestamp.desc()).all()

    data = []
    for a in alerts:
        # Convert UTC → IST (+5:30)
        ist_time = a.timestamp + timedelta(hours=5, minutes=30)

        data.append({
            "alert_type": a.alert_type,
            "timestamp": ist_time.strftime("%d-%b-%Y %I:%M %p"),
            "status": a.status
        })

    return jsonify(data)


@app.route('/send-verification', methods=['POST'])
def send_verification():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'No user found with this email'}), 404

    # Generate random 6-digit code
    code = str(random.randint(100000, 999999))
    expiry = datetime.now() + timedelta(minutes=5)
    verification_store[email] = {'code': code, 'expiry': expiry}

    try:
        msg = Message('Your Women Safety App Verification Code',
                      recipients=[email])
        msg.body = f"""
Hello {user.name if hasattr(user, 'name') else 'User'},

Your verification code for resetting your password is: {code}

This code will expire in 5 minutes.

If you did not request this, please ignore this message.

- Women Safety App
        """
        threading.Thread(target=send_async_email, args=(app, msg)).start()
        return jsonify({'message': 'Verification code sent successfully!'}), 200
    except Exception as e:
        print("Email send error:", e)
        return jsonify({'error': 'Failed to send verification email.'}), 500

@app.route('/verify-code', methods=['POST'])
def verify_code():
    data = request.get_json()
    email = data.get('email')
    code = data.get('verification_code')

    if not email or not code:
        return jsonify({'error': 'Email and verification code are required'}), 400

    stored = verification_store.get(email)

    if not stored:
        return jsonify({'error': 'No verification code found for this email.'}), 404

    if datetime.now() > stored['expiry']:
        verification_store.pop(email, None)
        return jsonify({'error': 'Verification code has expired.'}), 400

    if stored['code'] != code:
        return jsonify({'error': 'Invalid verification code.'}), 400

    # Verification successful
    return jsonify({'message': 'Code verified successfully!'}), 200

@app.route('/user/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'GET':
        return render_template('user/forgot_password.html')

    if request.is_json:
        data = request.get_json()
        email = data.get('email')
        code = data.get('verification_code')
        new_password = data.get('new_password')

        stored = verification_store.get(email)
        if not stored or stored['code'] != code:
            return jsonify({'error': 'Invalid or expired verification code.'}), 400

        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'error': 'User not found.'}), 404

        user.password = generate_password_hash(new_password)
        db.session.commit()

        verification_store.pop(email, None)
        return jsonify({'message': 'Password reset successful! You can now log in.'}), 200

    return jsonify({'error': 'Invalid request.'}), 400

@app.route('/user/logout')
def user_logout():
    session.clear()
    flash('Logged out successfully', 'info')
    return redirect(url_for('user_login'))

# Admin Routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        admin = Admin.query.filter_by(username=username).first()
        if admin and check_password_hash(admin.password, password):
            session['admin_id'] = admin.id
            session['user_type'] = 'admin'
            flash('Admin login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid credentials', 'danger')
    
    return render_template('admin/login.html')

@app.route('/admin/dashboard')
def admin_dashboard():

    # Total users
    total_users = User.query.count()

    # Total notifications
    total_notifications = Notification.query.count()

    # Active users today
    today = datetime.utcnow().strftime("%Y-%m-%d")

    active_users_today = (
        User.query.filter(
            db.func.date(User.last_active) == today
        ).count()
    )

    # Pending alerts
    pending_alerts = Notification.query.filter_by(status="pending").count()

    # Solved cases
    solved_cases = Notification.query.filter_by(status="solved").count()

    return render_template(
        "admin/dashboard.html",
        total_users=total_users,
        total_notifications=total_notifications,
        active_users_today=active_users_today,
        pending_alerts=pending_alerts,
        solved_cases=solved_cases
    )

@app.route('/admin/users')
def admin_users():
    users = User.query.all()
    return render_template("admin/manage_users.html", users=users)

@app.route('/admin/settings')
def admin_settings():
    return render_template("admin/system_settings.html")

@app.route('/admin/notifications')
def admin_notifications():
    if 'admin_id' not in session or session['user_type'] != 'admin':
        return redirect(url_for('admin_login'))
    
    notifications = Notification.query.order_by(Notification.created_at.desc()).all()
    for n in notifications:
        n.ist_time = to_ist(n.created_at)
    return render_template('admin/notifications.html', notifications=notifications)

@app.route('/admin/update-notification-status/<int:notif_id>', methods=['POST'])
def update_notification_status(notif_id):
    data = request.get_json()

    new_status = data.get('status')
    if new_status not in ['pending', 'active', 'solved']:
        return jsonify({"error": "Invalid status"}), 400

    notif = Notification.query.get(notif_id)
    if not notif:
        return jsonify({"error": "Notification not found"}), 404

    # Update DB
    notif.status = new_status
    db.session.commit()

    return jsonify({"message": "Status updated successfully"}), 200

@app.route('/admin/user/<int:user_id>')
def admin_user_details(user_id):
    user = User.query.get_or_404(user_id)

    guardians_list = Guardian.query.filter_by(user_id=user_id).all()
    videos = Video.query.filter_by(user_id=user.id).order_by(Video.created_at.desc()).all()

    return render_template(
        "admin/user_details.html",
        user=user,
        guardians=guardians_list,
        videos=videos  # optional if you need preview in user details
    )

@app.route('/admin/user/<int:user_id>/media')
def admin_view_media(user_id):
    user = User.query.get_or_404(user_id)

    # Folder for this user's videos
    user_folder = os.path.join("static/videos/user_" + str(user_id))

    videos = []
    allowed_ext = {".mp4", ".webm", ".avi", ".mov", ".mkv"}

    if os.path.exists(user_folder):
        for filename in os.listdir(user_folder):
            if any(filename.lower().endswith(ext) for ext in allowed_ext):
                
                filepath = os.path.join(user_folder, filename)

                videos.append({
                    "filename": f"user_{user_id}/{filename}",
                    "name": os.path.splitext(filename)[0].replace("_", " ").title(),
                    "created_at": datetime.fromtimestamp(os.path.getmtime(filepath)),
                })

    return render_template("admin/user_videos.html", user=user, videos=videos)

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    flash('Admin logged out successfully', 'info')
    return redirect(url_for('admin_login'))

FAST2SMS_API_KEY = os.environ.get("FAST2SMS_API_KEY")

def send_sms_fast2sms(phone, message):
    try:
        url = "https://www.fast2sms.com/dev/bulkV2"

        payload = {
            "route": "v3",
            "sender_id": "TXTIND",
            "message": message,
            "language": "english",
            "flash": 0,
            "numbers": phone
        }

        headers = {
            "authorization": FAST2SMS_API_KEY,
            "Content-Type": "application/json"
        }

        response = requests.post(url, json=payload, headers=headers)
        print("📨 Fast2SMS Response:", response.text)
        return response.status_code == 200

    except Exception as e:
        print("❌ SMS ERROR:", e)
        return False
    
def send_email_alert(to_email, subject, body):
    try:
        msg = Message(subject, sender=app.config['MAIL_USERNAME'], recipients=[to_email])
        msg.body = body
        mail.send(msg)
        print("📧 Email sent to", to_email)
        return True
    except Exception as e:
        print("❌ EMAIL ERROR:", e)
        return False

# --- Reverse geocode lat/lon → human address ---
def reverse_geocode(lat, lon):
    try:
        url = "https://nominatim.openstreetmap.org/reverse"
        params = {
            "format": "jsonv2",
            "lat": str(lat),
            "lon": str(lon),
            "zoom": 18,
            "addressdetails": 1
        }
        headers = {"User-Agent": "Tranam-App/1.0"}
        r = requests.get(url, params=params, headers=headers, timeout=6)
        data = r.json()
        return data.get("display_name")
    except:
        return None


# --- Maps link helper ---
def maps_link(lat, lon):
    return f"https://www.google.com/maps/search/?api=1&query={lat},{lon}"

# API Routes for emergency notifications
@app.route('/api/emergency', methods=['POST'])
def emergency_alert():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    user = User.query.get(session['user_id'])

    # SAFELY Read Data
    data = request.get_json(silent=True) or {}

    # -------------------------------
    # 📍 LOCATION IMPROVED SECTION
    # -------------------------------

    # Prefer GPS coordinates
    lat = data.get("latitude") or data.get("lat")
    lon = data.get("longitude") or data.get("lon")

    human_location = None
    maps_url = None

    # Convert to float if sent as strings
    try:
        if lat and lon:
            lat = float(lat)
            lon = float(lon)
    except:
        lat = None
        lon = None

    if lat and lon:
        # Reverse geocode → readable location
        human_location = reverse_geocode(lat, lon)

        # Maps URL
        maps_url = maps_link(lat, lon)

    # If only text given (old behaviour)
    raw_location = data.get("location")

    # FINAL location message
    if human_location:
        location = human_location
    elif raw_location:
        location = raw_location
    else:
        location = "Unknown"

    # -------------------------------
    # 📌 END OF LOCATION SECTION
    # -------------------------------

    # 1️⃣ Save notification (Admin Dashboard)
    notification = Notification(
        user_id=user.id,
        message=f"🚨 Emergency alert from {user.name}",
        location=location,
        status="active"
    )

    # 2️⃣ Save user alert history
    alert = AlertHistory(
        user_id=user.id,
        alert_type="SOS",
        status="Sent",
        location=location
    )

    try:
        db.session.add(notification)
        db.session.add(alert)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print("⚠️ ERROR saving alert:", e)
        return jsonify({'error': 'Failed to record alert'}), 500

    # ------------------------------------------------------
    # 3️⃣ SMS & EMAIL SENDING (Primary + All Additional Guardian)
    # ------------------------------------------------------

    guardians_list = []

    # Primary guardian
    if user.guardian_no:
        guardians_list.append({
            "phone": user.guardian_no,
            "email": user.guardian_email
        })

    # Additional guardians
    extra_guardians = Guardian.query.filter_by(user_id=user.id).all()
    for g in extra_guardians:
        guardians_list.append({
            "phone": g.phone,
            "email": g.email
        })

    # MESSAGE CONTENT (Location improved)
    sms_message = f"🚨 SOS Alert!\n{user.name} needs help\nLocation: {location}"
    if maps_url:
        sms_message += f"\nMAPS: {maps_url}"

    sms_message += "\n\nPlease reach them immediately."

    email_subject = "🚨 SOS Alert Triggered!"
    email_content = (
        f"Emergency alert from {user.name}.\n"
        f"Location: {location}\n"
    )
    if maps_url:
        email_content += f"Map link: {maps_url}\n\n"
    email_content += "Please reach them immediately."

    # -------- SEND SMS --------
    try:
        SMS_API_KEY = FAST2SMS_API_KEY

        for g in guardians_list:
            if g["phone"]:

                payload = {
                    "sender_id": "TXTIND",
                    "message": sms_message,
                    "language": "english",
                    "route": "q",
                    "numbers": g["phone"]
                }

                headers = {
                    "authorization": SMS_API_KEY,
                    "accept": "application/json"
                }

                r = requests.post(
                    "https://www.fast2sms.com/dev/bulkV2",
                    json=payload,
                    headers=headers
                )

                print("\n📨 FAST2SMS RESPONSE for", g["phone"], ":")
                print(r.text)

    except Exception as e:
        print("❌ SMS ERROR:", e)

    # -------- SEND EMAIL --------
    try:
        from flask_mail import Message
        for g in guardians_list:
            if g["email"]:
                try:
                    msg = Message(email_subject, recipients=[g["email"]])
                    msg.body = email_content
                    mail.send(msg)
                    print("Email sent to", g["email"])
                except Exception as e:
                    print("❌ Email send error for", g["email"], ":", e)
    except Exception as e:
        print("❌ EMAIL SYSTEM ERROR:", e)

    return jsonify({'message': 'Emergency alert sent successfully'})


    
@app.route('/api/save-video', methods=['POST'])
def save_video():
    data = request.get_json()

    user_id = data.get("user_id")
    filename = data.get("filename")
    name = data.get("name")

    if not user_id or not filename:
        return jsonify({"error": "Missing required fields"}), 400

    try:
        video = Video(
            user_id=user_id,
            filename=filename,   # ex: "user_1/video1.mp4"
            name=name
        )
        db.session.add(video)
        db.session.commit()

        return jsonify({"message": "Video inserted"})
    except Exception as e:
        db.session.rollback()
        print("DB error:", e)
        return jsonify({"error": "DB insert failed"}), 500

@app.route("/videos/<path:filename>")
def serve_video(filename):
    return send_from_directory("static/videos", filename)

# Add a route to manually initialize database (optional)
@app.route('/init-db')
def init_db_route():
    """Route to manually initialize database (for development)"""
    initialize_database()
    flash('Database initialized successfully!', 'success')
    return redirect(url_for('index'))

@app.before_request
def global_before_request():

    # 1) UPDATE USER LAST ACTIVE
    if 'user_id' in session and session.get('user_type') == 'user':
        user = User.query.get(session['user_id'])
        if user:
            user.last_active = datetime.utcnow()
            db.session.commit()

    # 2) FORCE LOGOUT CHECK
    allowed_routes = ['login', 'static', 'user_login']
    if request.endpoint not in allowed_routes and current_user.is_authenticated:
        system_flag = SystemSetting.get("force_logout")
        if system_flag == "yes":
            logout_user()
            SystemSetting.set("force_logout", "no")
            return redirect(url_for("user_login"))

    # 2. CHECK FORCE LOGOUT
    if request.endpoint not in ['login', 'static']:
        system_flag = SystemSetting.get("force_logout")
        if system_flag == "yes":
            session.clear()
            SystemSetting.set("force_logout", "no")
            return redirect(url_for("user_login"))

def check_force_logout():
    allowed_routes = ['login', 'static']  # add others if needed

    if request.endpoint in allowed_routes:
        return

    if current_user.is_authenticated:
        system_flag = SystemSetting.get("force_logout")
        if system_flag == "yes":
            logout_user()
            SystemSetting.set("force_logout", "no")
            return redirect(url_for("user_login"))

# System Settings routes
@app.route('/admin/toggle-setting', methods=['POST'])
def toggle_setting():
    data = request.get_json()
    key = data.get("setting")

    current = SystemSetting.get(key, "off")
    new_value = "on" if current == "off" else "off"

    SystemSetting.set(key, new_value)

    return jsonify({"message": f"{key.replace('_',' ').title()} set to {new_value}"}), 200

@app.route('/admin/change-password', methods=['POST'])
def change_admin_password():
    data = request.get_json()
    new_pass = data.get("password")

    admin = User.query.filter_by(role="admin").first()
    if not admin:
        return jsonify({"error": "Admin user not found"}), 404

    admin.password = generate_password_hash(new_pass)
    db.session.commit()

    return jsonify({"message": "Password updated successfully"})

@app.route('/admin/save-smtp', methods=['POST'])
def save_smtp():
    data = request.get_json()
    SystemSetting.set("smtp_host", data.get("host"))
    SystemSetting.set("smtp_port", data.get("port"))
    SystemSetting.set("smtp_user", data.get("user"))
    SystemSetting.set("smtp_pass", data.get("pass"))

    return jsonify({"message": "SMTP settings saved"})

@app.route('/admin/save-sms', methods=['POST'])
def save_sms_settings():
    data = request.get_json()
    SystemSetting.set("sms_api_key", data.get("api"))
    SystemSetting.set("sms_sender", data.get("sender"))

    return jsonify({"message": "SMS settings saved"})

@app.route('/admin/save-gps', methods=['POST'])
def save_gps_interval():
    data = request.get_json()
    interval = data.get("interval")

    SystemSetting.set("gps_interval", interval)

    return jsonify({"message": "GPS interval updated"})

@app.route('/admin/save-sos-retry', methods=['POST'])
def save_sos_retry():
    data = request.get_json()
    retry = data.get("retry")

    SystemSetting.set("sos_retry", retry)

    return jsonify({"message": "SOS retry setting saved"})

@app.route('/admin/backup-db')
def backup_db():
    os.makedirs("backups", exist_ok=True)

    backup_name = f"women_safety_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.db"
    backup_path = os.path.join("backups", backup_name)

    shutil.copy("women_safety.db", backup_path)

    return jsonify({"message": "Backup created", "file": backup_name})

@app.route('/admin/list-backups')
def list_backups():
    os.makedirs("backups", exist_ok=True)
    files = os.listdir("backups")
    files = [f for f in files if f.endswith(".db")]
    return jsonify({"files": files})


@app.route('/admin/restore-db', methods=['POST'])
def restore_db():
    filename = request.form.get("filename")

    if not filename:
        return jsonify({"error": "No backup selected"}), 400

    backup_path = os.path.join("backups", filename)

    if not os.path.isfile(backup_path):
        return jsonify({"error": "Backup file not found"}), 404

    try:
        db.session.close()      # IMPORTANT!
        shutil.copy(backup_path, "women_safety.db")

        return jsonify({"message": f"Database restored from {filename}. Restart server to apply changes."})
    except Exception as e:
        return jsonify({"error": f"Restore failed: {str(e)}"}), 500

@app.route('/admin/clean-media')
def clean_media():
    folders = [
        "static/uploads/videos",
        "static/uploads/profile_pics",
        "logs"
    ]

    for folder in folders:
        if not os.path.isdir(folder):
            continue
        for f in os.listdir(folder):
            try:
                os.remove(os.path.join(folder, f))
            except:
                pass

    return jsonify({"message": "Old media removed"})

from flask_login import logout_user

@app.route('/admin/force-logout')
def force_logout():
    SystemSetting.set("force_logout", "yes")
    return jsonify({"message": "All users will be logged out"})
        
if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0')