from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    guardian_name = db.Column(db.String(100))
    guardian_email = db.Column(db.String(120))
    guardian_no = db.Column(db.String(15), nullable=False)
    address = db.Column(db.Text, nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    profile_pic = db.Column(db.String(200))
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    notifications = db.relationship('Notification', backref='user', lazy=True)
    videos = db.relationship('Video', backref='owner', lazy=True)
    last_active = db.Column(db.DateTime, default=datetime.utcnow)

class Guardian(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    relationship = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120))
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(200))
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Video(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))   # REQUIRED
    name = db.Column(db.String(100))
    filename = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

class SystemSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.String(200), nullable=True)

    @staticmethod
    def get(key, default=None):
        s = SystemSetting.query.filter_by(key=key).first()
        return s.value if s else default

    @staticmethod
    def set(key, value):
        s = SystemSetting.query.filter_by(key=key).first()
        if not s:
            s = SystemSetting(key=key, value=value)
            db.session.add(s)
        else:
            s.value = value
        db.session.commit()

class AlertHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    alert_type = db.Column(db.String(50))   # 'SOS', 'Test', etc.
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50))       # 'Sent', 'Delivered', 'Responded'
    location = db.Column(db.String(255))
