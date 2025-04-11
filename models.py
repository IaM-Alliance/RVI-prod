from datetime import datetime
from app import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='vetting_agent')  # superadmin, server_admin, vetting_agent, inviting_admin
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    needs_password_change = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Relationships
    audit_logs = db.relationship('AuditLog', backref='user', lazy=True)
    tokens = db.relationship('MatrixToken', backref='creator', lazy=True)
    
    def is_superadmin(self):
        return self.role == 'superadmin'
    
    def is_server_admin(self):
        return self.role == 'server_admin' or self.role == 'superadmin'
    
    def is_vetting_agent(self):
        return self.role == 'vetting_agent' or 'admin' in self.role
    
    def is_inviting_admin(self):
        return self.role == 'inviting_admin' or self.role == 'superadmin' or self.role == 'server_admin'

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    action = db.Column(db.String(50), nullable=False)  # login, logout, token_generated, etc.
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(50))

class MatrixToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, nullable=False)
    user_fullname = db.Column(db.String(120), nullable=False)
    user_email = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, submitted, failed
    response_data = db.Column(db.Text)  # To store API response
