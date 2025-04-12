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
    
    # User approval fields
    status = db.Column(db.String(20), nullable=False, default='active')  # active, pending, rejected
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    approved_at = db.Column(db.DateTime)
    approval_notes = db.Column(db.Text)
    
    # Relationships
    audit_logs = db.relationship('AuditLog', backref='user', lazy=True)
    tokens = db.relationship('MatrixToken', backref='creator', lazy=True)
    vetting_forms = db.relationship('VettingForm', 
                                   foreign_keys='VettingForm.user_id',
                                   backref='submitted_by', 
                                   lazy=True)
    
    def is_superadmin(self):
        return self.role == 'superadmin'
    
    def is_server_admin(self):
        return self.role == 'server_admin' or self.is_superadmin()
    
    def is_vetting_agent(self):
        # Only returns true for vetting agents specifically, not for admins
        return self.role == 'vetting_agent'
    
    def is_inviting_admin(self):
        return self.role == 'inviting_admin' or self.is_superadmin() or self.is_server_admin()

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
    assigned_username = db.Column(db.String(120), nullable=False)  # Required username assigned to the user
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, submitted, failed
    response_data = db.Column(db.Text)  # To store API response JSON
    response_timestamp = db.Column(db.DateTime, nullable=True)  # When API response was received
    expiry_time = db.Column(db.BigInteger, nullable=True)  # Unix timestamp for expiry
    expiry_date = db.Column(db.String(20), nullable=True)  # Formatted date YYYY-MMM-DD
    uses_allowed = db.Column(db.Integer, default=1)
    vetting_form_id = db.Column(db.Integer, db.ForeignKey('vetting_form.id'), nullable=True)

class VettingEvidence(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vetting_form_id = db.Column(db.Integer, db.ForeignKey('vetting_form.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(512), nullable=False)
    file_type = db.Column(db.String(100), nullable=True)
    file_size = db.Column(db.Integer, nullable=True)  # Size in bytes
    notes = db.Column(db.Text, nullable=True)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<VettingEvidence {self.id}: {self.filename}>'

class VettingForm(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    status = db.Column(db.String(20), default='draft')  # draft, submitted, approved, rejected
    
    # Person details
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    matrix_id = db.Column(db.String(120), nullable=True)
    phone_number = db.Column(db.String(20), nullable=True)
    
    # Verification info
    identity_verified = db.Column(db.Boolean, default=False)
    verification_method = db.Column(db.String(50), nullable=True)  # in-person, video, trusted-referral
    verification_date = db.Column(db.DateTime, nullable=True)
    verification_location = db.Column(db.String(120), nullable=True)
    
    # Vetting information
    vetting_notes = db.Column(db.Text, nullable=True)
    vetting_score = db.Column(db.Integer, nullable=True)  # 1-5 score
    recommendation = db.Column(db.String(20), nullable=True)  # approve, reject, further-verification
    
    # Additional details (removed Security and trust information)
    additional_info = db.Column(db.Text, nullable=True)
    
    # Approval information
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    approved_at = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    approver = db.relationship('User', 
                             foreign_keys=[approved_by], 
                             backref=db.backref('approved_forms', lazy=True))
    matrix_tokens = db.relationship('MatrixToken', backref='vetting_form', lazy=True)
    evidence_files = db.relationship('VettingEvidence', backref='vetting_form', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<VettingForm {self.id}: {self.full_name}>'
