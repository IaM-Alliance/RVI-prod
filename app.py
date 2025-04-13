import os
import logging
import uuid
import json
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, request, abort, send_from_directory, jsonify
from markupsafe import Markup, escape
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import secrets
import string

# Setup logging
# Use INFO level for production (less verbose than DEBUG)
logging_level = logging.INFO if not os.environ.get("FLASK_DEBUG") else logging.DEBUG
logging.basicConfig(
    level=logging_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", secrets.token_hex(16))

# Explicitly set debug mode to False for production
# Can be overridden with FLASK_DEBUG environment variable
app.config['DEBUG'] = False

app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)  # needed for url_for to generate with https

# Initialize rate limiter with more robust settings for production
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["1000 per day", "300 per hour", "30 per minute"],
    storage_uri="memory://",  # In production, consider using redis or memcached
    strategy="moving-window",  # More accurate than fixed-window
    headers_enabled=True,  # Send rate limit headers
    swallow_errors=True,  # Don't fail if rate limiter fails
    default_limits_per_method=True  # Apply rate limits per HTTP method
)

# Configure the database
db_url = os.environ.get("DATABASE_URL")
if db_url and db_url.startswith("postgres://"):
    # Fix for SQLAlchemy 1.4+ compatibility
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,  # Recycle connections after 5 minutes of inactivity
    "pool_pre_ping": True,  # Verify connections before use to avoid stale connections
    "pool_size": 10,  # Increase connection pool size for production
    "max_overflow": 20,  # Allow up to 20 additional connections in high-load situations
    "pool_timeout": 30  # Connection timeout in seconds
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Configure upload settings
app.config["UPLOAD_FOLDER"] = "uploads/evidence"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 megabytes max upload size
app.config["ALLOWED_EXTENSIONS"] = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}

# Initialize the database
db.init_app(app)

# Ensure upload directory exists and has proper permissions
upload_dir = app.config["UPLOAD_FOLDER"]
if not os.path.exists(upload_dir):
    try:
        os.makedirs(upload_dir, mode=0o750, exist_ok=True)
        logger.info(f"Created upload directory: {upload_dir}")
    except Exception as e:
        logger.error(f"Failed to create upload directory: {str(e)}")

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'danger'

# Import models after db initialization
from models import User, AuditLog, MatrixToken, VettingForm, VettingEvidence, UserPreferences

# Add secure headers to all responses
@app.after_request
def add_security_headers(response):
    # Content Security Policy - Allow needed CDNs
    csp_policy = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net https://code.jquery.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.replit.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data:; "
        "font-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "connect-src 'self'; "
        "frame-ancestors 'self'; "  # Prevent embedding in iframes outside your domain
        "base-uri 'self'; "  # Restrict base tag
        "form-action 'self'; "  # Restrict form submissions
        "object-src 'none'; "  # Block plugins
        "upgrade-insecure-requests; "  # Force HTTPS
    )
    
    # Get domain name from request for production use
    domain = request.host.split(':')[0] if request.host else None
    if domain and domain != 'localhost' and domain != '127.0.0.1':
        # Add report-uri for production
        csp_policy += f"report-uri /csp-report;"
    
    response.headers['Content-Security-Policy'] = csp_policy
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # XSS Protection
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Click-jacking protection
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # Strict Transport Security (only in production)
    if not app.debug:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # Referrer Policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # Feature Policy
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    
    return response

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Import forms
from forms import LoginForm, ChangePasswordForm, UserRegistrationForm, MatrixRegistrationForm, VettingFormClass, UserPreferencesForm

from utils import generate_random_password, send_account_notification

# Helper functions for file uploads
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def save_evidence_file(file, form_id, notes=None):
    """Save an evidence file and return the VettingEvidence object"""
    if not file or file.filename == '':
        return None
    
    if not allowed_file(file.filename):
        flash(f'File type not allowed for {file.filename}', 'danger')
        return None
    
    # Create a unique filename
    filename = secure_filename(file.filename)
    unique_filename = f"{uuid.uuid4().hex}_{filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    
    # Save the file
    try:
        file.save(file_path)
        
        # Create evidence record
        evidence = VettingEvidence(
            vetting_form_id=form_id,
            filename=filename,
            file_path=file_path,
            file_type=file.content_type if hasattr(file, 'content_type') else None,
            file_size=len(file.read()) if hasattr(file, 'read') else None,
            notes=notes
        )
        
        # Reset file position after reading for size
        if hasattr(file, 'seek'):
            file.seek(0)
        
        return evidence
    except Exception as e:
        logger.error(f"Error saving file: {str(e)}")
        flash(f'Error saving file: {str(e)}', 'danger')
        return None

# Custom filters
@app.template_filter('datetime_format')
def datetime_format(value, format='%Y-%m-%d %H:%M:%S'):
    if value is None:
        return ""
    return value.strftime(format)

@app.template_filter('timestamp_format')
def timestamp_format(value, format='%Y-%m-%d %H:%M:%S'):
    """Format a Unix timestamp to human-readable date."""
    if not value:
        return "Unknown"
    try:
        # Convert Unix timestamp to datetime
        dt = datetime.fromtimestamp(int(value))
        return dt.strftime(format)
    except (ValueError, TypeError) as e:
        logger.error(f"Error formatting timestamp {value}: {str(e)}")
        return "Invalid timestamp"

@app.template_filter('nl2br')
def nl2br(value):
    if value:
        return Markup(value.replace('\n', '<br>'))

# Context processors
@app.context_processor
def inject_current_year():
    return {'current_year': datetime.utcnow().year}

@app.context_processor
def inject_pending_forms():
    try:
        if hasattr(current_user, 'is_authenticated') and current_user.is_authenticated:
            if hasattr(current_user, 'is_superadmin') and (current_user.is_superadmin() or current_user.is_server_admin()):
                try:
                    pending_forms = VettingForm.query.filter_by(status='submitted').count()
                    return {'pending_forms': pending_forms}
                except Exception as e:
                    logger.error(f"Error getting pending forms: {str(e)}")
                    return {'pending_forms': 0}
    except Exception as e:
        logger.error(f"Error in inject_pending_forms: {str(e)}")
    return {'pending_forms': 0}

# Create routes
@app.route('/csp-report', methods=['POST'])
def csp_report():
    """Endpoint to receive CSP violation reports"""
    try:
        # Accept both JSON and form data submissions
        content_type = request.headers.get('Content-Type', '')
        if 'application/json' in content_type:
            data = request.get_json(silent=True)
            if data:
                report_data = data.get('csp-report', {})
            else:
                report_data = {'error': 'Empty JSON data'}
        elif 'application/csp-report' in content_type:
            # Some browsers use this content type
            try:
                report_data = json.loads(request.data.decode('utf-8')).get('csp-report', {})
            except:
                report_data = {'error': 'Invalid CSP report format'}
        else:
            # Fall back to raw data for any other content type
            report_data = {'raw': request.data.decode('utf-8', errors='replace')}
        
        # Log CSP violations
        logger.warning(f"CSP Violation: {json.dumps(report_data)}")
        return jsonify({'status': 'received'}), 204
    except Exception as e:
        logger.error(f"Error processing CSP report: {str(e)}")
        return jsonify({'status': 'error'}), 500

@app.route('/')
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    if current_user.needs_password_change:
        flash('Please change your temporary password before continuing.', 'warning')
        return redirect(url_for('change_password'))
    
    if current_user.is_superadmin() or current_user.is_server_admin():
        return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('agent_dashboard'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute; 20 per hour")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            
            # Log the login event
            log_entry = AuditLog(
                user_id=user.id,
                action="login",
                details=f"User logged in from IP: {request.remote_addr}",
                ip_address=request.remote_addr
            )
            db.session.add(log_entry)
            
            # Update last login time
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            next_page = request.args.get('next')
            if not next_page or not next_page.startswith('/'):
                next_page = url_for('index')
                
            return redirect(next_page)
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    # Log the logout event
    log_entry = AuditLog(
        user_id=current_user.id,
        action="logout",
        details=f"User logged out from IP: {request.remote_addr}",
        ip_address=request.remote_addr
    )
    db.session.add(log_entry)
    db.session.commit()
    
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
@limiter.limit("3 per minute; 10 per hour")
def change_password():
    form = ChangePasswordForm()
    
    if form.validate_on_submit():
        if check_password_hash(current_user.password_hash, form.current_password.data):
            current_user.password_hash = generate_password_hash(form.new_password.data)
            current_user.needs_password_change = False
            
            # Log the password change
            log_entry = AuditLog(
                user_id=current_user.id,
                action="password_change",
                details="User changed their password",
                ip_address=request.remote_addr
            )
            db.session.add(log_entry)
            db.session.commit()
            
            flash('Your password has been updated.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Current password is incorrect.', 'danger')
    
    return render_template('change_password.html', form=form)

@app.route('/user-preferences', methods=['GET', 'POST'])
@login_required
def user_preferences():
    # Check if user has preferences, create if they don't
    if not current_user.preferences:
        new_preferences = UserPreferences(user_id=current_user.id)
        db.session.add(new_preferences)
        db.session.commit()
        db.session.refresh(current_user)
    
    form = UserPreferencesForm()
    
    # On GET, populate form with current preferences
    if request.method == 'GET':
        form.theme.data = current_user.preferences.theme
        form.animation_enabled.data = current_user.preferences.animation_enabled
        form.tooltip_enabled.data = current_user.preferences.tooltip_enabled
        
        # Populate token colors
        token_colors = current_user.preferences.get_token_colors()
        form.token_available_color.data = token_colors.get('available', 'bg-info')
        form.token_used_color.data = token_colors.get('used', 'bg-success')
        form.token_pending_color.data = token_colors.get('pending', 'bg-warning')
        form.token_expired_color.data = token_colors.get('expired', 'bg-danger')
        form.token_error_color.data = token_colors.get('error', 'bg-danger')
        
        # Populate role colors
        role_colors = current_user.preferences.get_role_colors()
        form.superadmin_color.data = role_colors.get('superadmin', 'bg-danger')
        form.server_admin_color.data = role_colors.get('server_admin', 'bg-warning')
        form.inviting_admin_color.data = role_colors.get('inviting_admin', 'bg-primary')
        form.vetting_agent_color.data = role_colors.get('vetting_agent', 'bg-info')
        
        # Populate status colors
        status_colors = current_user.preferences.get_status_colors()
        form.active_status_color.data = status_colors.get('active', 'bg-success')
        form.pending_status_color.data = status_colors.get('pending', 'bg-warning')
        form.awaiting_token_status_color.data = status_colors.get('awaiting_token', 'bg-info')
        form.rejected_status_color.data = status_colors.get('rejected', 'bg-danger')
        form.draft_status_color.data = status_colors.get('draft', 'bg-secondary')
        form.submitted_status_color.data = status_colors.get('submitted', 'bg-primary')
    
    # On POST, save the preferences
    if form.validate_on_submit():
        # Update theme and option preferences
        current_user.preferences.theme = form.theme.data
        current_user.preferences.animation_enabled = form.animation_enabled.data
        current_user.preferences.tooltip_enabled = form.tooltip_enabled.data
        
        # Update token colors
        token_colors = {
            'available': form.token_available_color.data,
            'used': form.token_used_color.data,
            'pending': form.token_pending_color.data,
            'expired': form.token_expired_color.data,
            'error': form.token_error_color.data
        }
        current_user.preferences.token_colors = json.dumps(token_colors)
        
        # Update role colors
        role_colors = {
            'superadmin': form.superadmin_color.data,
            'server_admin': form.server_admin_color.data,
            'inviting_admin': form.inviting_admin_color.data,
            'vetting_agent': form.vetting_agent_color.data
        }
        current_user.preferences.role_colors = json.dumps(role_colors)
        
        # Update status colors
        status_colors = {
            'active': form.active_status_color.data,
            'pending': form.pending_status_color.data,
            'awaiting_token': form.awaiting_token_status_color.data,
            'rejected': form.rejected_status_color.data,
            'draft': form.draft_status_color.data,
            'submitted': form.submitted_status_color.data
        }
        current_user.preferences.status_colors = json.dumps(status_colors)
        
        # Update last modified timestamp (handled by onupdate)
        
        # Log the preference change
        log_entry = AuditLog(
            user_id=current_user.id,
            action="preferences_updated",
            details="User updated their preferences",
            ip_address=request.remote_addr
        )
        db.session.add(log_entry)
        db.session.commit()
        
        flash('Your preferences have been updated.', 'success')
        return redirect(url_for('user_preferences'))
    
    return render_template('user_preferences.html', form=form)

# File routes
@app.route('/uploads/evidence/<filename>')
@login_required
def serve_evidence_file(filename):
    """Serve an evidence file securely"""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/agent/evidence/<int:evidence_id>/info', methods=['GET'])
@login_required
def evidence_info(evidence_id):
    """Debug information about an evidence file"""
    evidence = VettingEvidence.query.get_or_404(evidence_id)
    vetting_form = VettingForm.query.get(evidence.vetting_form_id)
    
    if not vetting_form or (vetting_form.user_id != current_user.id and not current_user.is_server_admin()):
        abort(403)
    
    info = {
        'id': evidence.id,
        'filename': evidence.filename,
        'vetting_form_id': evidence.vetting_form_id,
        'file_path': evidence.file_path,
        'exists': os.path.exists(evidence.file_path),
        'form_status': vetting_form.status,
        'user_is_owner': vetting_form.user_id == current_user.id,
        'user_is_admin': current_user.is_server_admin()
    }
    
    return jsonify(info)

@app.route('/agent/evidence/<int:evidence_id>/delete', methods=['POST'])
@login_required
def delete_evidence_file(evidence_id):
    """Delete an evidence file"""
    # Log the request for debugging
    logger.debug(f"Delete request for evidence ID: {evidence_id}")
    logger.debug(f"POST data: {request.form}")
    
    evidence = VettingEvidence.query.get_or_404(evidence_id)
    logger.debug(f"Found evidence record: ID={evidence.id}, File={evidence.filename}")
    
    # Verify ownership or admin rights
    vetting_form = VettingForm.query.get(evidence.vetting_form_id)
    if not vetting_form:
        logger.error(f"Vetting form not found for ID: {evidence.vetting_form_id}")
        abort(404)
        
    logger.debug(f"Vetting form: ID={vetting_form.id}, User={vetting_form.user_id}, Current user={current_user.id}")
    
    if vetting_form.user_id != current_user.id and not current_user.is_server_admin():
        logger.warning(f"Permission denied for user {current_user.id} to delete evidence {evidence_id}")
        abort(403)
    
    # Check if the form is editable
    if vetting_form.status in ['approved', 'rejected']:
        flash('You cannot delete evidence from a processed form.', 'warning')
        return redirect(url_for('edit_vetting_form', form_id=evidence.vetting_form_id))
    
    # Delete the file from filesystem
    try:
        if os.path.exists(evidence.file_path):
            logger.debug(f"Removing file from disk: {evidence.file_path}")
            os.remove(evidence.file_path)
        else:
            logger.warning(f"File not found on disk: {evidence.file_path}")
    except Exception as e:
        logger.error(f"Error deleting file: {str(e)}")
    
    # Log the deletion
    log_entry = AuditLog(
        user_id=current_user.id,
        action="evidence_deleted",
        details=f"Deleted evidence file: {evidence.filename} from vetting form ID: {evidence.vetting_form_id} (ID: {evidence.id})",
        ip_address=request.remote_addr
    )
    db.session.add(log_entry)
    
    # Delete the database record
    form_id = evidence.vetting_form_id
    try:
        logger.debug(f"Deleting evidence record from database: {evidence.id}")
        db.session.delete(evidence)
        db.session.commit()
        logger.debug("Database commit successful")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Database error during deletion: {str(e)}")
        flash(f'Error deleting file: {str(e)}', 'danger')
        return redirect(url_for('edit_vetting_form', form_id=form_id))
    
    flash(f'Evidence file "{evidence.filename}" deleted successfully.', 'success')
    return redirect(url_for('edit_vetting_form', form_id=form_id))

# Admin Routes
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not (current_user.is_superadmin() or current_user.is_server_admin()):
        abort(403)
    
    user_count = User.query.count()
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
    recent_tokens = MatrixToken.query.order_by(MatrixToken.created_at.desc()).limit(10).all()
    pending_forms = VettingForm.query.filter_by(status='submitted').count()
    awaiting_token_forms = 0
    
    # Only count awaiting_token_forms for inviting_admin and above
    if current_user.is_inviting_admin():
        awaiting_token_forms = VettingForm.query.filter_by(status='awaiting_token').count()
    
    return render_template('admin/dashboard.html', 
                          user_count=user_count, 
                          recent_logs=recent_logs,
                          recent_tokens=recent_tokens,
                          pending_forms=pending_forms,
                          awaiting_token_forms=awaiting_token_forms)

@app.route('/admin/register-user', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per hour")
def register_user():
    if not (current_user.is_superadmin() or current_user.is_server_admin()):
        abort(403)
    
    form = UserRegistrationForm()
    
    # Only show server_admin option for superadmin
    if not current_user.is_superadmin():
        form.role.choices = [
            ('vetting_agent', 'Vetting Agent'),
            ('inviting_admin', 'Inviting Admin')
        ]
    
    if form.validate_on_submit():
        # Generate a random temporary password
        temp_password = generate_random_password()
        
        # Determine registration status
        # Superadmins can create any account immediately
        # Server admins need approval for creating vetting_agent and inviting_admin accounts
        if current_user.is_superadmin() or form.role.data == 'server_admin':
            status = 'active'
            approved_by = current_user.id
            approved_at = datetime.utcnow()
        else:
            status = 'pending'
            approved_by = None
            approved_at = None
        
        # Create the new user
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=generate_password_hash(temp_password),
            role=form.role.data,
            needs_password_change=True,
            created_by=current_user.id,
            status=status,
            approved_by=approved_by,
            approved_at=approved_at
        )
        
        db.session.add(new_user)
        
        # Log the user creation
        action = "user_created" if status == 'active' else "user_created_pending"
        details = f"Created new user: {form.username.data} with role: {form.role.data}"
        if status == 'pending':
            details += " (awaiting approval)"
            
        log_entry = AuditLog(
            user_id=current_user.id,
            action=action,
            details=details,
            ip_address=request.remote_addr
        )
        db.session.add(log_entry)
        db.session.commit()
        
        # Only send notifications for active users
        if status == 'active':
            try:
                send_account_notification(
                    admin_email=current_user.email,
                    user_email=new_user.email,
                    username=new_user.username,
                    admin_name=current_user.username
                )
                flash(f'User {new_user.username} created successfully. Temporary password: {temp_password}', 'success')
                flash('Notification emails have been sent.', 'info')
            except Exception as e:
                logger.error(f"Email notification error: {str(e)}")
                flash(f'User created, but email notifications failed. Temporary password: {temp_password}', 'warning')
        else:
            flash(f'User {new_user.username} created and awaiting approval from a Superadmin or Server Admin.', 'info')
        
        return redirect(url_for('user_list'))
    
    return render_template('admin/register_user.html', form=form)

@app.route('/admin/users')
@login_required
def user_list():
    if not (current_user.is_superadmin() or current_user.is_server_admin()):
        abort(403)
    
    users = User.query.all()
    # Get count of pending users
    pending_users_count = User.query.filter_by(status='pending').count()
    
    return render_template('admin/user_list.html', users=users, pending_users_count=pending_users_count)

@app.route('/admin/approve-user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def approve_user(user_id):
    if not (current_user.is_superadmin() or current_user.is_server_admin()):
        abort(403)
    
    # Get the user to approve
    user = User.query.get_or_404(user_id)
    
    # Check if user is pending
    if user.status != 'pending':
        flash('This user is not pending approval.', 'warning')
        return redirect(url_for('user_list'))
    
    # Check if user is trying to approve their own created user
    if user.created_by == current_user.id:
        flash('You cannot approve a user you created. Another admin must approve this user.', 'warning')
        return redirect(url_for('user_list'))
    
    # Check if trying to approve a server_admin (only superadmin can do this)
    if user.role == 'server_admin' and not current_user.is_superadmin():
        flash('Only a Superadmin can approve a Server Admin account.', 'danger')
        return redirect(url_for('user_list'))
    
    if request.method == 'POST':
        action = request.form.get('action')
        notes = request.form.get('notes', '')
        
        if action not in ['approve', 'reject']:
            flash('Invalid action.', 'danger')
            return redirect(url_for('user_list'))
        
        if action == 'approve':
            user.status = 'active'
            user.approved_by = current_user.id
            user.approved_at = datetime.utcnow()
            user.approval_notes = notes
            
            # Generate a random temporary password
            temp_password = generate_random_password()
            user.password_hash = generate_password_hash(temp_password)
            
            # Log the approval
            log_entry = AuditLog(
                user_id=current_user.id,
                action="user_approved",
                details=f"Approved user: {user.username} with role: {user.role}",
                ip_address=request.remote_addr
            )
            db.session.add(log_entry)
            db.session.commit()
            
            # Send notification
            try:
                send_account_notification(
                    admin_email=current_user.email,
                    user_email=user.email,
                    username=user.username,
                    admin_name=current_user.username
                )
                flash(f'User {user.username} approved successfully. Temporary password: {temp_password}', 'success')
                flash('Notification emails have been sent.', 'info')
            except Exception as e:
                logger.error(f"Email notification error: {str(e)}")
                flash(f'User approved, but email notifications failed. Temporary password: {temp_password}', 'warning')
        else:  # reject
            user.status = 'rejected'
            user.approved_by = current_user.id
            user.approved_at = datetime.utcnow()
            user.approval_notes = notes
            
            # Log the rejection
            log_entry = AuditLog(
                user_id=current_user.id,
                action="user_rejected",
                details=f"Rejected user: {user.username} with role: {user.role}. Reason: {notes}",
                ip_address=request.remote_addr
            )
            db.session.add(log_entry)
            db.session.commit()
            
            flash(f'User {user.username} has been rejected.', 'info')
        
        return redirect(url_for('user_list'))
    
    # Pass User query to template for looking up the creator
    return render_template('admin/approve_user.html', user=user, user_query=User.query)

@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    # Only allow superadmin to delete users
    if not current_user.is_superadmin():
        abort(403)
    
    # Prevent deletion of own account
    if current_user.id == user_id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('user_list'))
    
    # Get the user to delete
    user = User.query.get_or_404(user_id)
    
    try:
        # Get the username for the log
        username = user.username
        
        # Delete all associated audit logs
        AuditLog.query.filter_by(user_id=user_id).delete()
        
        # Delete all associated tokens
        MatrixToken.query.filter_by(created_by=user_id).delete()
        
        # Delete all associated vetting forms
        vetting_forms = VettingForm.query.filter_by(user_id=user_id).all()
        for form in vetting_forms:
            # Delete associated evidence files
            VettingEvidence.query.filter_by(vetting_form_id=form.id).delete()
            
        # Now delete the vetting forms
        VettingForm.query.filter_by(user_id=user_id).delete()
        
        # Finally delete the user
        db.session.delete(user)
        
        # Log the user deletion
        log_entry = AuditLog(
            user_id=current_user.id,
            action="user_deleted",
            details=f"Deleted user: {username} with role: {user.role}",
            ip_address=request.remote_addr
        )
        db.session.add(log_entry)
        db.session.commit()
        
        flash(f'User {username} has been permanently deleted.', 'success')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting user: {str(e)}", exc_info=True)
        flash(f'Error deleting user: {str(e)}', 'danger')
    
    return redirect(url_for('user_list'))

@app.route('/admin/audit-log/<int:user_id>')
@login_required
def audit_log(user_id):
    if not (current_user.is_superadmin() or current_user.is_server_admin()):
        abort(403)
    
    user = User.query.get_or_404(user_id)
    logs = AuditLog.query.filter_by(user_id=user_id).order_by(AuditLog.timestamp.desc()).all()
    
    return render_template('admin/audit_log.html', user=user, logs=logs)

@app.route('/admin/vetting-forms')
@login_required
def admin_vetting_forms():
    if not (current_user.is_superadmin() or current_user.is_server_admin()):
        abort(403)
    
    # Get submitted vetting forms that are pending review
    pending_forms = VettingForm.query.filter_by(status='submitted').order_by(VettingForm.updated_at.desc()).all()
    
    # Get forms that are approved and awaiting token generation
    # Only inviting_admin, server_admin, and superadmin can see this
    awaiting_token_forms = []
    if current_user.is_inviting_admin():
        awaiting_token_forms = VettingForm.query.filter_by(status='awaiting_token').order_by(VettingForm.approved_at.desc()).all()
    
    # Get recently approved/rejected forms
    processed_forms = VettingForm.query.filter(
        VettingForm.status.in_(['approved', 'rejected']),
        VettingForm.approved_by.isnot(None)
    ).order_by(VettingForm.approved_at.desc()).limit(10).all()
    
    return render_template('admin/vetting_forms.html', 
                          pending_forms=pending_forms,
                          awaiting_token_forms=awaiting_token_forms,
                          processed_forms=processed_forms)

@app.route('/admin/vetting-form/<int:form_id>', methods=['GET', 'POST'])
@login_required
def admin_review_vetting_form(form_id):
    if not (current_user.is_superadmin() or current_user.is_server_admin()):
        abort(403)
    
    # Get the vetting form record
    vetting_form_record = VettingForm.query.get_or_404(form_id)
    
    # Check if the form is already processed
    if vetting_form_record.status in ['approved', 'rejected']:
        flash('This vetting form has already been processed.', 'info')
    
    # Get the agent who submitted the form
    submitter = User.query.get(vetting_form_record.user_id)
    
    # Get evidence files for this form
    evidence_files = VettingEvidence.query.filter_by(vetting_form_id=form_id).all()
    
    # Attach evidence files to form record for template access
    vetting_form_record.evidence_files = evidence_files
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action in ['approve', 'reject']:
            # Set status to 'awaiting_token' if approved, otherwise 'rejected'
            vetting_form_record.status = 'awaiting_token' if action == 'approve' else 'rejected'
            vetting_form_record.approved_by = current_user.id
            vetting_form_record.approved_at = datetime.utcnow()
            
            # Log the approval/rejection
            status_text = 'approved (awaiting token)' if action == 'approve' else 'rejected'
            log_details = f"Vetting form for {vetting_form_record.full_name} was {status_text}"
            if evidence_files:
                log_details += f" with {len(evidence_files)} evidence file(s)"
                
            log_entry = AuditLog(
                user_id=current_user.id,
                action=f"vetting_form_{action}d",
                details=log_details,
                ip_address=request.remote_addr
            )
            db.session.add(log_entry)
            db.session.commit()
            
            if action == 'approve':
                flash(f'Vetting form has been approved. The applicant is now in the queue awaiting token generation.', 'success')
            else:
                flash(f'Vetting form has been rejected.', 'success')
                
            return redirect(url_for('admin_vetting_forms'))
    
    return render_template('admin/review_vetting_form.html', 
                          form=vetting_form_record,
                          submitter=submitter)

# Agent Routes
@app.route('/agent/dashboard')
@login_required
def agent_dashboard():
    if current_user.needs_password_change:
        flash('Please change your temporary password before continuing.', 'warning')
        return redirect(url_for('change_password'))
    
    # Get tokens generated by this user
    tokens = MatrixToken.query.filter_by(created_by=current_user.id).order_by(MatrixToken.created_at.desc()).limit(10).all()
    
    # Get vetting forms submitted by this user
    vetting_forms = VettingForm.query.filter_by(user_id=current_user.id).order_by(VettingForm.updated_at.desc()).limit(10).all()
    
    return render_template('agent/dashboard.html', 
                          tokens=tokens,
                          vetting_forms=vetting_forms)

@app.route('/admin/generate-token-for-form/<int:form_id>', methods=['GET', 'POST'])
@login_required
@limiter.limit("20 per day; 5 per hour")
def generate_token_for_form(form_id):
    # Only allow inviting_admin, server_admin and superadmin
    if not current_user.is_inviting_admin():
        flash('You do not have permission to generate tokens.', 'danger')
        return redirect(url_for('index'))
        
    if current_user.needs_password_change:
        flash('Please change your temporary password before continuing.', 'warning')
        return redirect(url_for('change_password'))
    
    # Get the vetting form
    vetting_form = VettingForm.query.get_or_404(form_id)
    
    # Verify the form is awaiting token
    if vetting_form.status != 'awaiting_token':
        flash('This form is not approved for token generation.', 'warning')
        return redirect(url_for('admin_vetting_forms'))
    
    form = MatrixRegistrationForm()
    
    # Pre-fill the form with data from the vetting form
    form.full_name.data = vetting_form.full_name
    form.email.data = vetting_form.email
    
    if form.validate_on_submit():
        # Request Matrix API to generate a token
        from utils import matrix_api_post, send_token_notification
        
        # Call the API first to get a token
        result = matrix_api_post(
            user_fullname=form.full_name.data,
            user_email=form.email.data,
            assigned_username=form.assigned_username.data
        )
        
        if result["success"]:
            # Extract the token and other data from the API response
            response_data = result["response"]
            token = response_data.get("token", "")
            
            # Create token record with assigned username and API-provided data
            new_token = MatrixToken(
                token=token,
                user_fullname=form.full_name.data,
                user_email=form.email.data,
                assigned_username=form.assigned_username.data,
                created_by=current_user.id,
                status="submitted",
                response_data=json.dumps(response_data),
                response_timestamp=datetime.fromisoformat(result["response_timestamp"].rstrip('Z')),
                expiry_time=result["expiry_time"],
                expiry_date=result["expiry_date"],
                uses_allowed=1,
                vetting_form_id=vetting_form.id  # Link the token to the vetting form
            )
            
            # Update the vetting form status to approved
            vetting_form.status = 'approved'
            
            db.session.add(new_token)
            
            # Log the token generation
            log_entry = AuditLog(
                user_id=current_user.id,
                action="token_generated_from_form",
                details=f"Generated Matrix token for approved form: {form.full_name.data} ({form.email.data}), assigned username: {form.assigned_username.data}",
                ip_address=request.remote_addr
            )
            db.session.add(log_entry)
            db.session.commit()
            
            # Prepare vetting info for email notification
            vetting_info = {
                'verification_method': vetting_form.verification_method,
                'verification_date': vetting_form.verification_date.strftime('%Y-%m-%d') if vetting_form.verification_date else None,
                'verification_location': vetting_form.verification_location,
                'vetting_score': vetting_form.vetting_score,
                'vetting_notes': vetting_form.vetting_notes
            }
            
            # Send email notification to admin
            try:
                send_token_notification(
                    admin_email=current_user.email,
                    admin_name=current_user.username,
                    full_name=form.full_name.data,
                    email=form.email.data,
                    assigned_username=form.assigned_username.data,
                    token=token,
                    expiry_date=result["expiry_date"],
                    vetting_info=vetting_info
                )
                flash(f'Token successfully generated and notification email sent.', 'success')
            except Exception as e:
                logger.error(f"Email notification error: {str(e)}")
                flash(f'Token successfully generated, but email notification failed. Token: {token}, expires on: {result["expiry_date"]}', 'warning')
            
            return redirect(url_for('admin_vetting_forms'))
        else:
            # Log the failure
            error_log = AuditLog(
                user_id=current_user.id,
                action="token_generation_failed",
                details=f"Failed to generate token with Matrix API: {result['error']}",
                ip_address=request.remote_addr
            )
            db.session.add(error_log)
            db.session.commit()
            
            flash('Failed to generate token with Matrix API. Please try again or contact an administrator.', 'danger')
            return redirect(url_for('generate_token_for_form', form_id=form_id))
    
    return render_template('admin/generate_token_for_form.html', form=form, vetting_form=vetting_form)

@app.route('/admin/tokens')
@login_required
def token_list():
    """List all tokens with details and check their usage status"""
    # Only allow inviting_admin, server_admin and superadmin to access token list
    if not current_user.is_inviting_admin():
        flash('You do not have permission to access Token List.', 'danger')
        return redirect(url_for('index'))
        
    if current_user.needs_password_change:
        flash('Please change your temporary password before continuing.', 'warning')
        return redirect(url_for('change_password'))
    
    # Get all tokens ordered by creation date (newest first)
    tokens = MatrixToken.query.order_by(MatrixToken.created_at.desc()).all()
    
    # For each token, get the latest usage status from the Matrix API
    from utils import get_matrix_token_info
    import time
    
    token_statuses = {}
    for token_record in tokens:
        try:
            # Get token status from Matrix API
            result = get_matrix_token_info(token_record.token)
            if result['success']:
                token_statuses[token_record.token] = result['response']
            else:
                token_statuses[token_record.token] = {
                    'error': result.get('error', 'Unknown error'),
                    'pending': None,
                    'completed': None
                }
        except Exception as e:
            logger.error(f"Error getting token status for {token_record.token}: {str(e)}")
            token_statuses[token_record.token] = {
                'error': f"Exception: {str(e)}",
                'pending': None,
                'completed': None
            }
    
    # Pass current time to template for expiry checking
    current_time = int(time.time())
    
    return render_template('admin/token_list.html', 
                          tokens=tokens, 
                          token_statuses=token_statuses,
                          now=current_time)

@app.route('/agent/matrix-form', methods=['GET', 'POST'])
@login_required
@limiter.limit("20 per day; 5 per hour")
def matrix_form():
    if current_user.needs_password_change:
        flash('Please change your temporary password before continuing.', 'warning')
        return redirect(url_for('change_password'))
        
    # Only allow inviting_admin, server_admin and superadmin to access matrix registration
    if not current_user.is_inviting_admin():
        flash('You do not have permission to access Matrix registration.', 'danger')
        return redirect(url_for('agent_dashboard'))
    
    form = MatrixRegistrationForm()
    
    if form.validate_on_submit():
        # Request Matrix API to generate a token
        from utils import matrix_api_post
        
        # Call the API first to get a token
        result = matrix_api_post(
            user_fullname=form.full_name.data,
            user_email=form.email.data,
            assigned_username=form.assigned_username.data
        )
        
        if result["success"]:
            # Extract the token and other data from the API response
            response_data = result["response"]
            token = response_data.get("token", "")
            
            # Create token record with assigned username and API-provided data
            new_token = MatrixToken(
                token=token,
                user_fullname=form.full_name.data,
                user_email=form.email.data,
                assigned_username=form.assigned_username.data,
                created_by=current_user.id,
                status="submitted",
                response_data=json.dumps(response_data),
                response_timestamp=datetime.fromisoformat(result["response_timestamp"].rstrip('Z')),
                expiry_time=result["expiry_time"],
                expiry_date=result["expiry_date"],
                uses_allowed=1
            )
            
            db.session.add(new_token)
            
            # Log the token generation
            log_entry = AuditLog(
                user_id=current_user.id,
                action="token_generated",
                details=f"Generated Matrix token for: {form.full_name.data} ({form.email.data}), assigned username: {form.assigned_username.data}",
                ip_address=request.remote_addr
            )
            db.session.add(log_entry)
            db.session.commit()
            
            flash(f'Token successfully generated via Matrix API: {token}', 'success')
            flash(f'Token will expire on: {result["expiry_date"]}', 'info')
        else:
            # Log the failure
            error_log = AuditLog(
                user_id=current_user.id,
                action="token_generation_failed",
                details=f"Failed to generate token with Matrix API: {result['error']}",
                ip_address=request.remote_addr
            )
            db.session.add(error_log)
            db.session.commit()
            
            flash('Failed to generate token with Matrix API. Please try again or contact an administrator.', 'danger')
        return redirect(url_for('agent_dashboard'))
    
    return render_template('agent/matrix_form.html', form=form)

@app.route('/agent/vetting-form', methods=['GET', 'POST'])
@login_required
def vetting_form():
    if current_user.needs_password_change:
        flash('Please change your temporary password before continuing.', 'warning')
        return redirect(url_for('change_password'))
    
    form = VettingFormClass()  # Use the form class from forms.py
    
    if form.validate_on_submit():
        # Create new vetting form record
        new_form_record = VettingForm(  # Use VettingForm model from models.py
            user_id=current_user.id,
            full_name=form.full_name.data,
            email=form.email.data,
            matrix_id=form.matrix_id.data,
            phone_number=form.phone_number.data,
            identity_verified=form.identity_verified.data,
            verification_method=form.verification_method.data,
            verification_date=form.verification_date.data,
            verification_location=form.verification_location.data,
            vetting_notes=form.vetting_notes.data,
            vetting_score=int(form.vetting_score.data) if form.vetting_score.data else None,
            recommendation=form.recommendation.data,
            additional_info=form.additional_info.data,
            status='draft' if 'save_draft' in request.form else 'submitted'
        )
        
        db.session.add(new_form_record)
        db.session.commit()  # Commit to get the ID for evidence files
        
        # Process uploaded evidence files
        evidence_files_uploaded = 0
        
        # Process up to 5 evidence files
        if form.evidence_file1.data:
            evidence = save_evidence_file(form.evidence_file1.data, new_form_record.id, form.evidence_notes1.data)
            if evidence:
                db.session.add(evidence)
                evidence_files_uploaded += 1
                
        if form.evidence_file2.data:
            evidence = save_evidence_file(form.evidence_file2.data, new_form_record.id, form.evidence_notes2.data)
            if evidence:
                db.session.add(evidence)
                evidence_files_uploaded += 1
                
        if form.evidence_file3.data:
            evidence = save_evidence_file(form.evidence_file3.data, new_form_record.id, form.evidence_notes3.data)
            if evidence:
                db.session.add(evidence)
                evidence_files_uploaded += 1
                
        if form.evidence_file4.data:
            evidence = save_evidence_file(form.evidence_file4.data, new_form_record.id, form.evidence_notes4.data)
            if evidence:
                db.session.add(evidence)
                evidence_files_uploaded += 1
                
        if form.evidence_file5.data:
            evidence = save_evidence_file(form.evidence_file5.data, new_form_record.id, form.evidence_notes5.data)
            if evidence:
                db.session.add(evidence)
                evidence_files_uploaded += 1
        
        # Log the form submission
        action = "vetting_form_draft" if 'save_draft' in request.form else "vetting_form_submitted"
        details = f"Vetting form for {form.full_name.data} ({form.email.data}) {'saved as draft' if 'save_draft' in request.form else 'submitted'}"
        if evidence_files_uploaded > 0:
            details += f" with {evidence_files_uploaded} evidence file(s)"
            
        log_entry = AuditLog(
            user_id=current_user.id,
            action=action,
            details=details,
            ip_address=request.remote_addr
        )
        db.session.add(log_entry)
        db.session.commit()
        
        if 'save_draft' in request.form:
            flash(f'Vetting form saved as draft with {evidence_files_uploaded} evidence file(s).', 'info')
        else:
            flash(f'Vetting form submitted successfully with {evidence_files_uploaded} evidence file(s).', 'success')
        
        return redirect(url_for('agent_dashboard'))
    
    return render_template('agent/vetting_form.html', form=form)

@app.route('/agent/vetting-form/<int:form_id>', methods=['GET', 'POST'])
@login_required
def edit_vetting_form(form_id):
    if current_user.needs_password_change:
        flash('Please change your temporary password before continuing.', 'warning')
        return redirect(url_for('change_password'))
    
    # Get the vetting form record
    vetting_form_record = VettingForm.query.get_or_404(form_id)
    
    # Check if the current user is the owner or an admin
    if vetting_form_record.user_id != current_user.id and not current_user.is_server_admin():
        abort(403)
    
    # Check if the form is already approved
    if vetting_form_record.status in ['approved', 'rejected']:
        flash('This vetting form has already been processed and cannot be edited.', 'warning')
        return redirect(url_for('agent_dashboard'))
    
    form = VettingFormClass(obj=vetting_form_record)  # Use the same form class from forms.py
    
    if form.validate_on_submit():
        # Update the form data
        vetting_form_record.full_name = form.full_name.data
        vetting_form_record.email = form.email.data
        vetting_form_record.matrix_id = form.matrix_id.data
        vetting_form_record.phone_number = form.phone_number.data
        vetting_form_record.identity_verified = form.identity_verified.data
        vetting_form_record.verification_method = form.verification_method.data
        vetting_form_record.verification_date = form.verification_date.data
        vetting_form_record.verification_location = form.verification_location.data
        vetting_form_record.vetting_notes = form.vetting_notes.data
        vetting_form_record.vetting_score = int(form.vetting_score.data) if form.vetting_score.data else None
        vetting_form_record.recommendation = form.recommendation.data
        vetting_form_record.additional_info = form.additional_info.data
        
        if 'save_draft' in request.form:
            vetting_form_record.status = 'draft'
        elif 'submit' in request.form and vetting_form_record.status == 'draft':
            vetting_form_record.status = 'submitted'
        
        db.session.commit()  # Commit changes to the form
        
        # Process uploaded evidence files
        evidence_files_uploaded = 0
        
        # Process up to 5 evidence files
        if form.evidence_file1.data:
            evidence = save_evidence_file(form.evidence_file1.data, vetting_form_record.id, form.evidence_notes1.data)
            if evidence:
                db.session.add(evidence)
                evidence_files_uploaded += 1
                
        if form.evidence_file2.data:
            evidence = save_evidence_file(form.evidence_file2.data, vetting_form_record.id, form.evidence_notes2.data)
            if evidence:
                db.session.add(evidence)
                evidence_files_uploaded += 1
                
        if form.evidence_file3.data:
            evidence = save_evidence_file(form.evidence_file3.data, vetting_form_record.id, form.evidence_notes3.data)
            if evidence:
                db.session.add(evidence)
                evidence_files_uploaded += 1
                
        if form.evidence_file4.data:
            evidence = save_evidence_file(form.evidence_file4.data, vetting_form_record.id, form.evidence_notes4.data)
            if evidence:
                db.session.add(evidence)
                evidence_files_uploaded += 1
                
        if form.evidence_file5.data:
            evidence = save_evidence_file(form.evidence_file5.data, vetting_form_record.id, form.evidence_notes5.data)
            if evidence:
                db.session.add(evidence)
                evidence_files_uploaded += 1
        
        # Log the form update
        action = "vetting_form_updated"
        details = f"Vetting form for {form.full_name.data} ({form.email.data}) updated"
        if evidence_files_uploaded > 0:
            details += f" with {evidence_files_uploaded} new evidence file(s)"
            
        log_entry = AuditLog(
            user_id=current_user.id,
            action=action,
            details=details,
            ip_address=request.remote_addr
        )
        db.session.add(log_entry)
        db.session.commit()
        
        if 'save_draft' in request.form:
            flash(f'Vetting form saved as draft with {evidence_files_uploaded} new evidence file(s).', 'info')
        else:
            flash(f'Vetting form updated successfully with {evidence_files_uploaded} new evidence file(s).', 'success')
        
        return redirect(url_for('agent_dashboard'))
    
    # Get existing evidence files
    evidence_files = VettingEvidence.query.filter_by(vetting_form_id=form_id).all()
    
    return render_template('agent/vetting_form.html', form=form, editing=True, form_id=form_id, evidence_files=evidence_files)

# Error handlers
@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403

@app.errorhandler(404)
def page_not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('errors/500.html'), 500

# Initialize the database tables
with app.app_context():
    db.create_all()
    
    # Create superadmin user if not exists
    superadmin = User.query.filter_by(username='superadmin').first()
    if not superadmin:
        initial_password = generate_random_password()
        superadmin = User(
            username='superadmin',
            email='admin@iam-alliance.com',
            password_hash=generate_password_hash(initial_password),
            role='superadmin',
            needs_password_change=True
        )
        db.session.add(superadmin)
        db.session.commit()
        print(f"Created superadmin user with initial password: {initial_password}")
