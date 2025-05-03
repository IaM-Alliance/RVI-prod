from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import StringField, PasswordField, SubmitField, SelectField, EmailField, TextAreaField, BooleanField, DateField, HiddenField, FieldList, FormField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, Optional
from models import RVIUser as User, UserPreferences

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters long')
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(),
        EqualTo('new_password', message='Passwords must match')
    ])
    submit = SubmitField('Change Password')

class UserRegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=64)
    ])
    email = EmailField('Email', validators=[
        DataRequired(),
        Email()
    ])
    role = SelectField('Role', choices=[
        ('vetting_agent', 'Vetting Agent'),
        ('inviting_admin', 'Inviting Admin'),
        ('server_admin', 'Server Admin')
    ], validators=[DataRequired()])
    
    # Status for user registration approval
    status = HiddenField('Status', default='pending')
    submit = SubmitField('Register User')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists. Please choose a different one.')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered. Please use a different one.')

class MatrixRegistrationForm(FlaskForm):
    full_name = StringField('Full Name', validators=[DataRequired()])
    email = EmailField('Email', validators=[
        DataRequired(),
        Email()
    ])
    assigned_username = StringField('Assigned Username of Invited Member', validators=[
        DataRequired(),
        Length(min=3, max=64)
    ])
    submit = SubmitField('Generate Token and Submit')

class VettingFormClass(FlaskForm):
    # Person details
    full_name = StringField('Full Name', validators=[DataRequired(), Length(max=120)])
    email = EmailField('Email Address', validators=[DataRequired(), Email(), Length(max=120)])
    matrix_id = StringField('Matrix ID (if available)', validators=[Optional(), Length(max=120)])
    phone_number = StringField('Phone Number', validators=[Optional(), Length(max=20)])
    
    # Verification info
    identity_verified = BooleanField('Identity Verified')
    verification_method = SelectField('Verification Method', choices=[
        ('', 'Select Method'),
        ('in-person', 'In-Person Meeting'),
        ('video', 'Video Call'),
        ('trusted-referral', 'Trusted Referral')
    ], validators=[Optional()])
    verification_date = DateField('Verification Date', format='%Y-%m-%d', validators=[Optional()])
    verification_location = StringField('Verification Location (city/online platform)', validators=[Optional(), Length(max=120)])
    
    # Vetting information
    vetting_notes = TextAreaField('Vetting Notes', validators=[Optional()])
    vetting_score = SelectField('Vetting Score (1-5)', choices=[
        ('', 'Select Score'),
        ('1', '1 - Very Low Trust'),
        ('2', '2 - Low Trust'),
        ('3', '3 - Moderate Trust'),
        ('4', '4 - High Trust'),
        ('5', '5 - Very High Trust')
    ], validators=[Optional()])
    recommendation = SelectField('Recommendation', choices=[
        ('', 'Select Recommendation'),
        ('approve', 'Approve'),
        ('reject', 'Reject'),
        ('further-verification', 'Request Further Verification')
    ], validators=[Optional()])
    
    # Vetting Evidence Upload section
    evidence_file1 = FileField('Evidence File 1', validators=[
        Optional(),
        FileAllowed(['jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx', 'txt'], 'Only images, PDFs, and documents are allowed')
    ])
    evidence_notes1 = TextAreaField('Evidence 1 Notes', validators=[Optional()])
    
    evidence_file2 = FileField('Evidence File 2', validators=[
        Optional(),
        FileAllowed(['jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx', 'txt'], 'Only images, PDFs, and documents are allowed')
    ])
    evidence_notes2 = TextAreaField('Evidence 2 Notes', validators=[Optional()])
    
    evidence_file3 = FileField('Evidence File 3', validators=[
        Optional(),
        FileAllowed(['jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx', 'txt'], 'Only images, PDFs, and documents are allowed')
    ])
    evidence_notes3 = TextAreaField('Evidence 3 Notes', validators=[Optional()])
    
    evidence_file4 = FileField('Evidence File 4', validators=[
        Optional(),
        FileAllowed(['jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx', 'txt'], 'Only images, PDFs, and documents are allowed')
    ])
    evidence_notes4 = TextAreaField('Evidence 4 Notes', validators=[Optional()])
    
    evidence_file5 = FileField('Evidence File 5', validators=[
        Optional(),
        FileAllowed(['jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx', 'txt'], 'Only images, PDFs, and documents are allowed')
    ])
    evidence_notes5 = TextAreaField('Evidence 5 Notes', validators=[Optional()])
    
    # Additional details
    additional_info = TextAreaField('Additional Information', validators=[Optional()])
    
    # Submission buttons
    save_draft = SubmitField('Save as Draft')
    submit = SubmitField('Submit for Review')

class UserPreferencesForm(FlaskForm):
    theme = SelectField('Theme', choices=[
        ('dark', 'Dark Mode'),
        ('light', 'Light Mode')
    ], validators=[DataRequired()])
    
    # Token Status Colors
    token_available_color = SelectField('Available Token Color', choices=[
        ('bg-info', 'Blue'),
        ('bg-success', 'Green'),
        ('bg-primary', 'Indigo'),
        ('bg-secondary', 'Gray'),
        ('bg-dark', 'Dark'),
        ('bg-warning text-dark', 'Yellow'),
        ('bg-danger', 'Red')
    ], validators=[DataRequired()])
    
    token_used_color = SelectField('Used Token Color', choices=[
        ('bg-success', 'Green'),
        ('bg-info', 'Blue'),
        ('bg-primary', 'Indigo'),
        ('bg-secondary', 'Gray'),
        ('bg-dark', 'Dark'),
        ('bg-warning text-dark', 'Yellow'),
        ('bg-danger', 'Red')
    ], validators=[DataRequired()])
    
    token_pending_color = SelectField('Pending Token Color', choices=[
        ('bg-warning text-dark', 'Yellow'),
        ('bg-info', 'Blue'),
        ('bg-success', 'Green'),
        ('bg-primary', 'Indigo'),
        ('bg-secondary', 'Gray'),
        ('bg-dark', 'Dark'),
        ('bg-danger', 'Red')
    ], validators=[DataRequired()])
    
    token_expired_color = SelectField('Expired Token Color', choices=[
        ('bg-danger', 'Red'),
        ('bg-info', 'Blue'),
        ('bg-success', 'Green'),
        ('bg-primary', 'Indigo'),
        ('bg-secondary', 'Gray'),
        ('bg-dark', 'Dark'),
        ('bg-warning text-dark', 'Yellow')
    ], validators=[DataRequired()])
    
    token_error_color = SelectField('Error Token Color', choices=[
        ('bg-danger', 'Red'),
        ('bg-info', 'Blue'),
        ('bg-success', 'Green'),
        ('bg-primary', 'Indigo'),
        ('bg-secondary', 'Gray'),
        ('bg-dark', 'Dark'),
        ('bg-warning text-dark', 'Yellow')
    ], validators=[DataRequired()])
    
    # User Role Colors
    superadmin_color = SelectField('Superadmin Role Color', choices=[
        ('bg-danger', 'Red'),
        ('bg-info', 'Blue'),
        ('bg-success', 'Green'),
        ('bg-primary', 'Indigo'),
        ('bg-secondary', 'Gray'),
        ('bg-dark', 'Dark'),
        ('bg-warning text-dark', 'Yellow')
    ], validators=[DataRequired()])
    
    server_admin_color = SelectField('Server Admin Role Color', choices=[
        ('bg-warning text-dark', 'Yellow'),
        ('bg-danger', 'Red'),
        ('bg-info', 'Blue'),
        ('bg-success', 'Green'),
        ('bg-primary', 'Indigo'),
        ('bg-secondary', 'Gray'),
        ('bg-dark', 'Dark')
    ], validators=[DataRequired()])
    
    inviting_admin_color = SelectField('Inviting Admin Role Color', choices=[
        ('bg-primary', 'Indigo'),
        ('bg-danger', 'Red'),
        ('bg-info', 'Blue'),
        ('bg-success', 'Green'),
        ('bg-secondary', 'Gray'),
        ('bg-dark', 'Dark'),
        ('bg-warning text-dark', 'Yellow')
    ], validators=[DataRequired()])
    
    vetting_agent_color = SelectField('Vetting Agent Role Color', choices=[
        ('bg-info', 'Blue'),
        ('bg-danger', 'Red'),
        ('bg-success', 'Green'),
        ('bg-primary', 'Indigo'),
        ('bg-secondary', 'Gray'),
        ('bg-dark', 'Dark'),
        ('bg-warning text-dark', 'Yellow')
    ], validators=[DataRequired()])
    
    # Form Status Colors
    active_status_color = SelectField('Active Status Color', choices=[
        ('bg-success', 'Green'),
        ('bg-danger', 'Red'),
        ('bg-info', 'Blue'),
        ('bg-primary', 'Indigo'),
        ('bg-secondary', 'Gray'),
        ('bg-dark', 'Dark'),
        ('bg-warning text-dark', 'Yellow')
    ], validators=[DataRequired()])
    
    pending_status_color = SelectField('Pending Status Color', choices=[
        ('bg-warning text-dark', 'Yellow'),
        ('bg-danger', 'Red'),
        ('bg-info', 'Blue'),
        ('bg-success', 'Green'),
        ('bg-primary', 'Indigo'),
        ('bg-secondary', 'Gray'),
        ('bg-dark', 'Dark')
    ], validators=[DataRequired()])
    
    awaiting_token_status_color = SelectField('Awaiting Token Status Color', choices=[
        ('bg-info', 'Blue'),
        ('bg-danger', 'Red'),
        ('bg-success', 'Green'),
        ('bg-primary', 'Indigo'),
        ('bg-secondary', 'Gray'),
        ('bg-dark', 'Dark'),
        ('bg-warning text-dark', 'Yellow')
    ], validators=[DataRequired()])
    
    rejected_status_color = SelectField('Rejected Status Color', choices=[
        ('bg-danger', 'Red'),
        ('bg-info', 'Blue'),
        ('bg-success', 'Green'),
        ('bg-primary', 'Indigo'),
        ('bg-secondary', 'Gray'),
        ('bg-dark', 'Dark'),
        ('bg-warning text-dark', 'Yellow')
    ], validators=[DataRequired()])
    
    draft_status_color = SelectField('Draft Status Color', choices=[
        ('bg-secondary', 'Gray'),
        ('bg-danger', 'Red'),
        ('bg-info', 'Blue'),
        ('bg-success', 'Green'),
        ('bg-primary', 'Indigo'),
        ('bg-dark', 'Dark'),
        ('bg-warning text-dark', 'Yellow')
    ], validators=[DataRequired()])
    
    submitted_status_color = SelectField('Submitted Status Color', choices=[
        ('bg-primary', 'Indigo'),
        ('bg-danger', 'Red'),
        ('bg-info', 'Blue'),
        ('bg-success', 'Green'),
        ('bg-secondary', 'Gray'),
        ('bg-dark', 'Dark'),
        ('bg-warning text-dark', 'Yellow')
    ], validators=[DataRequired()])
    
    # Animation Options
    animation_enabled = BooleanField('Enable Animations', default=True)
    tooltip_enabled = BooleanField('Enable Tooltips', default=True)
    
    submit = SubmitField('Save Preferences')
