from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, EmailField, TextAreaField, BooleanField, DateField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, Optional
from models import User

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
    submit = SubmitField('Generate Token and Submit')

class VettingForm(FlaskForm):
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
    
    # Security and trust information
    security_questions_answered = BooleanField('Security Questions Answered')
    trust_level = SelectField('Trust Level', choices=[
        ('', 'Select Trust Level'),
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High')
    ], validators=[Optional()])
    
    # Additional details
    additional_info = TextAreaField('Additional Information', validators=[Optional()])
    
    # Submission buttons
    save_draft = SubmitField('Save as Draft')
    submit = SubmitField('Submit for Review')
