import re
from flask_login import current_user
from flask_wtf import FlaskForm, RecaptchaField
from flask_wtf.file import FileField
from wtforms import (
    BooleanField,
    EmailField,
    PasswordField,
    StringField,
    SubmitField,
    ValidationError,
    TextAreaField,
    SelectField
)
from wtforms.validators import DataRequired, Email, EqualTo, Length
from ticket.models import User

def password_check(form, field):
    """
    Verify that the password meets the following criteria:
    1. 8 characters or more
    2. At least one uppercase letter
    3. At least one lowercase letter
    4. At least one number
    5. At least one special character (excluding spaces)
    """
    password = field.data

    if len(password) < 8:
        raise ValidationError('Password must be at least 8 characters long')

    if not re.search(r'[A-Z]', password):
        raise ValidationError('Password must contain at least one uppercase letter')

    if not re.search(r'[a-z]', password):
        raise ValidationError('Password must contain at least one lowercase letter')

    if not re.search(r'[0-9]', password):
        raise ValidationError('Password must contain at least one number')

    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise ValidationError('Password must contain at least one special character')

class RegisterForm(FlaskForm):
    email = EmailField(validators=[Email(), DataRequired()])
    password = PasswordField(validators=[DataRequired(), Length(min=6),password_check])
    confirm_password = PasswordField(
        validators=[DataRequired(), EqualTo("password"), Length(min=6)]
    )
    submit = SubmitField()

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError("Email already exists.")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remember Me")
    submit = SubmitField("Login")


# Admin form
class StaffRegistrationForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    department = SelectField('Department',
                           choices=[
                               ('it', 'IT Department'),
                               ('admissions', 'Admissions Department'),
                               ('finance', 'Finance Department')
                           ],
                           validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6),password_check])
    confirm_password = PasswordField('Confirm Password',
                                   validators=[DataRequired(),
                                             EqualTo('password')])
    submit = SubmitField('Create an Account')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered.')


class StaffUpdateTicketForm(FlaskForm):
    ticket_status = SelectField('Ticket Status',
                           choices=[
                               ('pending', 'Pending'),
                               ('under_consideration', 'Under Consideration'),
                               ('duplicate', 'Duplicate'),
                               ('awaiting_confirmation', 'Awaiting Confirmation'),
                               ('in_person_needed', 'In Person Needed'),
                               ('completed', 'Completed'),
                               ('rejected', 'Rejected')
                           ],
                           validators=[DataRequired()])
    remarks = TextAreaField('Ticket Update Remarks')
    submit = SubmitField("Update Ticket Status")

class TrackTicketForm(FlaskForm):
    ticket_id = StringField("TicketID", validators=[DataRequired()])
    submit = SubmitField("Find Ticket")


class TicketForm(FlaskForm):
    full_name = StringField("Full Name", validators=[DataRequired(),
                                                     Length(min=6, max=20)])
    email = EmailField(validators=[Email()])
    reg_no = StringField(validators=[DataRequired(), Length(min=9)])
    subject = StringField("Subject Concern", validators=[DataRequired(),
                                                         Length(max=20)])
    message = TextAreaField("Message", validators=[DataRequired()])
    file_input = FileField("File Attachments if any:")
    recaptcha = RecaptchaField()
    submit = SubmitField()


class EditTicketForm(FlaskForm):
    full_name = StringField("Full Name", validators=[DataRequired(),
                                                     Length(min=6, max=20)])
    email = EmailField(validators=[Email()])
    reg_no = StringField(validators=[DataRequired(), Length(min=9)])
    subject = StringField("Subject Concern", validators=[DataRequired(),
                                                         Length(max=20)])
    message = TextAreaField("Message", validators=[DataRequired()])
    file_input = FileField("File Attachments if any:")
    recaptcha = RecaptchaField()
    submit = SubmitField()


class RequestResetForm(FlaskForm):
    email = EmailField("Email:", validators=[Email(), DataRequired()])
    submit = SubmitField("Request Password Reset")

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError(
                "There is no account created with that Email. Please Sign UP."
            )


class PasswordResetForm(FlaskForm):
    password = PasswordField(validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField(
        validators=[DataRequired(), EqualTo("password"), Length(min=6),password_check]
    )
    submit = SubmitField("Reset Password")


class UpdateAccountForm(FlaskForm):
    email = EmailField("Email:", validators=[Email(), DataRequired()])
    account_submit = SubmitField("Update Account")

    def validate_email(self, email):
        if current_user.email != email.data:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError("Email already exists.")


class UpdatePasswordForm(FlaskForm):
    new_password = PasswordField("New Password:", validators=[Length(min=6),password_check])
    confirm_new_password = PasswordField(
        "Confirm New Password:", validators=[Length(min=6), EqualTo("new_password")]
    )
    password_submit = SubmitField("Update Password")


class DeleteAccountForm(FlaskForm):
    password = PasswordField("Password:", validators=[DataRequired(), Length(min=6)])
    submit = SubmitField("Proceed to delete")
