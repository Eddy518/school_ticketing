import os

from dotenv import load_dotenv
from flask import Flask
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy

from flask_wtf.csrf import CSRFProtect

load_dotenv(".env")
app = Flask(__name__)
app.app_context().push()
app.config["SECRET_KEY"] = (
    "\xce\xf2i\x87\x05<\xdaB\xf2\x1e\x80\x8f"
)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///site.db"
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")

app.config["RECAPTCHA_PUBLIC_KEY"] = os.getenv("RECAPTCHA_PUBLIC_KEY")
app.config["RECAPTCHA_PRIVATE_KEY"] = os.getenv("RECAPTCHA_PRIVATE_KEY")
app.testing = True

# File Handling
ALLOWED_EXTENSIONS = {'pdf'}
def allowed_file(filename):
    return '.' in filename and \
            filename.rsplit('.' ,1)[1].lower() in ALLOWED_EXTENSIONS

current_dir = os.path.abspath(os.getcwd())
print(current_dir)
app.config['UPLOAD_FOLDER'] = current_dir + 'ticket/static/file_uploads/'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
mail = Mail(app)
csrf = CSRFProtect(app)


SERVICE_DEPARTMENTS = {
    # IT Services
    'IT_SERVICES': {
        'technical-support': 'Technical Support',
        'network-issues': 'Network Issues',
        'software-installation': 'Software Installation',
        'hardware-repairs': 'Hardware Repairs',
        'email-config': 'Email Configuration',
        'security-services': 'Security Services'
    },
    
    # E-Learning
    'E_LEARNING': {
        'kusoma-setup': 'Kusoma Account Setup',
        'password-reset': 'Password Reset',
        'course-access': 'Course Access',
        'digital-library': 'Digital Library',
        'learning-resources': 'Learning Resources',
        'elearning-support': 'E-Learning Support'
    }
}

def get_department(service):
    for department, services in SERVICE_DEPARTMENTS.items():
        if service in services:
            return department.replace('_', ' ')
    return 'Unknown'

def get_service_name(service_key):
    for department in SERVICE_DEPARTMENTS.values():
        if service_key in department:
            return department[service_key]
    return service_key

from ticket import routes
