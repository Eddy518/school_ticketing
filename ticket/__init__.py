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


UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
mail = Mail(app)
csrf = CSRFProtect(app)


SERVICE_DEPARTMENTS = {
    'it': {
        'support': 'Technical Support',
        'network': 'Eduroam and Network Services',
        'portal': 'Student Portal',
        'lms': 'Learning Management System(LMS)',
        'email': 'Email Configuration',
        'security': 'Security Services'
    },
    'it': {
        'account': 'Kusoma Account Setup',
        'password': 'Password Reset',
        'courses': 'Course Access',
        'digital': 'Digital Library',
        'resources': 'Learning Resources',
        'support': 'E-Learning Support'
    },
    'admissions': {
        'undergraduate': 'Undergraduate Admissions',
        'postgraduate': 'Postgraduate Admissions'
    },
    'finance': {
        'student_finance_banking': 'Student Finance and Banking'
    }
}

def get_department_and_service(service_key=None, department_key=None):
    print("In init.py",department_key,service_key)
    if service_key:
        print("Service key being checked", service_key)
        for dept, services in SERVICE_DEPARTMENTS.items():
            if service_key in services.keys():
                print("Matched department")
                return (
                    dept.replace('_', ' '),
                    services[service_key]
                )
    
    elif department_key:
        dept = department_key.lower().replace(' ', '_')
        if dept in SERVICE_DEPARTMENTS:
            services = SERVICE_DEPARTMENTS[dept]
            service_key = list(services.keys())[0]
            print("Using default service", service_key)
            return (
                dept.replace('_', ' '),
                services[service_key]
            )
    print("Returning unkown department")
    return ('Unknown Department', 'Unknown Service')

from ticket import routes
