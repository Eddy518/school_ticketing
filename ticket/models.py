from datetime import datetime
from flask_login import UserMixin
from itsdangerous.url_safe import URLSafeTimedSerializer as Serializer

from ticket import app, db, login_manager


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.Text, unique=True, nullable=False)
    password = db.Column(db.Text, nullable=False)
    role = db.Column(db.String(20), nullable=False, default="student")
    department = db.Column(db.String(50), nullable=False, default="")
    user_tickets = db.relationship("Ticket", backref="ticket", lazy=True)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config["SECRET_KEY"])
        return s.dumps({"user_id": self.id}, salt=self.password)

    @staticmethod
    def verify_reset_token(token, user_id):
        s = Serializer(app.config["SECRET_KEY"])
        user = User.query.get(user_id)

        if not user:
            return None

        try:
            # Validate the token with the user's password as salt
            data = s.loads(token, salt=user.password, max_age=1800)

            # Confirm token is for this user
            if data.get("user_id") != user.id:
                return None

            return user
        except:
            return None

    def remove(self):
        db.session.delete(self)

    def get_id(self):
        return self.id

    def __repr__(self):
        return "<User %r>" % self.email


class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.String(9), unique=True, nullable=False)
    department = db.Column(db.String(50), nullable=False)
    service = db.Column(db.String(50), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120))
    reg_no = db.Column(db.String(50), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    file_input = db.Column(db.Text)
    ticket_status = db.Column(db.String(50), default="pending")
    remarks = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_modified_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    def __repr__(self) -> str:
        return f"Ticket('{self.ticket_id}', '{self.department}', '{self.service}')"
