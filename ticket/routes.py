import os
import random
import secrets
import string
from urllib.parse import urlencode
from datetime import datetime, timezone

import requests
from flask import (
    abort,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user
from flask_mail import Message

from ticket import app, bcrypt, db, mail
from ticket.form import (
    DeleteAccountForm,
    LoginForm,
    PasswordResetForm,
    RegisterForm,
    RequestResetForm,
    UpdateAccountForm,
    UpdatePasswordForm,
    SupportForm
)
from ticket.models import User


@app.route("/")
def home():
    print(current_user.is_authenticated)
    return render_template("index.html", current_user=current_user, current_page='home')


@app.route("/tickets/create")
def available_tickets():
    return render_template("create_ticket.html", current_user=current_user, current_page='create_a_ticket')

# @app.route("/support", methods=["GET", "POST"])
# def support():
#     form = SupportForm()
#     if request.method == "GET" and current_user.is_authenticated:
#         print(current_user)
#         form.username.data = current_user.username
#         form.email.data = current_user.email
#     if form.validate_on_submit() and current_user.is_authenticated:
#         username = form.username.data
#         email = form.email.data
#         message = form.message.data
#         support_msg = Message(f"Message from {username}", sender=email, recipients=["edmwangi2@gmail.com"])
#         support_msg.body = message
#         mail.send(support_msg)
#         flash("Message Successfully sent", "success")
#         form.message.data = ""
#     elif not current_user.is_authenticated:
#         email = form.email.data
#         message = form.message.data
#         guest_msg = Message(f"Message from {email}", sender=email, recipients=["edmwangi2@gmail.com"])
#         guest_msg.body = message
#         if request.method == 'POST' and email != '' and message != '' and guest_msg.body != '' and guest_msg != '':
#             mail.send(guest_msg)
#             flash("Message Successfully sent", "success")
#             form.message.data = ""
#
#     return render_template("support.html", form=form, current_user=current_user)
#
#
@app.route("/signin/", methods=("GET", "POST"))
@app.route("/SIGNIN/", methods=("GET", "POST"))
@app.route("/LOGIN/", methods=("GET", "POST"))
@app.route("/login/", methods=("GET", "POST"))
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for("home"))
        else:
            flash(
                """Login unsuccessful. Please check if your Email
                    and Password is correct and try again!""",
                "error",
            )
    return render_template("login_user.html", title=login, form=form)


@app.route("/register/", methods=["POST", "GET"])
@app.route("/REGISTER/", methods=["GET", "POST"])
@app.route("/SIGNUP/", methods=["GET", "POST"])
@app.route("/signup/", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    form = RegisterForm()
    if request.method == "POST":
        if form.validate_on_submit():
            email = form.email.data.lower()
            password = form.password.data

            hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
            user = User(
                email=email,
                password=hashed_password,
            )

            db.session.add(user)
            db.session.commit()
            flash(
                f" {form.email.data} you have been successfully registered. Log in to proceed.",
                "info",
            )
            return redirect(url_for("login"))
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    print(
                        f"Error in {getattr(form, field).label.text}: {error}", "error"
                    )

    return render_template("register_user.html", form=form)


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message(
        "Password Reset Request", sender="edmwangi2@gmail.com", recipients=[user.email]
    )
    msg.body = f"""To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be done.
"""
    mail.send(msg)


@app.route("/request_password", methods=["GET", "POST"])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        print(user)
        send_reset_email(user)
        flash(
            f"Hello, {form.email.data} \n. An email has been sent to you with reset instructions",
            "info",
        )
        return redirect(url_for('reset_request'))
        if not user:
            flash("Please check your credentials and try again.", "error")
    return render_template("reset_request.html", form=form)


@app.route("/request_password/<token>", methods=["GET", "POST"])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for("main_page"))
    user = User.verify_reset_token(token)
    if user is None:
        flash(
            "That token is invalid or expired. Please enter your email again.", "error"
        )
        return redirect(url_for("reset_request"))
    form = PasswordResetForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        user.password = hashed_password
        db.session.commit()
        flash(
            "Your password has been successfully updated. Log in to proceed.",
            "info",
        )
        return redirect(url_for("login"))
    return render_template("reset_token.html", form=form)


@app.route("/account/", methods=["GET", "POST"])
@app.route("/profile/", methods=["GET", "POST"])
@login_required
def profile():
    account_form = UpdateAccountForm()
    password_form = UpdatePasswordForm()
    if request.method == "GET":
        account_form.email.data = current_user.email
    if account_form.validate_on_submit():
        if (
            current_user.email == account_form.email.data
        ):
            redirect(url_for("profile"))
        else:
            current_user.email = account_form.email.data.lower()
            db.session.commit()
            flash("Your Account Info has been updated successfully!", "info")
            return redirect(url_for("profile"))
    if password_form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(password_form.new_password.data)
        current_user.password = hashed_password
        db.session.commit()
        flash("Your Password has been updated successfully!", "info")
        return redirect(url_for("profile"))
    return render_template(
        "user_profile.html", account_form=account_form, password_form=password_form, current_page='settings'
    )


@app.route("/account/delete", methods=("GET", "POST"))
@app.route("/profile/delete", methods=("GET", "POST"))
@login_required
def delete_account():
    current_user.remove()
    db.session.commit()
    flash("You no longer exist :)", "info")
    return redirect(url_for("home"))
    return render_template("confirm_delete.html")


@app.route("/logout/")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


# @app.errorhandler(404)
# def error_404(error):
#     return render_template("404.html")
#
#
# @app.errorhandler(403)
# def error_403(error):
#     return render_template("403.html")
#
#
# @app.errorhandler(401)
# def error_401(error):
#     return render_template("401.html")
#
#
# @app.errorhandler(500)
# def error_500(error):
#     return render_template("500.html")
