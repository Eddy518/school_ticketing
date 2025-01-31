import os
import random
import secrets
import string
import uuid
import pytz
import matplotlib.pyplot as plt
import io
from urllib.parse import urlencode
from datetime import datetime, timezone
from werkzeug.utils import secure_filename

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
    send_from_directory,
    Response
)
from flask_login import current_user, login_required, login_user, logout_user
from flask_mail import Message

from ticket import app, bcrypt, db, mail, allowed_file, get_department_and_service
from ticket.form import (
    DeleteAccountForm,
    LoginForm,
    PasswordResetForm,
    RegisterForm,
    RequestResetForm,
    UpdateAccountForm,
    UpdatePasswordForm,
    TicketForm,
    EditTicketForm,
    TrackTicketForm,
    SupportForm
)
from ticket.models import User, Ticket


@app.route("/")
def home():
    print(current_user.is_authenticated)
    tickets = Ticket.query.order_by(Ticket.created_at).all()
    return render_template("index.html", current_user=current_user, current_page='home', tickets=tickets)


@app.route("/tickets/all")
def available_tickets():
    return render_template("available_tickets.html", current_user=current_user, current_page='create_a_ticket')


@app.route('/ticket-graph')
def ticket_graph():
    # Query database for ticket counts per department
    ticket_counts = db.session.query(Ticket.department, db.func.count(Ticket.id)).group_by(Ticket.department).all()

    # Extract data
    departments = [row[0] for row in ticket_counts]
    counts = [row[1] for row in ticket_counts]

    # Create the bar chart
    plt.figure(figsize=(8, 5))
    plt.bar(departments, counts, color=['blue', 'green', 'red', 'orange'])
    plt.xlabel("Departments")
    plt.ylabel("Number of Tickets")
    plt.title("Tickets Created Per Department")
    plt.xticks(rotation=30)  # Rotate x-axis labels for readability

    # Convert plot to an image in memory
    img = io.BytesIO()
    plt.savefig(img, format='png')
    img.seek(0)
    plt.close()

    return Response(img.getvalue(), mimetype='image/png')


@app.route("/tickets/visualize/graph")
def graph_tickets():
    return render_template("ticket_analytics.html", current_user=current_user, current_page='ticket_analytics')


@app.route("/ticket/create", methods=["GET", "POST"])
@login_required
def create_ticket():
    form = TicketForm()

    if request.method == "POST":
        service_key = request.form.get("service")
        department_key = request.form.get("department")
    else:
        service_key = request.args.get('service')
        department_key = request.args.get('department')
    print("Department, Service Key in routes",department_key,service_key)

    department, service = get_department_and_service(
        service_key=service_key,
        department_key=department_key
    )

    form.email.data = current_user.email
    if form.validate_on_submit():
        ticket_id = str(uuid.uuid4().fields[-1])[:9]
        try:
            file_path = None
            if 'file_input' in request.files:
                file = request.files['file_input']
                if file and file.filename != '' and allowed_file(file.filename):
                    filename = f"{ticket_id}_{secure_filename(file.filename)}"
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    file_path = filename
            new_ticket = Ticket(
            ticket_id=ticket_id,
            department = department,
            service = service,
            full_name = form.full_name.data,
            email = form.email.data,
            reg_no = form.reg_no.data,
            subject = form.subject.data,
            message = form.message.data,
            file_input=file_path,
            user_id = current_user.id,
            )
            db.session.add(new_ticket)
            db.session.commit()
            flash('Ticket created successfully! Your ticket ID is: ' + ticket_id, 'success')
            return redirect(url_for('view_ticket',ticket_id=ticket_id))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while creating the ticket. Please try again','error')
            print(f"Error creating ticket: {str(e)}")
    else:
        for field, errors in form.errors.items():
            for error in errors:
                print(
                    f"Error in {getattr(form, field).label.text}: {error}", "error"
                )
        # form.email.data = current_user.email
    return render_template("create_ticket.html", form=form, department=department, service=service)

@app.route('/ticket/<ticket_id>/edit',methods=["GET","POST"])
def edit_ticket(ticket_id):
    form = EditTicketForm()
    ticket = Ticket.query.filter_by(ticket_id=ticket_id).first()

    # Prevent a user from editing another user tickets
    if current_user.id != ticket.user_id:
        abort(403)
    if not ticket:
        flash("Ticket not found!","error")
        return redirect(url_for('available_tickets'))

    form.email.data = ticket.email
    if request.method == "GET":
        form.full_name.data = ticket.full_name
        form.email.data = ticket.email
        form.reg_no.data = ticket.reg_no
        form.subject.data = ticket.subject
        form.message.data = ticket.message
        form.file_input.data = ticket.file_input
    if form.validate_on_submit():
        full_name = form.full_name.data
        email = form.email.data
        reg_no = form.reg_no.data
        subject = form.subject.data
        message = form.message.data

        file = request.files.get('file_input')
        file_uploaded = file and file.filename != '' and allowed_file(file.filename)
        if (
            full_name == ticket.full_name and
            email == ticket.email and
            reg_no == ticket.reg_no and
            subject == ticket.subject and
            message == ticket.message and
                not file_uploaded
            ):
            flash("Nothing has changed","info")
            return redirect(url_for('edit_ticket',ticket_id=ticket.ticket_id))
        
        print("I am being called")
        new_ticket_id = str(uuid.uuid4().fields[-1])[:9]

        file_path = None
        if file_uploaded:
            filename = f"{new_ticket_id}_{secure_filename(file.filename)}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            file_path = filename
        try:
            new_ticket = Ticket(
                ticket_id=new_ticket_id,
                department=ticket.department,
                service=ticket.service,
                full_name=full_name,
                email=email,
                reg_no=reg_no,
                subject=subject,
                message=message,
                file_input=file_path,
                user_id=current_user.id)
            db.session.add(new_ticket)
            db.session.commit()
            flash(f'New Ticket has been submitted successfully! Your new ticket ID is: {new_ticket_id}', 'success')
            return redirect(url_for('view_ticket', ticket_id=new_ticket_id))

        except Exception as e:
            db.session.rollback()
            flash('An error occurred while creating the ticket. Please try again', 'error')
            print(f"Error creating ticket: {str(e)}")
    #     else:
    #         print("I am being called")
    #         ticket_id = str(uuid.uuid4().fields[-1])[:9]
    #         try:
    #             file_path = None
    #             if 'file_input' in request.files:
    #                 file = request.files['file_input']
    #                 if file and file.filename != '' and allowed_file(file.filename):
    #                     filename = f"{ticket_id}_{secure_filename(file.filename)}"
    #                     file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    #                     file.save(file_path)
    #                     file_path = filename
    #             new_ticket = Ticket(
    #             ticket_id=ticket_id,
    #             department = ticket.department,
    #             service = ticket.service,
    #             full_name = form.full_name.data,
    #             email = form.email.data,
    #             reg_no = form.reg_no.data,
    #             subject = form.subject.data,
    #             message = form.message.data,
    #             file_input=file_path,
    #             user_id = current_user.id,
    #             )
    #             db.session.add(new_ticket)
    #             db.session.commit()
    #             flash('New Ticket has been submitted successfully! Your ticket ID is: ' + ticket_id, 'success')
    #             redirect(url_for('view_ticket'))
    #
    #         except Exception as e:
    #             db.session.rollback()
    #             flash('An error occurred while creating the ticket. Please try again','error')
    #             print(f"Error creating ticket: {str(e)}")
    # else:
    #     for field, errors in form.errors.items():
    #         for error in errors:
    #             print(
    #                 f"Error in {getattr(form, field).label.text}: {error}", "error"
    #             )


    return render_template("edit_ticket.html",form=form, ticket=ticket)

@app.route("/ticket/track", methods=["GET","POST"])
def find_ticket():
    form = TrackTicketForm()
    if request.method == "POST":
        ticket_id = request.form.get('ticket_id')
        ticket = Ticket.query.filter_by(ticket_id=ticket_id).first()
        if ticket:
            return render_template("track_ticket.html", ticket=ticket, current_page="track_a_ticket", form=form)
        else:
            error = "No ticket found with that ID. Please check and try again."
            return render_template("track_ticket.html", error=error, current_page='track_a_ticket', form=form)
    return render_template("track_ticket.html", current_user=current_user, current_page='track_a_ticket',form=form)



def convert_to_local(utc_dt):
    """Convert UTC time to user's local timezone"""
    user_tz = request.cookies.get('user_timezone', 'UTC')
    local_timezone = pytz.timezone(user_tz)
    return utc_dt.replace(tzinfo=pytz.utc).astimezone(local_timezone)

@app.route("/ticket/<ticket_id>")
@login_required
def view_ticket(ticket_id):
    ticket = Ticket.query.filter_by(ticket_id=ticket_id).first_or_404()
    local_created_at = convert_to_local(ticket.created_at)
    return render_template("view_ticket.html", 
                         ticket=ticket, 
                         current_page='track_ticket', local_created_at=local_created_at)


@app.route("/view-pdf/<ticket_id>")
@login_required
def view_pdf(ticket_id):
    ticket = Ticket.query.filter_by(ticket_id=ticket_id).first_or_404()
    
    if not ticket.file_input or not ticket.file_input.lower().endswith('.pdf'):
        flash('No PDF file attached to this ticket', 'error')
        return redirect(url_for('view_ticket', ticket_id=ticket_id))
    
    try:
        # Return the file with Content-Type as application/pdf
        return send_from_directory(
            app.config['UPLOAD_FOLDER'],
            ticket.file_input,
            mimetype='application/pdf'
        )
    except FileNotFoundError:
        flash('File not found', 'error')
        return redirect(url_for('view_ticket', ticket_id=ticket_id))


@app.route("/download/<ticket_id>")
@login_required
def download_file(ticket_id):
    ticket = Ticket.query.filter_by(ticket_id=ticket_id).first_or_404()
    
    if not ticket.file_input:
        flash('No file attached to this ticket', 'error')
        return redirect(url_for('view_ticket', ticket_id=ticket_id))
    
    # Get the filename from the file_input field
    filename = ticket.file_input
    
    try:
        # Return the file from the upload folder
        return send_from_directory(
            app.config['UPLOAD_FOLDER'],
            filename,
            as_attachment=True
        )
    except FileNotFoundError:
        flash('File not found', 'error')
        return redirect(url_for('view_ticket', ticket_id=ticket_id))


@app.route("/tickets")
def show_user_tickets():
    user_tickets = Ticket.query.filter_by(user_id=current_user.id).order_by(Ticket.created_at.desc()).all()
    # user_tickets = Ticket.query.all()
    print(user_tickets)
    return render_template("user_tickets.html", current_page='view_all_tickets',user_tickets=user_tickets)

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
                "success",
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
            flash("Your Account Info has been updated successfully!", "success")
            return redirect(url_for("profile"))
    else:
        account_form.email.data = current_user.email
    if password_form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(password_form.new_password.data)
        current_user.password = hashed_password
        db.session.commit()
        flash("Your Password has been updated successfully!", "success")
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


from werkzeug.exceptions import RequestEntityTooLarge

@app.errorhandler(RequestEntityTooLarge)
def handle_large_file_error(e):
    flash("File is too large! Maximum allowed size is 2MB.", "error")
    return redirect(request.url)  # Redirect back to the form

@app.errorhandler(404)
def error_404(error):
    return render_template("404.html")


@app.errorhandler(403)
def error_403(error):
    return render_template("403.html")


@app.errorhandler(401)
def error_401(error):
    return render_template("401.html")


@app.errorhandler(500)
def error_500(error):
    return render_template("500.html")
