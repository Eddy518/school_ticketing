import os
import uuid
import pytz
from werkzeug.utils import secure_filename
from datetime import datetime

from flask import (
    abort,
    flash,
    redirect,
    render_template,
    request,
    url_for,
    send_from_directory
)
from flask_login import current_user, login_required, login_user, logout_user
from flask_mail import Message

from ticket import app, bcrypt, db, mail, allowed_file, get_department_and_service
from ticket.form import (
    LoginForm,
    PasswordResetForm,
    RegisterForm,
    RequestResetForm,
    StaffUpdateTicketForm,
    UpdateAccountForm,
    UpdatePasswordForm,
    TicketForm,
    EditTicketForm,
    TrackTicketForm,
    StaffRegistrationForm
)
from ticket.models import User, Ticket


@app.route("/")
def home():
    print(current_user.is_authenticated)
    tickets = Ticket.query.order_by(Ticket.created_at).all()
    return render_template("index.html", current_user=current_user, current_page='home', tickets=tickets)

@app.route('/tickets/<department>/all')
def department_tickets(department):
    department = current_user.department
    tickets = Ticket.query.filter_by(department=current_user.department).all()
    return render_template("staff/department_tickets.html",current_user=current_user,department=department, tickets=tickets, current_page='department_tickets')

# Updating a ticket
@app.route("/staff/ticket/<int:ticket_id>/update", methods=["GET", "POST"])
@login_required
def update_ticket_status(ticket_id):
    if current_user.role != 'staff':
        abort(403)
    ticket = Ticket.query.get_or_404(ticket_id)
    if request.method == 'POST':
        new_status = request.form.get('status')
        ticket.ticket_status = new_status
        db.session.commit()
        flash('Ticket status updated successfully!', 'success')
        return redirect(url_for('staff_tickets'))
    return render_template('staff/update_ticket.html', ticket=ticket)

@app.route("/tickets/all")
def available_tickets():
    return render_template("available_tickets.html", current_user=current_user, current_page='create_a_ticket')


@app.route('/tickets/visualize/graph')
@login_required
def graph_tickets():
    if current_user.role != 'staff':
        abort(403)

    staff_department = current_user.department
    department_tickets = Ticket.query.filter_by(department=staff_department).all()

    if not department_tickets:
        return render_template(
            'ticket_analytics.html',
            graphJSON=None,
            total_tickets=0,
            department=staff_department.upper(),
            current_user=current_user,
            current_page='ticket_analytics',
            message="No tickets found for your department"
        )

    # Get unique services and statuses
    services = list(set(ticket.service for ticket in department_tickets))
    status_types = ['pending', 'completed', 'under_consideration', 'rejected',
                   'awaiting_confirmation', 'in_person_needed']

    # Colors for different statuses
    status_colors = {
        'pending': '#FFA500',  # Orange
        'completed': '#32CD32',  # Green
        'under_consideration': '#4169E1',  # Royal Blue
        'rejected': '#DC143C',  # Crimson
        'awaiting_confirmation': '#9370DB',  # Purple
        'in_person_needed': '#20B2AA'  # Light Sea Green
    }

    # Create traces - one for each status
    traces = []

    for status in status_types:
        counts = []
        hover_texts = []

        for service in services:
            # Get tickets for this service and status
            service_status_tickets = [
                t for t in department_tickets
                if t.service == service and t.ticket_status == status
            ]

            counts.append(len(service_status_tickets))

            # Create hover text with ticket details
            ticket_details = []
            for ticket in service_status_tickets:
                detail = (
                    f"Subject: {ticket.subject}<br>"
                    f"Created: {ticket.created_at.strftime('%Y-%m-%d')}<br>"
                    f"ID: {ticket.ticket_id}"
                )
                ticket_details.append(detail)

            hover_text = (
                f"Service: {service.replace('_', ' ').title()}<br>"
                f"Status: {status.replace('_', ' ').title()}<br>"
                f"Count: {len(service_status_tickets)}"
            )
            if ticket_details:
                hover_text += f"<br><br>Tickets:<br>{('<br>' + '-'*20 + '<br>').join(ticket_details)}"
            hover_texts.append(hover_text)

        # Create trace for this status
        trace = {
            'name': status.replace('_', ' ').title(),
            'x': [s.replace('_', ' ').title() for s in services],  # Service names
            'y': counts,
            'type': 'bar',
            'text': hover_texts,
            'hovertemplate': "%{text}<extra></extra>",
            'marker': {
                'color': status_colors[status]
            }
        }
        traces.append(trace)

    # Create the layout
    layout = {
        'title': {
            'text': f'Service Analysis for {staff_department.upper()} Department',
            'font': {'size': 24}
        },
        'xaxis': {
            'title': 'Services',
            'tickangle': 45,
            'tickfont': {'size': 10}
        },
        'yaxis': {
            'title': 'Number of Tickets'
        },
        'barmode': 'group',  # Group bars for each service
        'bargap': 0.15,      # Gap between bar groups
        'bargroupgap': 0.1,  # Gap between bars in a group
        'hovermode': 'closest',
        'plot_bgcolor': 'white',
        'paper_bgcolor': 'white',
        'showlegend': True,
        'legend': {
            'title': {'text': 'Ticket Status'},
            'bgcolor': 'rgba(255, 255, 255, 0.8)'
        },
        'margin': {'t': 50, 'b': 100, 'l': 50, 'r': 50}  # Adjusted margins
    }

    plot_data = {
        'data': traces,
        'layout': layout
    }

    # Calculate statistics
    total_department_tickets = len(department_tickets)
    service_counts = {
        service: len([t for t in department_tickets if t.service == service])
        for service in services
    }
    most_used_service = max(service_counts.items(), key=lambda x: x[1])

    return render_template(
        'ticket_analytics.html',
        graphJSON=plot_data,
        total_tickets=total_department_tickets,
        most_used_service=most_used_service[0].replace('_', ' ').title(),
        most_used_service_count=most_used_service[1],
        department=staff_department.upper(),
        current_user=current_user,
        current_page='ticket_analytics'
    )


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


# Present the created ticket date in local time instead of utc
def convert_to_local(utc_dt):
    """Convert UTC time to user's local timezone"""
    user_tz = request.cookies.get('user_timezone', 'UTC')
    local_timezone = pytz.timezone(user_tz)
    return utc_dt.replace(tzinfo=pytz.utc).astimezone(local_timezone)


def send_update_email(user,ticket):
    msg = Message(
        "Ticket Update Notification", sender=app.config['MAIL_USERNAME'], recipients=[user.email]
    )
    msg.body = f"Hello {user.email}, your ticket entitled {ticket.subject} has been updated to {ticket.ticket_status} at {convert_to_local(ticket.last_modified_date)}. Please log in to review it."
    mail.send(msg)

@app.route("/ticket/<ticket_id>", methods=["GET", "POST"])
@login_required
def view_ticket(ticket_id):
    ticket = Ticket.query.filter_by(ticket_id=ticket_id).first_or_404()
    local_created_at = convert_to_local(ticket.created_at)
    user = User.query.get_or_404(ticket.user_id)

    if current_user.role == 'staff':
        form = StaffUpdateTicketForm(obj=ticket)

        if form.validate_on_submit():
            # Update the ticket fields
            ticket.ticket_status = form.ticket_status.data
            ticket.remarks = form.remarks.data
            ticket.last_modified_date = datetime.utcnow()  # Use function call

            # Commit changes to the database
            db.session.commit()

            flash("Ticket updated successfully!", "success")
            send_update_email(user, ticket)
            return redirect(url_for("view_ticket", ticket_id=ticket_id))  # Redirect to avoid form resubmission

        return render_template("view_ticket.html",
                               ticket=ticket,
                               current_page='track_ticket',
                               form=form,
                               local_created_at=local_created_at)

    return render_template("view_ticket.html",
                           ticket=ticket,
                           current_page='track_ticket',
                           local_created_at=local_created_at)


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


@app.route("/staff/register/", methods=["POST", "GET"])
@app.route("/staff/REGISTER/", methods=["GET", "POST"])
@app.route("/staff/SIGNUP/", methods=["GET", "POST"])
@app.route("/staff/signup/", methods=["GET", "POST"])
def register_staff():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    form = StaffRegistrationForm()
    if request.method == "POST":
        if form.validate_on_submit():
            email = form.email.data.lower()
            department = form.department.data
            password = form.password.data
            role = 'staff'

            hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
            user = User(
                email=email,
                department=department,
                password=hashed_password,
                role=role
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

    return render_template("staff/register_staff.html", form=form)

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message(
        "Password Reset Request", sender=app.config['MAIL_USERNAME'], recipients=[user.email]
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

    if account_form.account_submit.data and account_form.validate_on_submit():
        if current_user.email == account_form.email.data:
            return redirect(url_for("profile"))
        else:
            current_user.email = account_form.email.data.lower()
            db.session.commit()
            flash("Your Account Info has been updated successfully!", "success")
            return redirect(url_for("profile"))

    if password_form.password_submit.data and password_form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(password_form.new_password.data).decode("utf-8")
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
