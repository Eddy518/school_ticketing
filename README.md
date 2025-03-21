# School Ticketing System (StuTicket)

StuTicket is a comprehensive web application designed to manage student service requests across various university departments. This system allows students to create, track, and manage support tickets while enabling staff members to respond to and resolve these tickets efficiently.

## Features

### For Students:
- **Account Management**: Register, login, and manage your profile
- **Ticket Creation**: Submit detailed support requests across multiple departments
- **File Attachments**: Attach PDFs to provide additional context for your issues (up to 2MB)
- **Ticket Tracking**: Monitor the status of your submitted tickets
- **Ticket Updates**: Receive email notifications when staff update your tickets

### For Staff:
- **Department-Specific Dashboard**: Access tickets relevant to your department
- **Ticket Management**: Update ticket status and provide detailed remarks
- **Analytics**: View graphical representations of department ticket statistics
- **PDF Handling**: View and download student-submitted PDF files

## Getting Started

### Prerequisites
- Python 3.8+
- Flask
- SMTP service for email notifications
- reCAPTCHA API keys (for form security)

### Environment Setup
Create a `.env` file in the root directory with the following variables:
```
MAIL_USERNAME=your_email@example.com
MAIL_PASSWORD=your_email_password
RECAPTCHA_PUBLIC_KEY=your_recaptcha_public_key
RECAPTCHA_PRIVATE_KEY=your_recaptcha_private_key
```

### Installation

1. Clone the repository
2. Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install required packages:
   ```
   pip install -r requirements.txt
   ```
4. Initialize the database:
   ```
   python -c "from ticket import db; db.create_all()"
   ```
5. Run the application:
   ```
   python run.py
   ```

## Usage Guide

### For Students

#### Registration and Login
1. Navigate to the homepage and click "Register"
2. Create an account using your school email
3. Login with your credentials

#### Creating a Ticket
1. From the dashboard, click "Create a ticket"
2. Select the appropriate department and service
3. Fill in all required details about your issue
4. Attach relevant documentation if needed (PDF only)
5. Submit your ticket

#### Tracking Tickets
1. Click "Your tickets" to view all your submitted tickets
2. Use the "Track a ticket" feature to find a specific ticket by ID
3. View ticket details, including status updates and staff remarks

#### Managing Your Account
1. Access "Settings" to update your email or password
2. Use the "Delete Account" option if you wish to remove your account

### For Staff

#### Registration and Login
1. Navigate to the registration page and select "Register Account (Staff only)"
2. Create an account with your department credentials
3. Login with your staff email and password

#### Managing Tickets
1. View department-specific tickets in your dashboard
2. Click on a ticket to view details
3. Update ticket status (e.g., pending, in progress, completed)
4. Add remarks to provide additional information to students

#### Analytics Dashboard
1. Access "Ticket Analytics" to view department statistics
2. Analyze ticket volume by service type and status
3. Identify trends to improve department efficiency

## Ticket Statuses

- **Pending**: Initial status when a ticket is submitted
- **Under Consideration**: Being reviewed by staff
- **Duplicate**: Ticket issue already exists in another submission
- **Awaiting Confirmation**: Waiting for additional information from student
- **In Person Needed**: Requires face-to-face interaction to resolve
- **Completed**: Issue has been resolved
- **Rejected**: Ticket cannot be processed (with explanation)

## Department Services

### IT Department
- Technical Support
- Eduroam and Network Services
- Student Portal
- Learning Management System (LMS)
- Email Configuration
- Security Services
- Kusoma Account Setup
- Password Reset
- Course Access
- Digital Library
- Learning Resources

### Admissions Department
- Undergraduate Admissions
- Postgraduate Admissions

### Finance Department
- Student Finance and Banking

## Security Features
- Password validation with complexity requirements
- CSRF protection
- Account lockout after failed attempts
- reCAPTCHA for form submissions
- Secure file handling

## Support

For issues or questions, please contact the system administrator or your department's IT support team.

---

© StuTicket - All Rights Reserved.
