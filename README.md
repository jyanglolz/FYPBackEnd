# FYPBackEnd - FINAL YEAR PROJECT
 
Overview

This repository contains the backend code for the "Enhancing Security in Task Management Web Application" project. The application is built using Django and provides the server-side logic, API endpoints, and security features necessary for a robust and secure task management system.

**Installation**

**1. Create a virtual environment**

python3 -m venv venv

source venv/bin/activate

**2. Install dependencies**

pip install -r requirements.txt

**3. Apply database migrations**

python manage.py migrate

**4. Create a superuser account**

python manage.py createsuperuser

**5. Start the development server**

python manage.py runserver


**Features**

**1. User Authentication:**

- Enforce strong password complexity rules.
  
- Implement Two-Factor Authentication (2FA) for added security.
  
**2. Task Management:**

- API endpoints for creating, updating, viewing, and deleting tasks.
  
- Task status updates.

**3. Administrator Privileges:**

- Manage individual user accounts.
  
- CRUD operations on tasks.
  
**4. Security Enhancements:**

- Password encryption.
- 
- Token-based verification.

