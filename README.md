## Password Strength Checker with Role-Based Access Control (RBAC)

This Python application combines password strength checking and Role-Based Access Control (RBAC) to enhance security.
It provides a graphical user interface (GUI) built with Tkinter, where users can log in, evaluate their password strength, and request permissions based on their roles.

## Features
- **Password Strength Evaluation**:
  - Measures password entropy.
  - Identifies weak passwords with detailed feedback (e.g., missing uppercase letters, numbers, or special characters).
  - Prevents use of common patterns and repetitive characters.
  - Rates passwords as Weak, Fair, Medium, or Strong.
  
- **Role-Based Access Control (RBAC)**:
  - Predefined user roles: Doctor, Nurse, Admin, Receptionist.
  - Role-specific permissions (e.g., doctors can "View Patient Data" and "Edit Patient Records").
  - Permission request validation based on user roles.

- **Interactive GUI**:
  - User-friendly Tkinter interface.
  - Real-time password strength feedback.
  - Permission request entry with dynamic access control response.
