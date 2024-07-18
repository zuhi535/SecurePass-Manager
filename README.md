# Password Manager
This is a secure and user-friendly Password Manager application built with Python and Tkinter. It allows users to register, log in, and manage their passwords for various websites. The application securely encrypts and stores passwords, ensuring user data privacy and security.

## Features
- User registration with a master password
- User login with a master password
- Add new website credentials (username and password)
- Retrieve saved passwords
- Delete saved passwords
- View a list of saved websites
- Secure encryption of all stored data
- Protection against brute-force login attempts
## Table of Contents
1. Installation
2. Usage
3. Functionality
    - Registration
    - Login
    - Add Password
    - Retrieve Password
    - Delete Password
    - View Saved Websites
    - Security Measures
4. Contributing
5. License
## Installation
1. Clone the repository:
```bash
git clone https://github.com/zuhi535/SecurePass-Manager.git
```
2. Install the required dependencies:
```bash
pip install cryptography pyperclip
```
3. Run the application:
```bash
python SecurePass-Manager.py
```
> [!IMPORTANT]
> Before running, make sure that all necessary libraries are installed
## Usage
*Upon launching the application, the main menu is displayed with options to Register, Login, or Exit.*
### Registration
1. Click on the Register button.

2. Enter a Username and Master Password.

3. Click on the Register button to complete the registration.

    - The master password is hashed and stored securely.
    - The username is encrypted before storage.
### Login
1. Click on the Login button.

2. Enter your Username and Master Password.

3. Click on the Login button to access the password manager.

    - Successful login directs you to the password management menu.
    - Failed login attempts are tracked and may result in data reset after multiple failures.
### Retrieve Password
1. Click on Retrieve Password in the password management menu.
2. Enter the Website for which you want to retrieve the password.
3. The decrypted password is displayed and copied to the clipboard.
### Delete Password
1. Click on Delete Password in the password management menu.
2. Enter the Website for which you want to delete the password.
3. Click on the Delete Password button to remove the credentials.
### View Saved Websites
1. Click on View Saved Websites in the password management menu.
2. A list of saved websites associated with the logged-in user is displayed.
### Logout
Click on the Logout button to log out and return to the main menu.
## Security Measures
- Password Hashing: Master passwords are hashed using PBKDF2 with SHA-512 and a high iteration count.
- Encryption: Usernames and passwords are encrypted using Fernet symmetric encryption.
- Failed Login Attempts: Failed login attempts are tracked, and after 5 failed attempts, all stored data is reset to protect against brute-force attacks.
