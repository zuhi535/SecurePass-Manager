import json
import os
import base64
import hashlib
from tkinter import Tk, Label, Entry, Button, messagebox, StringVar, OptionMenu
from tkinter import ttk
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import pyperclip

# Function for hashing the master password
def hash_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),  # Using SHA-512 for more security
        length=32,
        salt=salt,
        iterations=200000,  # Increasing the number of iterations
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Generate a secret key
def generate_key():
    return Fernet.generate_key()

# Initialize Fernet cipher with the provided key
def initialize_cipher(key):
    return Fernet(key)

# Function to encrypt a password
def encrypt_password(cipher, password):
    return cipher.encrypt(password.encode()).decode()

# Function to decrypt a password
def decrypt_password(cipher, encrypted_password):
    return cipher.decrypt(encrypted_password.encode()).decode()

# Function to register a new user
def register(username, master_password):
    salt = os.urandom(16)
    hashed_master_password = hash_password(master_password, salt)
    encrypted_username = encrypt_password(cipher, username)  # Encrypting the username

    user_data = {
        'username': encrypted_username,
        'master_password': hashed_master_password.decode(),
        'salt': base64.b64encode(salt).decode()
    }
    file_name = 'user_data.json'

    try:
        with open(file_name, 'r') as file:
            existing_data = json.load(file)
    except FileNotFoundError:
        existing_data = []

    for user in existing_data:
        # Compare encrypted values here
        if decrypt_password(cipher, user['username']) == username:
            messagebox.showinfo("Success", "Username already exists. Proceed to login.")
            return

    existing_data.append(user_data)

    with open(file_name, 'w') as file:
        json.dump(existing_data, file)
        messagebox.showinfo("Success", "Registration Successful!")

# Function to log in a user
def login(username, entered_password):
    try:
        with open('user_data.json', 'r') as file:
            user_data_list = json.load(file)

        for user_data in user_data_list:
            salt = base64.b64decode(user_data['salt'])
            stored_password_hash = user_data['master_password']
            decrypted_username = decrypt_password(cipher, user_data['username'])  # Decrypting the username
            entered_password_hash = hash_password(entered_password, salt).decode()

            if entered_password_hash == stored_password_hash and decrypted_username == username:
                reset_failed_attempts()
                messagebox.showinfo("Success", "Login Successful!")
                return True

        increment_failed_attempts()
        messagebox.showerror("Error", "Incorrect Login Credentials.")
        return False

    except Exception as e:
        messagebox.showerror("Error", "Error logging in.")
        print(e)
        return False

# Function to view saved websites
def view_websites(logged_in_username):
    try:
        with open('passwords.json', 'r') as data:
            view = json.load(data)
            websites = "\n".join(x['website'] for x in view if x['username'] == logged_in_username)
            if websites:
                messagebox.showinfo("Saved Websites", websites)
            else:
                messagebox.showinfo("Saved Websites", "No saved websites.")
    except FileNotFoundError:
        messagebox.showerror("Error", "No saved passwords.")

# Load or generate the encryption key securely
key_filename = 'encryption_key.key'
if os.path.exists(key_filename):
    with open(key_filename, 'rb') as key_file:
        key = key_file.read()
else:
    key = generate_key()
    with open(key_filename, 'wb') as key_file:
        key_file.write(key)

cipher = initialize_cipher(key)

# Function to add (save) password
def add_password(username, website, password):
    if not os.path.exists('passwords.json'):
        data = []
    else:
        try:
            with open('passwords.json', 'r') as file:
                data = json.load(file)
        except json.JSONDecodeError:
            data = []

    encrypted_password = encrypt_password(cipher, password)
    password_entry = {'username': username, 'website': website, 'password': encrypted_password}
    data.append(password_entry)

    with open('passwords.json', 'w') as file:
        json.dump(data, file, indent=4)
    messagebox.showinfo("Success", "Password Added!")

# Function to retrieve a saved password
def get_password(logged_in_username, website):
    if not os.path.exists('passwords.json'):
        return None, None

    try:
        with open('passwords.json', 'r') as file:
            data = json.load(file)
    except json.JSONDecodeError:
        data = []

    for entry in data:
        if entry['website'] == website and entry['username'] == logged_in_username:
            decrypted_password = decrypt_password(cipher, entry['password'])
            username = entry['username']
            pyperclip.copy(decrypted_password)
            messagebox.showinfo("Password", f"Username: {username}\nPassword for {website}: {decrypted_password}\nPassword copied to clipboard.")
            return username, decrypted_password

    messagebox.showerror("Error", "Password not found.")
    return None, None

# Function to delete a saved password
def delete_password(logged_in_username, website):
    if not os.path.exists('passwords.json'):
        return False

    try:
        with open('passwords.json', 'r') as file:
            data = json.load(file)
    except json.JSONDecodeError:
        data = []

    for entry in data:
        if entry['website'] == website and entry['username'] == logged_in_username:
            data.remove(entry)
            with open('passwords.json', 'w') as file:
                json.dump(data, file, indent=4)
            messagebox.showinfo("Success", "Password Deleted!")
            return True

    messagebox.showerror("Error", "Password not found.")
    return False

# Function to increment failed login attempts
def increment_failed_attempts():
    attempts = 0
    if os.path.exists('failed_attempts.json'):
        with open('failed_attempts.json', 'r') as file:
            attempts = json.load(file).get('attempts', 0)

    attempts += 1

    if attempts >= 5:
        reset_data()
        messagebox.showerror("Error", "Too many failed login attempts. You're looking in the wrong place.")

    with open('failed_attempts.json', 'w') as file:
        json.dump({'attempts': attempts}, file)

# Function to reset failed login attempts
def reset_failed_attempts():
    with open('failed_attempts.json', 'w') as file:
        json.dump({'attempts': 0}, file)

# Function to reset all data
def reset_data():
    if os.path.exists('user_data.json'):
        os.remove('user_data.json')
    if os.path.exists('passwords.json'):
        os.remove('passwords.json')
    if os.path.exists('failed_attempts.json'):
        os.remove('failed_attempts.json')

# Tkinter GUI
class PasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.resizable(False, False)
        self.root.configure(background='#DCDAD5')

        self.logged_in_username = None

        self.create_main_menu()

        # Create a custom style for rounded buttons
        style = ttk.Style()
        style.configure("Custom.TButton", padding=10, font=("Operations", 10), background="#DCDAD5", foreground="black")
        style.map("Custom.TButton",
                  background=[('active', '#DCDAD5'), ('disabled', '#DCDAD5')],
                  foreground=[('active', 'black')])
        style.configure("Custom.TButton", borderwidth=0, borderradius=5)

    def translate(self, key):
        translations = {
            "register": "Register",
            "login": "Login",
            "exit": "Exit",
            "username": "Username",
            "master_password": "Master Password",
            "add_password": "Add Password",
            "retrieve_password": "Retrieve Password",
            "view_saved_websites": "View Saved Websites",
            "delete_password": "Delete Password",
            "logout": "Logout",
            "language": "Language",
            "success": "Success",
            "error": "Error",
            "registration_successful": "Registration Successful!",
            "incorrect_login_credentials": "Incorrect Login Credentials.",
            "user_not_registered": "User not registered.",
            "password_added": "Password Added!",
            "password_deleted": "Password Deleted!",
            "password_not_found": "Password not found.",
            "all_fields_required": "All fields are required!",
            "login_successful": "Login Successful!",
            "saved_websites": "Saved Websites",
            "password": "Password",
            "website": "Website",
            "password_for": "Password for",
            "password_copied": "Password copied to clipboard.",
            "back": "Back",
            "add": "Add"
        }
        return translations[key]

    def create_main_menu(self):
        self.clear_window()

        style = ttk.Style()
        style.configure("TButton", padding=10, font=("Operations", 10), background="#DCDAD5", foreground="black")
        style.map("TButton",
                  background=[('active', '#DCDAD5'), ('disabled', '#DCDAD5')],
                  foreground=[('active', 'black')])

        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)

        self.create_buttons([
            (self.translate("register"), self.create_registration_window, 1),
            (self.translate("login"), self.create_login_window, 2),
            (self.translate("exit"), self.root.quit, 3)
        ], padx=20, pady=20)

    def create_buttons(self, button_configs, padx=0, pady=0):
        for text, command, row in button_configs:
            button = ttk.Button(self.root, text=text, command=command, style="Custom.TButton")
            button.grid(row=row, column=0, columnspan=2, padx=padx, pady=pady, sticky="ew")

    def create_registration_window(self):
        self.clear_window()
        self.root.title(self.translate("register"))

        labels_entries = [
            (self.translate("username"), "register_username_entry"),
            (self.translate("master_password"), "register_master_password_entry")
        ]
        self.create_labels_and_entries(labels_entries, 0)

        ttk.Button(self.root, text=self.translate("register"), command=self.perform_registration).grid(row=2, column=0, columnspan=2, pady=10)
        ttk.Button(self.root, text=self.translate("back"), command=self.create_main_menu).grid(row=3, column=0, columnspan=2, pady=10)

    def create_labels_and_entries(self, labels_entries, start_row):
        for i, (label_text, entry_var) in enumerate(labels_entries, start=start_row):
            ttk.Label(self.root, text=label_text).grid(row=i, column=0, padx=10, pady=10, sticky="e")
            entry = ttk.Entry(self.root, show="*" if "password" in entry_var else None)
            entry.grid(row=i, column=1, padx=10, pady=10, sticky="w")
            setattr(self, entry_var, entry)

    def create_login_window(self):
        self.clear_window()
        self.root.title(self.translate("login"))

        labels_entries = [
            (self.translate("username"), "login_username_entry"),
            (self.translate("master_password"), "login_master_password_entry")
        ]
        self.create_labels_and_entries(labels_entries, 0)

        ttk.Button(self.root, text=self.translate("login"), command=self.perform_login).grid(row=2, column=0, columnspan=2, pady=10)
        ttk.Button(self.root, text=self.translate("back"), command=self.create_main_menu).grid(row=3, column=0, columnspan=2, pady=10)

    def create_password_manager_menu(self):
        self.clear_window()
        self.root.title(self.translate("login_successful"))

        buttons = [
            (self.translate("add_password"), self.create_add_password_window, 0),
            (self.translate("retrieve_password"), self.create_retrieve_password_window, 1),
            (self.translate("view_saved_websites"), lambda: view_websites(self.logged_in_username), 2),
            (self.translate("delete_password"), self.create_delete_password_window, 3),
            (self.translate("logout"), self.create_main_menu, 4)
        ]
        self.create_buttons(buttons, padx=20, pady=10)

    def create_add_password_window(self):
        self.clear_window()
        self.root.title(self.translate("add_password"))

        labels_entries = [
            (self.translate("website"), "add_website_entry"),
            (self.translate("username"), "add_username_entry"),
            (self.translate("password"), "add_password_entry")
        ]
        self.create_labels_and_entries(labels_entries, 0)

        ttk.Button(self.root, text=self.translate("add"), command=self.perform_add_password).grid(row=3, column=0, columnspan=2, pady=10)
        ttk.Button(self.root, text=self.translate("back"), command=self.create_password_manager_menu).grid(row=4, column=0, columnspan=2, pady=10)

    def create_retrieve_password_window(self):
        self.clear_window()
        self.root.title(self.translate("retrieve_password"))

        ttk.Label(self.root, text=self.translate("website")).grid(row=0, column=0, padx=10, pady=10, sticky="e")
        self.retrieve_website_entry = ttk.Entry(self.root)
        self.retrieve_website_entry.grid(row=0, column=1, padx=10, pady=10)

        ttk.Button(self.root, text=self.translate("retrieve_password"), command=self.perform_retrieve_password).grid(row=1, column=0, columnspan=2, pady=10)
        ttk.Button(self.root, text=self.translate("back"), command=self.create_password_manager_menu).grid(row=2, column=0, columnspan=2, pady=10)

    def create_delete_password_window(self):
        self.clear_window()
        self.root.title(self.translate("delete_password"))

        ttk.Label(self.root, text=self.translate("website")).grid(row=0, column=0, padx=10, pady=10, sticky="e")
        self.delete_website_entry = ttk.Entry(self.root)
        self.delete_website_entry.grid(row=0, column=1, padx=10, pady=10)

        ttk.Button(self.root, text=self.translate("delete_password"), command=self.perform_delete_password).grid(row=1, column=0, columnspan=2, pady=10)
        ttk.Button(self.root, text=self.translate("back"), command=self.create_password_manager_menu).grid(row=2, column=0, columnspan=2, pady=10)

    def perform_registration(self):
        username = self.register_username_entry.get()
        master_password = self.register_master_password_entry.get()

        if username and master_password:
            register(username, master_password)
            self.create_main_menu()
        else:
            messagebox.showerror(self.translate("error"), self.translate("all_fields_required"))

    def perform_login(self):
        username = self.login_username_entry.get()
        master_password = self.login_master_password_entry.get()

        if username and master_password:
            if login(username, master_password):
                self.logged_in_username = username  # Save the logged-in user's username.
                self.create_password_manager_menu()
        else:
            messagebox.showerror(self.translate("error"), self.translate("all_fields_required"))

    def perform_add_password(self):
        website = self.add_website_entry.get()
        username = self.add_username_entry.get()
        password = self.add_password_entry.get()

        if website and username and password:
            add_password(self.logged_in_username, website, password)
            self.create_password_manager_menu()
        else:
            messagebox.showerror(self.translate("error"), self.translate("all_fields_required"))

    def perform_retrieve_password(self):
        website = self.retrieve_website_entry.get()
        if website:
            get_password(self.logged_in_username, website)
        else:
            messagebox.showerror(self.translate("error"), self.translate("all_fields_required"))

    def perform_delete_password(self):
        website = self.delete_website_entry.get()
        if website:
            delete_password(self.logged_in_username, website)
        else:
            messagebox.showerror(self.translate("error"), self.translate("all_fields_required"))

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    root = Tk()
    app = PasswordManager(root)
    root.mainloop()
