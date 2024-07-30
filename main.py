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
        with open('passwords.json', 'r') as data_file:
            data = json.load(data_file)
            
        # Debugging print statements
        print("Loaded data:", data)
        
        # Filter data by logged_in_username
        websites = [entry['website'] for entry in data if entry['current_username'] == logged_in_username]
        
        # Debugging print statements
        print("Filtered websites:", websites)
        
        if websites:
            messagebox.showinfo("Saved Websites", "\n".join(websites))
        else:
            messagebox.showinfo("Saved Websites", "No saved websites.")
    except FileNotFoundError:
        messagebox.showerror("Error", "No saved passwords.")
    except json.JSONDecodeError:
        messagebox.showerror("Error", "Error decoding passwords file.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

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
def add_password(current_username, website, username, password):
    if not os.path.exists('passwords.json'):
        data = []
    else:
        try:
            with open('passwords.json', 'r') as file:
                data = json.load(file)
        except json.JSONDecodeError:
            data = []

    encrypted_password = encrypt_password(cipher, password)
    password_entry = {'current_username': current_username, 'website': website, 'username': username, 'password': encrypted_password}
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
        if entry['website'] == website and entry['current_username'] == logged_in_username:
            decrypted_password = decrypt_password(cipher, entry['password'])
            pyperclip.copy(decrypted_password)
            messagebox.showinfo("Password", f"Username: {entry['username']}\nPassword for {website}: {decrypted_password}\nPassword copied to clipboard.")
            return entry['username'], decrypted_password

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

    # Use a temporary list to hold items to keep
    new_data = []
    found = False

    for entry in data:
        if entry['website'].strip().lower() == website.strip().lower() and entry['current_username'].strip().lower() == logged_in_username.strip().lower():
            found = True
            continue
        new_data.append(entry)

    if found:
        with open('passwords.json', 'w') as file:
            json.dump(new_data, file, indent=4)
        messagebox.showinfo("Success", "Password Deleted!")
        return True
    else:
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
        return

    with open('failed_attempts.json', 'w') as file:
        json.dump({'attempts': attempts}, file)

# Function to reset failed login attempts
def reset_failed_attempts():
    with open('failed_attempts.json', 'w') as file:
        json.dump({'attempts': 0}, file)

# Function to reset all data
def reset_data():
    # Remove all relevant data files
    for file in ['user_data.json', 'passwords.json', 'failed_attempts.json']:
        if os.path.exists(file):
            os.remove(file)
    # Optionally, reset encryption key if needed
    if os.path.exists('encryption_key.key'):
        os.remove('encryption_key.key')

# Tkinter GUI
class PasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.resizable(False, False)
        self.root.configure(background='#DCDAD5')

        self.logged_in_username = None

        self.clear_window()  # Call this method early to ensure it's defined
        self.create_main_menu()

        # Create a custom style for rounded buttons
        style = ttk.Style()
        style.configure("Custom.TButton", padding=10, font=("Operations", 10), background="#DCDAD5", foreground="black")
        style.map("Custom.TButton",
                  background=[('active', '#DCDAD5'), ('disabled', '#DCDAD5')],
                  foreground=[('active', 'black')])
        style.configure("Custom.TButton", borderwidth=0, borderradius=5)

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

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
            "password_added": "Password Added!",
            "password_deleted": "Password Deleted!",
            "password_not_found": "Password not found.",
            "username_already_exists": "Username already exists. Proceed to login.",
            "password_copied": "Password copied to clipboard.",
            "too_many_attempts": "Too many failed login attempts. You're looking in the wrong place."
        }
        return translations.get(key, key)

    def create_main_menu(self):
        self.clear_window()
        title_label = Label(self.root, text="Welcome to Password Manager", font=("Operations", 24, "bold"), bg='#DCDAD5')
        title_label.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

        register_button = Button(self.root, text=self.translate("register"), command=self.create_register_page, font=("Operations", 12, "bold"), bg='#DCDAD5', fg="black")
        register_button.grid(row=1, column=0, padx=10, pady=10, sticky="ew")

        login_button = Button(self.root, text=self.translate("login"), command=self.create_login_page, font=("Operations", 12, "bold"), bg='#DCDAD5', fg="black")
        login_button.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

        exit_button = Button(self.root, text=self.translate("exit"), command=self.root.quit, font=("Operations", 12, "bold"), bg='#DCDAD5', fg="black")
        exit_button.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

    def create_register_page(self):
        self.clear_window()
        username_label = Label(self.root, text=self.translate("username"), font=("Operations", 12), bg='#DCDAD5')
        username_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        username_entry = Entry(self.root, font=("Operations", 12))
        username_entry.grid(row=0, column=1, padx=10, pady=10)

        master_password_label = Label(self.root, text=self.translate("master_password"), font=("Operations", 12), bg='#DCDAD5')
        master_password_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")
        master_password_entry = Entry(self.root, show="*", font=("Operations", 12))
        master_password_entry.grid(row=1, column=1, padx=10, pady=10)

        register_button = Button(self.root, text=self.translate("register"), command=lambda: self.register_user(username_entry.get(), master_password_entry.get()), font=("Operations", 12, "bold"), bg='#DCDAD5', fg="black")
        register_button.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

        back_button = Button(self.root, text="Back", command=self.create_main_menu, font=("Operations", 12, "bold"), bg='#DCDAD5', fg="black")
        back_button.grid(row=3, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

    def create_login_page(self):
        self.clear_window()
        username_label = Label(self.root, text=self.translate("username"), font=("Operations", 12), bg='#DCDAD5')
        username_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        username_entry = Entry(self.root, font=("Operations", 12))
        username_entry.grid(row=0, column=1, padx=10, pady=10)

        master_password_label = Label(self.root, text=self.translate("master_password"), font=("Operations", 12), bg='#DCDAD5')
        master_password_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")
        master_password_entry = Entry(self.root, show="*", font=("Operations", 12))
        master_password_entry.grid(row=1, column=1, padx=10, pady=10)

        login_button = Button(self.root, text=self.translate("login"), command=lambda: self.login_user(username_entry.get(), master_password_entry.get()), font=("Operations", 12, "bold"), bg='#DCDAD5', fg="black")
        login_button.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

        back_button = Button(self.root, text="Back", command=self.create_main_menu, font=("Operations", 12, "bold"), bg='#DCDAD5', fg="black")
        back_button.grid(row=3, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

    def create_dashboard(self):
        self.clear_window()

        add_password_button = Button(self.root, text=self.translate("add_password"), command=self.create_add_password_page, font=("Operations", 12, "bold"), bg='#DCDAD5', fg="black")
        add_password_button.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        retrieve_password_button = Button(self.root, text=self.translate("retrieve_password"), command=self.create_retrieve_password_page, font=("Operations", 12, "bold"), bg='#DCDAD5', fg="black")
        retrieve_password_button.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        view_saved_websites_button = Button(self.root, text=self.translate("view_saved_websites"), command=lambda: view_websites(self.logged_in_username), font=("Operations", 12, "bold"), bg='#DCDAD5', fg="black")
        view_saved_websites_button.grid(row=1, column=0, padx=10, pady=10, sticky="ew")

        delete_password_button = Button(self.root, text=self.translate("delete_password"), command=self.create_delete_password_page, font=("Operations", 12, "bold"), bg='#DCDAD5', fg="black")
        delete_password_button.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

        logout_button = Button(self.root, text=self.translate("logout"), command=self.logout_user, font=("Operations", 12, "bold"), bg='#DCDAD5', fg="black")
        logout_button.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

    def create_add_password_page(self):
        self.clear_window()

        website_label = Label(self.root, text=self.translate("enter_website"), font=("Operations", 12), bg='#DCDAD5')
        website_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        website_entry = Entry(self.root, font=("Operations", 12))
        website_entry.grid(row=0, column=1, padx=10, pady=10)

        username_label = Label(self.root, text=self.translate("enter_username"), font=("Operations", 12), bg='#DCDAD5')
        username_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")
        username_entry = Entry(self.root, font=("Operations", 12))
        username_entry.grid(row=1, column=1, padx=10, pady=10)

        password_label = Label(self.root, text=self.translate("enter_password"), font=("Operations", 12), bg='#DCDAD5')
        password_label.grid(row=2, column=0, padx=10, pady=10, sticky="w")
        password_entry = Entry(self.root, show="*", font=("Operations", 12))
        password_entry.grid(row=2, column=1, padx=10, pady=10)

        add_button = Button(self.root, text=self.translate("add_password"), command=lambda: add_password(self.logged_in_username, website_entry.get(), username_entry.get(), password_entry.get()), font=("Operations", 12, "bold"), bg='#DCDAD5', fg="black")
        add_button.grid(row=3, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

        back_button = Button(self.root, text="Back", command=self.create_dashboard, font=("Operations", 12, "bold"), bg='#DCDAD5', fg="black")
        back_button.grid(row=4, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

    def create_retrieve_password_page(self):
        self.clear_window()

        website_label = Label(self.root, text=self.translate("enter_website"), font=("Operations", 12), bg='#DCDAD5')
        website_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        website_entry = Entry(self.root, font=("Operations", 12))
        website_entry.grid(row=0, column=1, padx=10, pady=10)

        retrieve_button = Button(self.root, text=self.translate("retrieve_password"), command=lambda: get_password(self.logged_in_username, website_entry.get()), font=("Operations", 12, "bold"), bg='#DCDAD5', fg="black")
        retrieve_button.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

        back_button = Button(self.root, text="Back", command=self.create_dashboard, font=("Operations", 12, "bold"), bg='#DCDAD5', fg="black")
        back_button.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

    def create_delete_password_page(self):
        self.clear_window()

        website_label = Label(self.root, text=self.translate("enter_website"), font=("Operations", 12), bg='#DCDAD5')
        website_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        website_entry = Entry(self.root, font=("Operations", 12))
        website_entry.grid(row=0, column=1, padx=10, pady=10)

        delete_button = Button(self.root, text=self.translate("delete_password"), command=lambda: delete_password(self.logged_in_username, website_entry.get()), font=("Operations", 12, "bold"), bg='#DCDAD5', fg="black")
        delete_button.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

        back_button = Button(self.root, text="Back", command=self.create_dashboard, font=("Operations", 12, "bold"), bg='#DCDAD5', fg="black")
        back_button.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

    def register_user(self, username, master_password):
        if username and master_password:
            register(username, master_password)
        else:
            messagebox.showerror("Error", "Please enter both username and password.")

    def login_user(self, username, master_password):
        if username and master_password:
            if login(username, master_password):
                self.logged_in_username = username
                self.create_dashboard()
        else:
            messagebox.showerror("Error", "Please enter both username and password.")

    def logout_user(self):
        self.logged_in_username = None
        self.create_main_menu()

# Main program
if __name__ == "__main__":
    root = Tk()
    app = PasswordManager(root)
    root.mainloop()
