import os
import shutil
import tempfile
import time
from base64 import urlsafe_b64encode
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from random import choice, randint, shuffle
from tkinter import *
from tkinter import messagebox

SALT_SIZE = 16  # Size salt in bytes
DATA_FILE = "data.xd"
LOCK_FILE = "data.lock"

letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
           'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
           'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
symbols = ['!', '#', '$', '%', '&', '(', ')', '*', '+']
numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']

is_logged = False
master_password_logged = ""
passwords_window_open = False
passwords_window = None
decrypted_password_lines_for_edit = ""


# ---------------------------- LOCK FILE SYSTEM ------------------------------- #
def acquire_lock():
    while os.path.exists(LOCK_FILE):
        time.sleep(0.1)  # Wait 100ms if the file is locked

    with open(LOCK_FILE, "w") as lock_file:
        lock_file.write("locked")


def release_lock():
    if os.path.exists(LOCK_FILE):
        os.remove(LOCK_FILE)


# ---------------------------- LOGIN/REGISTER/CHANGE ------------------------------- #
def derive_key(password, salt):
    """
    Derive a key using PBKDF2HMAC since a password and a salt.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = urlsafe_b64encode(kdf.derive(password.encode()))
    return key


def login():
    master_password = master_password_entry.get()
    if len(master_password) == 0:
        messagebox.showinfo(title="Oops", message="Introduce your master password!")
        return

    if not os.path.isfile(DATA_FILE):
        messagebox.showinfo(title="Oops", message="No user exists!")
        return

    try:
        with open(DATA_FILE, "rb") as encrypted_file:
            first_line = encrypted_file.readline()
            salt = first_line[:SALT_SIZE]
            encrypted_message = first_line[SALT_SIZE:].strip()
            user_key = derive_key(master_password, salt)

            cipher = Fernet(user_key)
            global is_logged

            cipher.decrypt(encrypted_message).decode()
            is_logged = True
            messagebox.showinfo(title="Login", message="Successfully login!")

    except Exception as e:
        is_logged = False
        messagebox.showinfo(title="Oops", message=f"Invalid password! {e}")

    if is_logged:
        global master_password_logged
        master_password_logged = master_password

        login_button["state"] = "disabled"
        register_button["state"] = "disabled"
        change_button["state"] = "normal"
        search_button["state"] = "normal"
        open_button["state"] = "normal"
        add_button["state"] = "normal"
        edit_button["state"] = "normal"
        delete_button["state"] = "normal"

    delete_entries()


def register():
    master_password = master_password_entry.get()
    if len(master_password) == 0:
        messagebox.showinfo(title="Oops", message="Create your master password!")
        return

    if os.path.isfile(DATA_FILE):
        messagebox.showinfo(title="Oops", message="A user already exists!")
        return

    master_password = master_password_entry.get()

    # Generate a salt for this register
    salt = os.urandom(SALT_SIZE)

    # Derive the key using the master pass from user and the salt generated
    user_key = derive_key(master_password, salt)
    cipher = Fernet(user_key)

    try:
        encrypted_message = cipher.encrypt(master_password.encode())
        with open(DATA_FILE, "wb") as encrypted_file:
            encrypted_file.write(salt + encrypted_message + b'\n')  # Save the salt followed by the encrypted message
        messagebox.showinfo(title="Register", message=f"User registered.")
    except Exception as e:
        messagebox.showinfo(title="Oops", message=f"Error encrypting password! {e}")
        delete_entries()


def write_passwords_safely(updated_lines):
    with tempfile.NamedTemporaryFile('wb', delete=False) as temp_file:
        temp_file.writelines(updated_lines)
        temp_file_path = temp_file.name

    shutil.move(temp_file_path, DATA_FILE)  # Securely move the temporary file to the original file


def change_master_password():
    if not is_logged:
        return

    master_password = master_password_entry.get()
    if len(master_password) == 0:
        messagebox.showinfo(title="Oops", message="Write another password!")
        return

    global master_password_logged
    updated_lines = []  # Re-encrypt all existing passwords with the new master password

    try:
        acquire_lock()
        with open(DATA_FILE, "rb") as encrypted_file:
            is_current_line_first = True

            for line in encrypted_file:
                salt = line[:SALT_SIZE]
                encrypted_message = line[SALT_SIZE:].strip()
                user_key = derive_key(master_password_logged, salt)

                cipher = Fernet(user_key)
                decrypted_message = cipher.decrypt(encrypted_message).decode()
                if is_current_line_first:
                    is_current_line_first = False
                    if decrypted_message == master_password_logged:
                        decrypted_message = master_password

                # Generate a new salt and re-encrypt with the new master password
                new_salt = os.urandom(SALT_SIZE)
                new_user_key = derive_key(master_password, new_salt)
                new_cipher = Fernet(new_user_key)
                new_encrypted_message = new_cipher.encrypt(decrypted_message.encode())

                updated_lines.append(new_salt + new_encrypted_message + b'\n')

        write_passwords_safely(updated_lines)

        master_password_logged = master_password
        messagebox.showinfo(title="Login", message="The master password has been successfully changed!")

        release_lock()

        delete_entries()
        refresh_passwords_window()

    except Exception as e:
        release_lock()
        messagebox.showinfo(title="Oops", message=f"Error changing master password! {e}")


# ---------------------------- PASSWORD GENERATOR ------------------------------- #
def generate_password():
    password_letters = [choice(letters) for _ in range(randint(8, 10))]
    password_symbols = [choice(symbols) for _ in range(randint(2, 4))]
    password_numbers = [choice(numbers) for _ in range(randint(2, 4))]

    password_list = password_letters + password_symbols + password_numbers

    shuffle(password_list)

    password = "".join(password_list)

    password_entry.delete(0, END)
    password_entry.insert(0, password)


# ---------------------------- PASSWORD MANAGER ------------------------------- #
def find_password(website=None, email=None):
    decrypted_lines = []
    found = False
    stored_password = None

    try:
        acquire_lock()
        # Read the file and search for the entry
        with open(DATA_FILE, "rb") as encrypted_file:
            is_current_line_first = True
            for line in encrypted_file:
                salt = line[:SALT_SIZE]
                encrypted_message = line[SALT_SIZE:].strip()
                user_key = derive_key(master_password_logged, salt)

                cipher = Fernet(user_key)
                decrypted_message = cipher.decrypt(encrypted_message).decode()
                decrypted_lines.append((salt, decrypted_message))  # Save the decrypted message with its salt

                if is_current_line_first:
                    is_current_line_first = False
                    continue

                # Check if the entry matches the website and email
                stored_website, stored_email, stored_password = decrypted_message.split(" | ")

                if website and email:
                    if stored_website == website and stored_email == email:
                        found = True
                        break
                elif website:
                    if stored_website == website:
                        found = True
                        break

    except Exception as e:
        release_lock()
        raise Exception(f"Error decrypting password! {e}")

    release_lock()
    return found, stored_website, stored_email, stored_password, decrypted_lines


def show_searched_password(title, content):
    result_window = Toplevel()
    result_window.title(title)
    result_window.iconphoto(False, logo_img)

    text_widget = Text(result_window, wrap="word")
    text_widget.insert("1.0", content)
    text_widget.config(state="disabled")  # Make the text in the Text widget selectable and copyable
    text_widget.pack(padx=10, pady=10, expand=True, fill="both")

    result_window.geometry("300x150")


def search_password():
    if not is_logged:
        return

    website = website_entry.get()
    if len(website) == 0:
        messagebox.showinfo(title="Oops", message="Please fill in the Website field.")
        return

    found, stored_website, stored_email, stored_password, _ = find_password(website=website_entry.get())
    if not found:
        messagebox.showinfo(title=website, message="Password not found for that Website.")
        return

    show_searched_password(title=stored_website,
                           content=f"Email: {stored_email}\nPassword: {stored_password}")


def add_password():
    if not is_logged:
        return

    website = website_entry.get()
    email = email_entry.get()
    password = password_entry.get()

    if len(website) == 0 or len(password) == 0:
        messagebox.showinfo(title="Oops", message="Please make sure you haven't left any fields empty.")
        return

    is_ok = messagebox.askokcancel(title=website, message=f"These are the details entered: "
                                                          f"\nEmail/Username: {email} "
                                                          f"\nPassword: {password} "
                                                          f"\nIs it ok to save?")
    if not is_ok:
        return

    salt = os.urandom(SALT_SIZE)
    user_key = derive_key(master_password_logged, salt)
    cipher = Fernet(user_key)
    message = f"{website} | {email} | {password}"

    try:
        encrypted_message = cipher.encrypt(message.encode())
        acquire_lock()

        with open(DATA_FILE, "ab") as encrypted_file:
            encrypted_file.write(salt + encrypted_message + b'\n')

        release_lock()
        delete_entries()
        refresh_passwords_window()
    except Exception as e:
        release_lock()
        messagebox.showinfo(title="Oops", message=f"Error encrypting password! {e}")


def close_passwords_window():
    global passwords_window_open, passwords_window
    passwords_window_open = False
    passwords_window.destroy()


def refresh_passwords_window():
    if not passwords_window_open:
        return
    close_passwords_window()
    open_passwords_window()


def open_passwords_window():
    if not is_logged:
        return

    global passwords_window_open
    if passwords_window_open:
        return

    passwords_window_open = True

    global passwords_window
    passwords_window = Toplevel(window)
    passwords_window.title("Stored Passwords")
    passwords_window.iconphoto(False, logo_img)

    passwords_window.protocol("WM_DELETE_WINDOW", close_passwords_window)

    frame = Frame(passwords_window)
    frame.pack(fill=BOTH, expand=True)

    scrollbar = Scrollbar(frame)
    scrollbar.pack(side=RIGHT, fill=Y)

    passwords_text = Text(frame, wrap="word", yscrollcommand=scrollbar.set, width=90, height=20)
    passwords_text.pack(side=LEFT, fill=BOTH, expand=True)

    scrollbar.config(command=passwords_text.yview)

    try:
        acquire_lock()

        with open(DATA_FILE, "rb") as encrypted_file:
            for line in encrypted_file:
                salt = line[:SALT_SIZE]
                encrypted_message = line[SALT_SIZE:].strip()
                user_key = derive_key(master_password_logged, salt)

                cipher = Fernet(user_key)
                decrypted_message = cipher.decrypt(encrypted_message).decode()
                passwords_text.insert(END, decrypted_message + "\n")

        release_lock()

    except Exception as e:
        release_lock()
        messagebox.showinfo(title="Oops", message=f"Error decrypting password! {e}")
        return

    passwords_text.config(state="disabled")

    close_button = Button(passwords_window, text="Close", command=close_passwords_window)
    close_button.pack(pady=10)


def edit_password():
    if not is_logged:
        return

    website = website_entry.get()
    email = email_entry.get()

    if len(website) == 0 or len(email) == 0:
        messagebox.showinfo(title="Oops", message="Please fill in both the Website and Email fields.")
        return

    try:
        found, _, _, stored_password, decrypted_lines = find_password(website=website, email=email)

        if found:
            password_entry.delete(0, END)
            password_entry.insert(0, stored_password)
            edit_button.config(text="Update", command=update_password)
            search_button["state"] = "disabled"
            add_button["state"] = "disabled"
            delete_button["state"] = "disabled"
            # Store the decrypted lines globally, so they can be reused in save_edited_password
            global decrypted_password_lines_for_edit
            decrypted_password_lines_for_edit = decrypted_lines
        else:
            messagebox.showinfo(title="Oops", message="No matching entry found.")
            delete_entries()
    except Exception as e:
        messagebox.showinfo(title="Oops", message=f"Error decrypting password! {e}")


def update_password(is_deleting=False):
    website = website_entry.get()
    email = email_entry.get()
    new_password = password_entry.get()

    if not is_deleting:
        if len(website) == 0 or len(email) == 0 or len(new_password) == 0:
            messagebox.showinfo(title="Oops", message="Please fill in all fields before update.")
            return
    elif len(website) == 0 or len(email) == 0:
        messagebox.showinfo(title="Oops", message="Please fill in both the Website and Email fields.")
        return

    updated_lines = []
    updated = False
    is_current_line_first = True

    try:
        for salt, decrypted_message in decrypted_password_lines_for_edit:
            user_key = derive_key(master_password_logged, salt)
            cipher = Fernet(user_key)

            new_encrypted_message = decrypted_message
            if is_current_line_first:
                is_current_line_first = False
            elif not is_deleting:
                stored_website, stored_email, stored_password = decrypted_message.split(" | ")
                if stored_website == website and stored_email == email:
                    new_encrypted_message = f"{website} | {email} | {new_password}"
                    updated = True

            encrypted_message = cipher.encrypt(new_encrypted_message.encode())
            updated_lines.append(salt + encrypted_message + b'\n')

    except Exception as e:
        messagebox.showinfo(title="Oops", message=f"Error encrypting password! {e}")
        delete_entries()
        return

    if updated or is_deleting:
        # Write all lines back to the file
        with open(DATA_FILE, "wb") as encrypted_file:
            encrypted_file.writelines(updated_lines)
        refresh_passwords_window()
    else:
        messagebox.showinfo(title="Error", message="Failed to update the password.")

    edit_button.config(text="Edit", command=edit_password)
    search_button["state"] = "normal"
    add_button["state"] = "normal"
    delete_button["state"] = "normal"
    delete_entries()


def delete_password():
    if not is_logged:
        return

    website = website_entry.get()
    email = email_entry.get()

    if len(website) == 0 or len(email) == 0:
        messagebox.showinfo(title="Oops", message="Please fill in both the Website and Email fields.")
        return

    found = False
    decrypted_lines = []

    try:
        acquire_lock()

        # Read the file and search for the entry
        with open(DATA_FILE, "rb") as encrypted_file:
            is_current_line_first = True

            for line in encrypted_file:
                salt = line[:SALT_SIZE]
                encrypted_message = line[SALT_SIZE:].strip()
                user_key = derive_key(master_password_logged, salt)
                cipher = Fernet(user_key)

                decrypted_message = cipher.decrypt(encrypted_message).decode()

                if is_current_line_first:
                    is_current_line_first = False
                    decrypted_lines.append((salt, decrypted_message))  # Save the decrypted message with its salt
                    continue

                # Check if the entry matches the website and email
                stored_website, stored_email, stored_password = decrypted_message.split(" | ")
                if stored_website == website and stored_email == email:
                    password = stored_password
                    found = True
                else:
                    decrypted_lines.append((salt, decrypted_message))

        release_lock()

    except Exception as e:
        release_lock()
        messagebox.showinfo(title="Oops", message=f"Error decrypting password! {e}")
        return

    if not found:
        messagebox.showinfo(title="Oops", message="No matching entry found.")
        delete_entries()
    else:
        is_ok = messagebox.askokcancel(title=website, message=f"These are the details to delete: "
                                                              f"\nWebsite: {website} "
                                                              f"\nEmail/Username: {email} "
                                                              f"\nPassword: {password} "
                                                              f"\nIs it ok to save?")
        if is_ok:
            # Store the decrypted lines globally, so they can be reused in save_edited_password
            global decrypted_password_lines_for_edit
            decrypted_password_lines_for_edit = decrypted_lines
            update_password(True)


# ---------------------------- UI SETUP ------------------------------- #
def delete_entries():
    master_password_entry.delete(0, END)
    website_entry.delete(0, END)
    password_entry.delete(0, END)


window = Tk()
window.title("Password Manager")
logo_img = PhotoImage(file="resources/logo.png")
window.iconphoto(False, logo_img)
window.config(padx=50, pady=50)

canvas = Canvas(height=200, width=200)
canvas.create_image(100, 100, image=logo_img)
canvas.grid(row=0, column=1, columnspan=2)

# Labels
master_password_label = Label(text="Master Password:")
master_password_label.grid(row=1, column=0, sticky="E")
website_label = Label(text="Website:")
website_label.grid(row=2, column=0, sticky="E")
email_label = Label(text="Email/Username:")
email_label.grid(row=3, column=0, sticky="E")
password_label = Label(text="Password:")
password_label.grid(row=4, column=0, sticky="E")

# Entries
master_password_entry = Entry(width=27)
master_password_entry.grid(row=1, column=1, padx=(0, 5), sticky="EW")
master_password_entry.focus()
website_entry = Entry(width=45)
website_entry.grid(row=2, column=1, columnspan=2, padx=(0, 5), sticky="EW")
email_entry = Entry(width=45)
email_entry.grid(row=3, column=1, columnspan=2, sticky="EW")
email_entry.insert(0, "@")
password_entry = Entry(width=27)
password_entry.grid(row=4, column=1, padx=(0, 5), sticky="EW")

# Buttons
login_button = Button(text="Login", command=login)
login_button.grid(row=1, column=2, sticky="EW")
register_button = Button(text="Register", command=register)
register_button.grid(row=1, column=3, sticky="EW")
change_button = Button(text="Change", command=change_master_password)
change_button.grid(row=1, column=4, sticky="EW")
change_button["state"] = "disabled"

search_button = Button(text="Search", command=search_password)
search_button.grid(row=2, column=3, columnspan=2, sticky="EW")
search_button["state"] = "disabled"

generate_password_button = Button(text="Generate Password", command=generate_password)
generate_password_button.grid(row=4, column=2, sticky="EW")

open_button = Button(text="Open", width=38, command=open_passwords_window)
open_button.grid(row=5, column=1, columnspan=2, sticky="EW")
open_button["state"] = "disabled"

add_button = Button(text="Add", command=add_password)
add_button.grid(row=6, column=1, sticky="EW")
add_button["state"] = "disabled"
edit_button = Button(text="Edit", command=edit_password)
edit_button.grid(row=6, column=2, sticky="EW")
edit_button["state"] = "disabled"
delete_button = Button(text="Delete", command=delete_password)
delete_button.grid(row=6, column=3, sticky="EW")
delete_button["state"] = "disabled"

window.mainloop()
