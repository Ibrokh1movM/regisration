import tkinter as tk
from tkinter import messagebox
import sqlite3

conn = sqlite3.connect('users.db')
c = conn.cursor()

c.execute('''
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    parol TEXT NOT NULL,
    login_try_count INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 0
)
''')
conn.commit()

def get_user_by_username(username):
    """
    this function is used to get a user by username
    :param username:
    :return:
    """
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    return c.fetchone()

def get_all_users():
    """
    this function is used to get all users
    :return:
    """
    c.execute("SELECT * FROM users")
    return c.fetchall()


def register_user():
    """
    this function is used to register a user
    :return:
    """
    username = username_entry.get()
    password = password_entry.get()

    if get_user_by_username(username):
        messagebox.showerror("Error", "Username already exists, please choose another one.")
        return

    if username and password:
        c.execute("INSERT INTO users (username, parol) VALUES (?, ?)", (username, password))
        conn.commit()
        messagebox.showinfo("Success", f"User {username} has been registered.")
        show_main_menu()
    else:
        messagebox.showerror("Error", "Please fill in all fields.")

def reset_password(user):
    """
    this function is used to reset a password
    :param user:
    :return:
    """
    new_password = password_entry.get()
    if new_password:
        c.execute("UPDATE users SET parol=?, login_try_count=0 WHERE username=?", (new_password, user[0]))
        conn.commit()
        messagebox.showinfo("Success", f"Password for {user[0]} has been reset.")
        show_main_menu()
    else:
        messagebox.showwarning("Cancelled", "Password reset cancelled.")

def attempt_login():
    """
    this function is used to login a user
    :return:
    """
    username = username_entry.get()
    user = get_user_by_username(username)

    if user is None:
        messagebox.showerror("Error", "Invalid username")
        return

    if user[2] >= 3:
        reset_option = messagebox.askyesno("Blocked",
                                           f"This {user[0]} account is blocked. Do you want to reset the password?")
        if reset_option:
            show_reset_password(user)
        return

    password = password_entry.get()

    if user[1] != password:
        c.execute("UPDATE users SET login_try_count=login_try_count+1 WHERE username=?", (username,))
        conn.commit()
        user = get_user_by_username(username)
        if user[2] >= 3:
            messagebox.showerror("Error", f"This {user[0]} account is blocked!!!")
        else:
            messagebox.showerror("Error", "Wrong password, please try again")
    else:
        c.execute("UPDATE users SET is_active=1, login_try_count=0 WHERE username=?", (username,))
        conn.commit()
        messagebox.showinfo("Success", "Login is successful")
        show_main_menu()


def show_main_menu():
    """
    this function is used to show main menu
    :return:
    """
    clear_window()
    tk.Button(root, text="Login", command=show_login_screen, width=20).pack(pady=10)
    tk.Button(root, text="Register", command=show_register_screen, width=20).pack(pady=10)
    tk.Button(root, text="Admin Panel", command=show_admin_login_screen, width=20).pack(pady=10)

def show_login_screen():
    """
    this function is used to show login screen
    :return:
    """
    clear_window()
    tk.Label(root, text="Username:", font=("Helvetica", 14)).pack(pady=5)
    global username_entry
    username_entry = tk.Entry(root, font=("Helvetica", 14))
    username_entry.pack(pady=5)

    tk.Label(root, text="Password:", font=("Helvetica", 14)).pack(pady=5)
    global password_entry
    password_entry = tk.Entry(root, show='*', font=("Helvetica", 14))
    password_entry.pack(pady=5)

    tk.Button(root, text="Show Password", command=toggle_password_visibility, font=("Helvetica", 14)).pack(
        pady=5)
    tk.Button(root, text="Login", command=attempt_login, font=("Helvetica", 14)).pack(pady=10)
    tk.Button(root, text="Back", command=show_main_menu, font=("Helvetica", 14)).pack(pady=5)

def show_register_screen():
    """
    this function is used to show register screen
    :return:
    """
    clear_window()
    tk.Label(root, text="Enter new username:", font=("Helvetica", 14)).pack(pady=5)
    global username_entry
    username_entry = tk.Entry(root, font=("Helvetica", 14))
    username_entry.pack(pady=5)

    tk.Label(root, text="Enter new password:", font=("Helvetica", 14)).pack(pady=5)
    global password_entry
    password_entry = tk.Entry(root, show='*', font=("Helvetica", 14))
    password_entry.pack(pady=5)

    tk.Button(root, text="Show Password", command=toggle_password_visibility, font=("Helvetica", 14)).pack(
        pady=5)
    tk.Button(root, text="Register", command=register_user, font=("Helvetica", 14)).pack(pady=10)
    tk.Button(root, text="Back", command=show_main_menu, font=("Helvetica", 14)).pack(pady=5)

def show_reset_password(user):
    """
    this function is used to show reset password
    :param user:
    :return:
    """
    clear_window()
    tk.Label(root, text=f"Enter new password for {user[0]}", font=("Helvetica", 14)).pack(pady=5)

    global password_entry
    password_entry = tk.Entry(root, show='*', font=("Helvetica", 14))
    password_entry.pack(pady=5)

    tk.Button(root, text="Reset Password", command=lambda: reset_password(user), font=("Helvetica", 14)).pack(pady=10)
    tk.Button(root, text="Back", command=show_main_menu, font=("Helvetica", 14)).pack(pady=5)

def show_admin_login_screen():
    """
    this function is used to show admin login screen
    :return:
    """
    clear_window()
    tk.Label(root, text="Enter admin password:", font=("Helvetica", 14)).pack(pady=5)
    admin_password_entry = tk.Entry(root, show='*', font=("Helvetica", 14))
    admin_password_entry.pack(pady=5)

    tk.Button(root, text="Login", command=lambda: check_admin_password(admin_password_entry.get()),
              font=("Helvetica", 14)).pack(pady=10)
    tk.Button(root, text="Back", command=show_main_menu, font=("Helvetica", 14)).pack(pady=5)

def check_admin_password(password):
    """
    this function is used to check admin password
    :param password:
    :return:
    """
    if password == '0000':
        show_admin_panel()
    else:
        messagebox.showerror("Error", "Invalid admin password")

def show_admin_panel():
    """
    this function show admin panel
    :return:
    """
    clear_window()
    tk.Label(root, text="Registered Users", font=("Helvetica", 16)).pack(pady=10)

    users = get_all_users()
    for user in users:
        user_info = f"Username: {user[0]}, Password: {user[1]}"
        tk.Label(root, text=user_info, font=("Helvetica", 12)).pack(pady=5)

        delete_button = tk.Button(root, text=f"Delete {user[0]}", command=lambda u=user: delete_user(u[0]),
                                  font=("Helvetica", 12), bg="red")
        delete_button.pack(pady=2)

    tk.Button(root, text="Back", command=show_main_menu, font=("Helvetica", 14)).pack(pady=10)

def delete_user(username):
    """
    this function is used to delete user
    :param username:
    :return:
    """
    c.execute("DELETE FROM users WHERE username=?", (username,))
    conn.commit()
    messagebox.showinfo("Success", f"User {username} has been deleted.")
    show_admin_panel()

def clear_window():
    """
    this function is used to clear window
    :return:
    """
    for widget in root.winfo_children():
        widget.destroy()

def toggle_password_visibility():
    """
    this function is used to toggle password visibility
    :return:
    """
    if password_entry.cget('show') == '*':
        password_entry.config(show='')
    else:
        password_entry.config(show='*')


root = tk.Tk()
root.title("Login System")

root.geometry("400x400")

show_main_menu()
root.mainloop()

conn.close()