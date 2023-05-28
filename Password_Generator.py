import customtkinter as tk
import customtkinter
import string
import random
import pyperclip
from tkinter import messagebox

# Define a function to generate a random password
def generate_password():
    # Get the desired password length from the text box
    password_length = int(length_entry.get())


    # Define the characters to use in the password
    password_chars = string.ascii_letters
    if include_numbers.get():
        password_chars += string.digits
    if include_special_chars.get():
        password_chars += string.punctuation
 

    # Generate a password with the desired length
    password = ''.join(random.choice(password_chars) for i in range(password_length))

    # Update the label to display the generated password
    password_label.configure(text=password)
    check_password_strength(password)

def check_password_strength(password):
    strength_label.configure(text="Password Strength: ", text_color="black")
    if len(password) < 8:
        strength_label.configure(text="Weak", text_color="red", font=("Arial", 18))
    elif len(password) < 12:
        strength_label.configure(text="Medium", text_color="orange",font=("Arial", 18))
    else:
        strength_label.configure(text="Strong", text_color="green",font=("Arial", 18))

def encrypt_password():
    password = password_label.cget("text")
    encrypted_password = encrypt(password)
    password_label.configure(text=encrypted_password)


def encrypt(text):
    encrypted_text = ""
    key = 7  # Encryption key (adjust this as needed)

    for char in text:
        encrypted_char = chr(ord(char) + key)
        encrypted_text += encrypted_char
    return encrypted_text
def decrypt_password():
    password = password_label.cget("text")
    decrypted_password = decrypt(password)
    password_label.configure(text=decrypted_password)

def decrypt(text):
    decrypted_text = ""
    key = 7  # Encryption key (should be the same as used for encryption)

    for char in text:
        decrypted_char = chr(ord(char) - key)
        decrypted_text += decrypted_char
    return decrypted_text
# Create the main window
root = tk.CTk()
root.title("Password Generator")
root.geometry("400x480")
root.config(background="#A9DFBF")
customtkinter.set_default_color_theme("blue")

# Create a label for the password length text box
length_label = tk.CTkLabel(root, text="Password length:", font=("Arial", 18),bg_color="#A9DFBF")
length_label.pack()

# Create a text box for the password length
length_entry = tk.CTkEntry(root, font=("Arial", 14),bg_color="#A9DFBF")
length_entry.pack(pady=10)

# Create a check box for including numbers in the password
include_numbers = tk.BooleanVar()
number_check = tk.CTkCheckBox(root, text="Include numbers", font=("Arial", 14),bg_color="#A9DFBF", variable=include_numbers,fg_color="#16A085",hover_color="#16A085")
number_check.pack(pady=10)

# Create a check box for including special characters in the password
include_special_chars = tk.BooleanVar()
special_check = tk.CTkCheckBox(root, text="Include special characters",bg_color="#A9DFBF", font=("Arial", 14), variable=include_special_chars,fg_color="#16A085",hover_color="#16A085")
special_check.pack(pady=10)

# Create a button to generate a new password
generate_button = tk.CTkButton(root, text="Generate Password", font=("Arial", 16),bg_color="#A9DFBF", command=generate_password,fg_color="#16A085",hover_color="#117864")
generate_button.pack(pady=10)


# Create a label to display the generated password
password_label = tk.CTkLabel(root, text="", font=("Arial", 16),bg_color="#A9DFBF")
password_label.pack(pady=10)

strength_label1 = tk.CTkLabel(root, text="Password Strength:", font=("Arial", 16),bg_color="#A9DFBF")
strength_label1.pack()

strength_label = tk.CTkLabel(root,text="", font=("Arial", 16),bg_color="#A9DFBF")
strength_label.pack()


encrypt_button = tk.CTkButton(root, text="Encrypt Password", font=("Arial", 16), command=encrypt_password,bg_color="#A9DFBF",fg_color="#16A085",hover_color="#117864")
encrypt_button.pack(pady=10)
encrypt_button = tk.CTkButton(root, text="Decrypt Password", font=("Arial", 16), command=decrypt_password,bg_color="#A9DFBF",fg_color="#16A085",hover_color="#117864")
encrypt_button.pack(pady=10)

# Run the main event loop
root.mainloop()
