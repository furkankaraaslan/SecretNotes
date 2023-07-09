import tkinter
from tkinter import *
from tkinter import messagebox
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

window = tkinter.Tk()
window.title("Secret Notes")
window.minsize(width=550, height=850)

picture = PhotoImage(file="image.png")
picture_label = Label(image=picture)
picture_label.place(x=185, y=80)

t1_label = Label(text="Enter Your Title", font=("Arial", 14))
t1_label.place(x=215, y=260)

e1_entry = Entry(width=30)
e1_entry.place(x=150, y=290)

note_label = Label(text="Encrypt and Decrypt Your Notes", font=("Arial", 14))
note_label.place(x=155, y=320)

text_area = Text(width=40, height=15)
text_area.place(x=120, y=350)

key_label = Label(text="Enter Master Key", font=("Arial", 14))
key_label.place(x=200, y=670)

key_entry = Entry(width=55)
key_entry.place(x=55, y=700)


def save_and_enc():
    title_entry = e1_entry.get()
    text_entry = text_area.get(1.0, END)
    pass_from_user = key_entry.get()
    if title_entry == "" or len(text_entry) <= 1 or pass_from_user == "":
        messagebox.showwarning("Warning", "Please Enter All Information")
    else:
        text_entry_byte = text_entry.encode('utf-8')
        key = gen_fernet_key(pass_from_user)

        with open("secretFile.txt", mode="a") as mySecretFile:
            mySecretFile.write(title_entry + '\n')
            encrypted_contents_byte = Fernet(key).encrypt(text_entry_byte)
            encrypted_contents = encrypted_contents_byte.decode('utf-8')
            mySecretFile.write(encrypted_contents + '\n')
            mySecretFile.close()


def decrypt():
    text_to_decrypt = text_area.get(1.0, END)
    key_from_user = key_entry.get()
    if len(text_to_decrypt) <= 1 or key_from_user == "":
        messagebox.showwarning("Warning", "Please Enter All Information")
    else:
        try:
            key = gen_fernet_key(key_from_user)
            decrypted_content = (Fernet(key).decrypt(text_to_decrypt)).decode()
            text_area.delete('1.0', END)
            text_area.insert(END, decrypted_content)
        except:
            messagebox.showerror("Error", "Please Check Your \nPassword and Content")


def gen_fernet_key(pass_key_from_user):
    password = pass_key_from_user.encode()
    my_salt = b':T9\xb3\x1d\x84\xfe\xb8you\xf0\xfft0\xf5'

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=my_salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key


save_encrypt_button = Button(text="Save & Encrypt", font=("Arial", 11), command=lambda: [f for f in [gen_fernet_key, save_and_enc()]])
save_encrypt_button.place(x=210, y=740)

decrypt_button = Button(text="Decrypt", font=("Arial", 11), command=lambda: [f for f in [gen_fernet_key, decrypt()]])
decrypt_button.place(x=235, y=780)

window.mainloop()
