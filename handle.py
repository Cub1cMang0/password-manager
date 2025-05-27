from main_work import *
from math import floor
import pygetwindow
import time
import pyotp
import qrcode
import customtkinter, tkinter
from tkinter import *
from tkinter import filedialog
from PIL import Image

# Returns a PIL.Image of the qr code setup for 2FA.
def open_image():
    enter_helper()
    image = Image.open("setup.png")
    exit_helper()
    return image

# Provides the user with a QR Code and url to set up 2FA on their phone, computer, or whatever.
def setup_qr_code() -> str:
    key = pyotp.random_base32()
    enter_helper()
    grant_perms("master.json")
    with open("master.json", "r") as file:
        data = json.load(file)
    twoFA = {"2FA" : key}
    data.append(twoFA)
    with open("master.json", "w") as file:
        json.dump(data, file, indent=4)
    uri = pyotp.totp.TOTP(key).provisioning_uri(
        name='2FA',
        issuer_name='PM')
    qrcode.make(uri).save("setup.png")
    rm_perms("master.json")
    exit_helper()
    return key

# Standard 2FA check for security
def check_2FA(code: int) -> bool:
    enter_helper()
    grant_perms("master.json")
    with open("master.json", "r") as file:
        data = json.load(file)
    rm_perms("master.json")
    exit_helper()
    source = None
    for section in data:
        if "2FA" in section:
            source = section["2FA"]
    totp = pyotp.TOTP(source)
    result = totp.verify(code)
    return result

# Check if the user has 2FA setup (used to avoid or prompt the user of using features that requrie 2FA to be setup).
def is2FAsetup() -> bool:
    enter_helper()
    if not os.path.exists("master.json"):
        exit_helper()
        return False
    grant_perms("master.json")
    with open("master.json", "r") as file:
        data = json.load(file)
    rm_perms("master.json")
    exit_helper()
    source = None
    for section in data:
        if "2FA" in section:
            source = section["2FA"]
    if source == None:
        return False
    elif source != None:
        return True

# 2FA disabling logic
def disable_2FA() -> None:
    enter_helper()
    grant_perms("master.json")
    with open("master.json", "r") as file:
        data = json.load(file)
    salt_holder = ''
    hash_holder = ''
    for section in data:
        if "salt" in section:
            salt_holder = section["salt"]
        if "hash" in section:
            hash_holder = section["hash"]
    no_2FA_data = {
        "salt": salt_holder,
        "hash": hash_holder
    }
    new_data = []
    new_data.append(no_2FA_data)
    with open("master.json", "w") as file:
        json.dump(new_data, file, indent=4)
    rm_perms("master.json")
    exit_helper()

# Since 2FA can be enabled later and startup, it makes sense to create a function for it
def setup2FA(yb, nb, app) -> None:
    yb.pack_forget()
    nb.pack_forget()
    twoFA_key = setup_qr_code()
    qr_code = open_image()
    qr_code_image = customtkinter.CTkImage(light_image=qr_code, dark_image=qr_code, size=(550, 550))
    cur_prompt = customtkinter.CTkToplevel()
    cur_prompt.geometry("700x790")
    cur_frame = customtkinter.CTkFrame(cur_prompt)
    cur_frame.pack(padx=20, pady=20, expand=True)
    cur_label = customtkinter.CTkLabel(cur_frame, image=qr_code_image, text=f"Manual 2FA Key: {twoFA_key}", compound="top")
    cur_label.pack(padx=20, pady=20)
    twoFA_entry = customtkinter.CTkEntry(cur_frame, placeholder_text="Enter 2FA Code Here", width=200, height=35, border_width=2, corner_radius=10)
    twoFA_entry.pack(padx=20,pady=0)
    def submit_2FA():
        code_2FA = twoFA_entry.get()
        successful = check_2FA(code_2FA)
        if successful:
            cur_prompt.destroy()
            app.deiconify()
        else:
            cur_label.configure(image=qr_code_image, text=f"Manual 2FA Key: {twoFA_key}" + "\nIncorrect Code", compound="top")
            twoFA_entry.delete(0, "end")
    submit_2FA_b = customtkinter.CTkButton(cur_frame, text="Submit", command=submit_2FA)
    submit_2FA_b.pack(padx=20, pady=10)
    cur_label.image = qr_code_image

# Stores the user's given password in the hidden directory.
def store(word: str, desc: str) -> None:
    yes = manage(word, desc)
    yes.setup()
    yes.encrypt()
    if os.path.exists(".helper"):
        enter_helper()
        yes.save_info()
        exit_helper()
    else:
        hidden_dir(".helper")
        os.chdir(".helper")
        yes.save_info()
        exit_helper()

# Deletes a password that the user stored. Will return certain numbers depending if it was successful or not.
def delete(word: str, desc: str) -> int:
    yes = manage(None, None)
    success = yes.load_info(desc)
    if success == 1:
        yes.decrypt()
        check = yes.password.decode()
        if word == check:
            enter_helper()
            with open('manager.json', 'r') as file:
                data = json.load(file)
            data = [entry for entry in data if entry.get('desc') != desc]
            with open('manager.json', 'w') as file:
                json.dump(data, file, indent=4)
            exit_helper()
            return 2
        else:
            return 3
    else:
        return 3

# Retrieves password from given description.
def fetch(desc: str) -> str:
    yeah = manage(None, None)
    success = yeah.load_info(desc)
    if success == 1:
        yeah.decrypt()
        here_it_is = yeah.password.decode()
        yeah = manage(None, None)
        return here_it_is
    else:
        return ''

# Provides access to manager.json
def access():
    enter_helper()
    with open("manager.json", "r") as file:
        data = json.load(file)
    exit_helper()
    return data

# Sets the user's master password
def master(passyword: str) -> None:
    enter_helper()
    set_master(passyword)

# Master password creation and storage logic
def set_master(master_p: str) -> None:
    user_salt = bcrypt.gensalt()
    hashed_master = bcrypt.hashpw(master_p.encode(), user_salt)
    user_salt = b64encode(user_salt).decode("utf-8")
    hashed_master = b64encode(hashed_master).decode("utf-8")
    info = {
        "salt" : user_salt,
        "hash" : hashed_master
    }
    data = []
    data.append(info)
    exit_helper()
    if not is2FAsetup():
        enter_helper()
        with open("master.json", "w") as file:
            json.dump(data, file, indent=4)
        exit_helper()
    else:
        enter_helper()
        grant_perms("master.json")
        with open("master.json", "r") as file:
            data = json.load(file)
        for data_entry in data:
            if "salt" in data_entry:
                data_entry["salt"] = user_salt
            if "hash" in data_entry:
                data_entry["hash"] = hashed_master
        with open("master.json", "w") as file:
            json.dump(data, file, indent=4)
        rm_perms("master.json")
        exit_helper()

# Used to check if the user has already gone through the setup phase.
def first_time() -> bool:
    enter_helper()
    if os.path.exists("master.json"):
        isFirst = False
    else:
        isFirst = True
    exit_helper()
    return isFirst

# Used to check for the presence of manager.json
def present() -> bool:
    enter_helper()
    exists = os.path.exists("manager.json")
    exit_helper()
    return exists

# Used for the main window instead of sub windows
def big_yes_no_buttons(framework, conf_type):
    yes_button = customtkinter.CTkButton(master=framework, text="Yes", command=lambda decision=1: conf_type(decision))
    yes_button.place(relx=0.35, rely=0.6, anchor=tkinter.CENTER)
    no_button = customtkinter.CTkButton(master=framework, text="No", command=lambda decision=0: conf_type(decision))
    no_button.place(relx=0.65, rely=0.6, anchor=tkinter.CENTER)
    return yes_button, no_button

# Used for subwindows since the function above doesn't interact well with it.
def small_yes_no_buttons(framework, conf_type):
    yes_button = customtkinter.CTkButton(master=framework, text="Yes", command=lambda decision=1: conf_type(decision))
    yes_button.pack(side=tkinter.LEFT, padx=(20, 10), pady=20)
    no_button = customtkinter.CTkButton(master=framework, text="No", command=lambda decision=0: conf_type(decision))
    no_button.pack(side=tkinter.RIGHT, padx=(10, 20), pady=20)
    return yes_button, no_button

def main():
    enter_helper()
    grant_perms("master.json")

if __name__ == "__main__":
    main()