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
def setup_2FA() -> str:
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

def main():
    enter_helper()
    grant_perms("master.json")

if __name__ == "__main__":
    main()