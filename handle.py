from main_work import *
from math import floor
import pygetwindow
import time
import pyotp
import qrcode
import customtkinter, tkinter
from tkinter import *
from PIL import Image

def open_image():
    enter_helper()
    image = Image.open("setup.png")
    exit_helper()
    return image

# Provides the user with a QR Code and url to set up 2FA on their phone or whatever
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

def access():
    enter_helper()
    with open("manager.json", "r") as file:
        data = json.load(file)
    exit_helper()
    return data

def master(passyword: str) -> None:
    enter_helper()
    set_master(passyword)
    exit_helper()

def first_time() -> bool:
    enter_helper()
    if os.path.exists("master.json"):
        isFirst = False
    else:
        isFirst = True
    exit_helper()
    return isFirst

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