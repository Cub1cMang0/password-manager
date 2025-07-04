from main_work import *
import main_work
from math import floor
import pygetwindow
import time
import pyotp, qrcode, shutil
import customtkinter as ctk
import tkinter
from tkinter import *
from tkinter import filedialog
from PIL import Image
import pyperclip
import cryptography, secrets

# Returns a PIL.Image of the qr code setup for 2FA.
def open_image():
    enter_helper()
    image = Image.open("setup.png")
    exit_helper()
    return image

# Provides the user with a QR Code and url to set up 2FA on their phone, computer, or whatever.
def setup_qr_code_image() -> str:
    enter_helper()
    key = pyotp.random_base32()
    uri = pyotp.totp.TOTP(key).provisioning_uri(
        name='2FA',
        issuer_name='PM')
    qrcode.make(uri).save("setup.png")
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
def setup2FA(yb, nb, success_function=None) -> None:
    yb.pack_forget()
    nb.pack_forget()
    twoFA_key = setup_qr_code_image()
    qr_code = open_image()
    qr_code_image = ctk.CTkImage(light_image=qr_code, dark_image=qr_code, size=(550, 550))
    cur_prompt = ctk.CTkToplevel()
    cur_prompt.title("Setup 2FA")
    cur_prompt.geometry("700x790")
    cur_frame = ctk.CTkFrame(cur_prompt)
    cur_frame.pack(padx=20, pady=20, expand=True)
    cur_label = ctk.CTkLabel(cur_frame, image=qr_code_image, text=f"Manual 2FA Key: {twoFA_key}", compound="top")
    cur_label.pack(padx=20, pady=20)
    twoFA_entry = ctk.CTkEntry(cur_frame, placeholder_text="Enter 2FA Code Here", width=200, height=35, border_width=2, corner_radius=10)
    twoFA_entry.pack(padx=20,pady=0)
    def submit_2FA():
        code_2FA = twoFA_entry.get()
        totp = pyotp.TOTP(twoFA_key)
        successful = totp.verify(code_2FA)
        if successful:
            enter_helper()
            grant_perms("master.json")
            with open("master.json", "r") as file:
                data = json.load(file)
            twoFA = {"2FA" : twoFA_key}
            data.append(twoFA)
            with open("master.json", "w") as file:
                json.dump(data, file, indent=4)
            rm_perms("master.json")
            exit_helper()
            cur_prompt.destroy()
            if not isinstance(success_function, type(None)):
                success_function()
        else:
            cur_label.configure(image=qr_code_image, text=f"Manual 2FA Key: {twoFA_key}" + "\nIncorrect code", compound="top")
            twoFA_entry.delete(0, "end")
    submit_2FA_b = ctk.CTkButton(cur_frame, text="Submit", command=submit_2FA)
    submit_2FA_b.pack(padx=20, pady=10)
    cur_label.image = qr_code_image
    cur_prompt.grab_set()

def recover_account(rec_button, previous_prompt, success_function) -> None:
    previous_prompt.destroy()
    rec_button.pack_forget()
    recover_prompt = ctk.CTkToplevel()
    recover_prompt.title("Recover Account")
    recover_prompt.geometry("720x480")
    recover_frame = ctk.CTkFrame(recover_prompt)
    recover_frame.pack(padx=20, pady=20)
    recover_label = ctk.CTkLabel(recover_frame, text="Enter the recovery key that was provided during setup")
    recover_label.pack(padx=20, pady=20)
    recover_entry = ctk.CTkEntry(recover_frame, placeholder_text="Enter Recovery Key Here")
    recover_entry.pack(padx=20, pady=20)
    def submit_recovery_key():
        successful = check_recovery_key(recover_entry.get())
        if successful:
            recover_prompt.destroy()
            success_function()
        else:
            recover_label.configure(text="Incorrect recovery key")
            recover_entry.delete(0, "end")
    submit_key = ctk.CTkButton(recover_frame, text="Submit", command=submit_recovery_key)
    submit_key.pack(padx=20, pady=20)
    recover_prompt.grab_set()


def retrieve_2FA_key() -> str:
    enter_helper()
    with open("manager.json", "r") as file:
        data = json.load(file)
    exit_helper()
    return data["saltier"]

# Selects an algorithm for the password managing logic (and to stick to)
def select_base() -> str:
    letter_range = string.ascii_lowercase[23:25]
    rand_letter = random.choice(letter_range)
    return rand_letter

def check_base() -> str:
    enter_helper()
    if os.path.exists("manager.json"):
        grant_perms("manager.json")
        key, re_enc_data, storage_data = dec_file(main_work.QUI, main_work.AUTH_TYPE, "manager.json")
        base = storage_data[0]["yes"]
        re_enc_file(key, re_enc_data, storage_data, "manager.json")
        rm_perms("manager.json")
    else:
        base = select_base()
    exit_helper()
    return base

# General function to check password strength and to steer the user into making stronger passwords.
def check_strength(criteria: str, entry_widget, entry_label) -> None:
    current_input = entry_widget.get()
    if current_input == "Password Length":
        entry_label.configure(text="")
        return
    if current_input != '' and current_input.isdigit():
        length = int(current_input)
        if criteria == "Password Length":
            if length < 8:
                entry_label.configure(text="Password is too short", text_color="red")
            elif length >= 8 and length < 16:
                entry_label.configure(text="Ok", text_color="yellow")
            elif length > 15 and length < 65:
                entry_label.configure(text="Strong", text_color="green")
            elif length > 64:
                entry_label.configure(text="Password is too long", text_color="red")
            else:
                entry_label.configure(text="")
        else:
            if length <= 2:
                entry_label.configure(text="Weak", text_color="red")
            elif length >=3 and length < 5:
                entry_label.configure(text="Ok", text_color="yellow")
            elif length >= 5:
                entry_label.configure(text="Strong", text_color="green")
            else:
                entry_label.configure(text="")
    else:
        entry_label.configure(text="")

# Password-generating function that includes all letters a-Z, numbers 0-9, and non conflicting symbols "!@#$%^&*()-_=+[]{};:,.?/"
def generate_passyword(selection: list, length) -> str:
    passyword = ''
    if length.get() == '':
        return "Password length not specified"
    else:
        passy_length = int(length.get())
        remaining = int(length.get())
    if passy_length > 64:
        return "Password is too long"
    if passy_length < 8:
        return "Password is too short"
    selected = []
    selection_length = 0
    letters_length = ''
    numbers_length = ''
    symbols_length = ''
    for i in range(len(selection)):
        if i == 0:
            if selection[0][1] != '':
                letters_length = int(selection[0][1])
                selection_length += letters_length
            if selection[0][0] == 1:
                selected.append("Letters")
        elif i == 1:
            if selection[1][1] != '':
                numbers_length = int(selection[1][1])
                selection_length += numbers_length
            if selection[1][0]:
                selected.append("Numbers")
        elif i == 2:
            if selection [2][1] != '':
                symbols_length = int(selection[2][1])
                selection_length += symbols_length
            if selection[2][0] == 1:
                selected.append("Symbols")
    if passy_length < selection_length:
        return f"Password length and requested characters don't match ({passy_length} vs {selection_length})" 
    elif selection[0][0] == 0 and selection [1][0] == 0 and selection [2][0] == 0:
        return "Password criteria hasn't been selected"
    elif selection[0][1] == '' and selection [1][1] == '' and selection [2][1] == '' and selection[0][0] == 1 and selection [1][0] == 1 and selection [2][0] == 1:
        passyword = ''.join(random.choice(string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.?/") for _ in range(passy_length))
        return passyword
    else:
        if letters_length != '':
            passyword += ''.join(random.choice(string.ascii_letters) for _ in range(letters_length))
            remaining -= letters_length
        if numbers_length != '':
            passyword += ''.join(random.choice(string.digits) for _ in range(numbers_length))
            remaining -= numbers_length
        if symbols_length != '':
            passyword += ''.join(random.choice("!@#$%^&*()-_=+[]{};:,.?/") for _ in range(symbols_length))
            remaining -= symbols_length
    if remaining != 0:
        while remaining != 0:
            char_type = random.choice(selected)
            random_amount = random.randint(1, remaining)
            if char_type == "Letters":
                passyword += ''.join(random.choice(string.ascii_letters) for _ in range(random_amount))
            elif char_type == "Numbers":
                passyword += ''.join(random.choice(string.digits) for _ in range(random_amount))
            elif char_type == "Symbols":
                passyword += ''.join(random.choice("!@#$%^&*()-_=+[]{};:,.?/") for _ in range(random_amount))
            remaining -= random_amount
    return passyword

# Stores the user's given password in the hidden directory.
def store(word: str, desc: str) -> None:
    base = check_base()
    enter_helper()
    try:
        grant_perms("manager.json")
        key, re_enc_data, storage_data = dec_file(main_work.QUI, main_work.AUTH_TYPE, "manager.json")
        with open("manager.json", "r") as file:
            data = json.load(file)
        desc_section = data[0]["data"]
        for description in desc_section:
            existing_descs = {d["desc"] for d in desc_section}
            if desc not in existing_descs:
                final_desc = desc
            else:
                i = 1
                while f"{desc} ({i})" in existing_descs:
                    i += 1
                final_desc = f"{desc} ({i})"
            desc = final_desc
        re_enc_file(key, re_enc_data, storage_data, "manager.json")
    except:
        pass
    if base == "z":
        yes = PM_Z(word, desc)
    elif base == "y":
        yes = PM_Y(word, desc)
    elif base == "x":
        yes = PM_X(word, desc)
    yes.setup()
    yes.encrypt()
    yes.save_info()
    rm_perms("manager.json")
    exit_helper()


# Deletes a password that the user stored. Will return certain numbers depending if it was successful or not.
def delete(word: str, desc: str) -> int:
    base = check_base()
    if base == "z":
        yes = PM_Z(None, None)
    elif base == "y":
        yes = PM_Y(None, None)
    elif base == "x":
        yes = PM_X(None, None)
    success = yes.load_info(desc)
    if success:
        yes.decrypt()
        check = yes.password.decode()
        if word == check:
            enter_helper()
            grant_perms("manager.json")
            key, re_enc_data, storage_data = dec_file(main_work.QUI, main_work.AUTH_TYPE, "manager.json")
            storage_data[0]["data"] = [entry for entry in storage_data[0]["data"] if entry.get('desc') != desc]
            re_enc_file(key, re_enc_data, storage_data, "manager.json")
            rm_perms("manager.json")
            exit_helper()
            delete_result = 2
        else:
            delete_result = 3
    else:
        delete_result = 3
    return delete_result

# Retrieves password from given description.
def fetch(desc: str) -> str:
    base = check_base()
    if base == "z":
        yes = PM_Z(None, None)
    elif base == "y":
        yes = PM_Y(None, None)
    elif base == "x":
        yes = PM_X(None, None)
    success = yes.load_info(desc)
    if success:
        yes.decrypt()
        here_it_is = yes.password.decode()
        return here_it_is
    else:
        return ''

# Provides access to manager.json (specifically the sensative stuff)
def access():
    enter_helper()
    try:
        grant_perms("manager.json")
        key, re_encrypt_data, storage_data = dec_file(main_work.QUI, main_work.AUTH_TYPE, "manager.json")
        data_section = storage_data[0]["data"]
        re_enc_file(key, re_encrypt_data, storage_data, "manager.json")
        exit_helper()
    except FileNotFoundError:
        return None
    return data_section

# Sets the user's master password
def master(passyword: str) -> None:
    enter_helper()
    set_master(passyword)

# Master password creation and storage logic
def set_master(master_p: str) -> None:
    user_salt = bcrypt.gensalt()
    hashed_master = bcrypt.hashpw(master_p.encode(), user_salt)
    user_salt = base64.b64encode(user_salt).decode("utf-8")
    salt_again = os.urandom(16)
    salt_again = base64.b64encode(salt_again).decode("utf-8")
    hashed_master = base64.b64encode(hashed_master).decode("utf-8")
    info = {
        "salt" : user_salt,
        "saltier": salt_again,
        "hash" : hashed_master
    }
    data = []
    data.append(info)
    exit_helper()
    if not is2FAsetup():
        enter_helper()
        if os.path.exists("master.json"):
            grant_perms("master.json")
        with open("master.json", "w") as file:
            json.dump(data, file, indent=4)
        rm_perms("master.json")
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
            if "saltier" in data_entry:
                data_entry["saltier"] = salt_again
        with open("master.json", "w") as file:
            json.dump(data, file, indent=4)
        rm_perms("master.json")
        exit_helper()

def save_recover_key(recover_key: str):
    user_salt = bcrypt.gensalt()
    hashed_rec_key = bcrypt.hashpw(recover_key.encode(), user_salt)
    user_salt = base64.b64encode(user_salt).decode("utf-8")
    hashed_rec_key = base64.b64encode(hashed_rec_key).decode("utf-8")
    info = {
        "rec_salt": user_salt,
        "rec_hash": hashed_rec_key,
    }
    enter_helper()
    grant_perms("master.json")
    with open("master.json", "r") as file:
        data = json.load(file)
    data.append(info)
    with open("master.json", "w") as new_file:
        json.dump(data, new_file, indent=4)
    rm_perms("master.json")
    exit_helper()

# Import a file containing password (that was exported from the program) and give the user to merge passwords or override.
def import_info(merge_decision, master_passyword: str) -> str:
    file_path = filedialog.askopenfilename(
        defaultextension=".json",
        filetypes=[("JSON files", "*.json")],
        title="Import",
        initialfile="export.json"
    )
    if file_path:
        try:
            given_key, given_re_enc_data, given_storage_data = dec_file(master_passyword, main_work.AUTH_TYPE, file_path)
            if given_key != "Incorrect master password or failed 2FA authentication" and given_storage_data[0]["exported_by"] == "PM" and (given_storage_data[0]["yes"] in ("z", "y", "x")):
                base = given_storage_data[0]["yes"]
                passyword_count = len(given_storage_data[0]["data"])
                for i in range(passyword_count):
                    data_section = given_storage_data[0]["data"][i]
                    if base == "z":
                        try:
                            assert data_section["desc"] not in [None, '']
                            assert data_section["enc_k"] not in [None, '']
                            assert data_section["non"] not in [None, '']
                            assert data_section["cipher_t"] not in [None, '']
                            assert data_section["tag"] not in [None, '']
                        except AssertionError:
                            return "The file selected was not exported by this program or has been corrupted"
                    elif base == "y":
                        try:
                            assert data_section["desc"] not in [None, '']
                            assert data_section["enc_k"] not in [None, '']
                            assert data_section["key"] not in [None, '']
                            assert data_section["iv"] not in [None, '']
                        except AssertionError:
                            return "The file selected was not exported by this program or has been corrupted"
                    elif base == "x":
                        try:
                            assert data_section["desc"] not in [None, '']
                            assert data_section["enc_k"] not in [None, '']
                            assert data_section["key"] not in [None, '']
                            assert data_section["non"] not in [None, '']
                        except AssertionError:
                            return "The file selected was not exported by this program or has been corrupted"
            else:
                return "The master password is incorrect", None
        except cryptography.fernet.InvalidToken:
            return "The master password is incorrect", None
    else:
        message = "The file selected does not exist"
        return message, file_path
    if merge_decision:
        file_base = check_base()
        export_base = given_storage_data[0]["yes"]
        export_data = given_storage_data[0]["data"]
        enter_helper()
        try:
            grant_perms("manager.json")
            key, re_enc_data, storage_data = dec_file(main_work.QUI, main_work.AUTH_TYPE, "manager.json")
            rm_perms("manager.json")
            exit_helper()
        except FileNotFoundError:
            file_destination = os.getcwd()
            file_destination = os.path.join(file_destination, "manager.json")
            try:
                shutil.copy2(file_path, file_destination)
                message = "File successfully imported. Would you like to keep the exported file?"
                rm_perms("manager.json")
                exit_helper()
            except:
                message = "The file selected was not exported by this program or has been corrupted"
            return message, file_path
        current_descs = [desc.get('desc') for desc in storage_data[0]["data"]]
        current_descs = set(current_descs)
        for data_section in export_data:
            description = data_section["desc"]
            if description in current_descs:
                if file_base == "z":
                    yes = PM_Z(None, None)
                elif file_base == "y":
                    yes = PM_Y(None, None)
                elif file_base == "x":
                    yes = PM_X(None, None)
                yes.load_info(description)
                yes.decrypt()
                passyword = yes.password.decode()
                description = description + " (imported)"
            else:
                if export_base == "z":
                    yes = PM_Z(None, None)
                    yes.key = data_section["key"]
                    yes.nonce = data_section["non"]
                    yes.cipher_t = data_section["cipher_t"]
                    yes.auth_t = data_section["tag"]
                elif export_base == "y":
                    yes = PM_Y(None, None)
                    yes.password = base64.b64decode(data_section["enc_k"])
                    yes.key = base64.b64decode(data_section["key"])
                    yes.iv = base64.b64decode(data_section["iv"])
                elif export_base == "x":
                    yes = PM_X(None, None)
                    yes.password = base64.b64decode(data_section["enc_k"])
                    yes.key = base64.b64decode(data_section["key"])
                    yes.nonce = base64.b64decode(data_section["non"])
                yes.description = data_section["desc"]
                yes.decrypt()
                passyword = yes.password.decode()
            store(passyword, description)
        message = "File successfully imported. Would you like to keep the exported file?"
    elif not merge_decision:
        enter_helper()
        file_destination = os.getcwd()
        file_destination = os.path.join(file_destination, "manager.json")
        try:
            shutil.copy2(file_path, file_destination)
            message = "File successfully imported. Would you like to keep the exported file?"
            exit_helper()
        except:
            message = "The file selected was not exported by this program or has been corrupted"
    return message, file_path

# Used to export the user's passwords encrypted with warning (its the only way to import passwords)
def export_info_enc() -> str:
    message = ''
    enter_helper()
    if os.path.exists("manager.json"):
        key, re_enc_data, storage_data = dec_file(main_work.QUI, main_work.AUTH_TYPE, "manager.json")
        exit_helper()
        if len(storage_data[0]["data"]) == 0:
            message = "There are no passwords currently stored"
            return message, None
    else:
        message = "The file does not exist (Try storing some passwords)"
        exit_helper()
        return message, None
    file_path = filedialog.asksaveasfilename(
        defaultextension=".json",
        filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        title="Export",
        initialfile="export.json"
    )
    if file_path:
        enter_helper()
        exported_file = os.path.join(os.getcwd(), "manager.json")
        try:
            shutil.copy2(exported_file, file_path)
            message = "File successfully exported"
        except:
            message = "The file or path specified does not exist or is corrupt"
        exit_helper()
    else:
        message = "The file or path specified does not exist"
    return message, file_path


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
    yes_button = ctk.CTkButton(master=framework, text="Yes", command=lambda decision=1: conf_type(decision))
    yes_button.place(relx=0.35, rely=0.6, anchor=tkinter.CENTER)
    no_button = ctk.CTkButton(master=framework, text="No", command=lambda decision=0: conf_type(decision))
    no_button.place(relx=0.65, rely=0.6, anchor=tkinter.CENTER)
    return yes_button, no_button

# Used for subwindows that provide the user with two options to choose from
def binary_buttons(framework, conf_type, b1, b2):
    yes_button = ctk.CTkButton(master=framework, text=b1, command=lambda decision=1: conf_type(decision))
    yes_button.pack(side=tkinter.LEFT, padx=(20, 10), pady=20)
    no_button = ctk.CTkButton(master=framework, text=b2, command=lambda decision=0: conf_type(decision))
    no_button.pack(side=tkinter.RIGHT, padx=(10, 20), pady=20)
    return yes_button, no_button

def load_lockout_data():
    enter_helper()
    if os.path.exists("lockout.json"):
        with open("lockout.json", "r") as f:
            exit_helper()
            return json.load(f)
    exit_helper()
    return {"attempts": 0, "remaining": 0}

def save_lockout_data(attempts: int, remaining: int):
    enter_helper()
    with open("lockout.json", "w") as f:
        json.dump({"attempts": attempts, "remaining": remaining}, f)
    exit_helper()

def clear_lockout():
    enter_helper()
    if os.path.exists("lockout.json"):
        os.remove("lockout.json")
    exit_helper()

def main():
    return

if __name__ == "__main__":
    main()