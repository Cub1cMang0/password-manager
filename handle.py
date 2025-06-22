from main_work import *
from math import floor
import pygetwindow
import time
import pyotp, qrcode
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
    twoFA_key = setup_qr_code_image()
    qr_code = open_image()
    qr_code_image = customtkinter.CTkImage(light_image=qr_code, dark_image=qr_code, size=(550, 550))
    cur_prompt = customtkinter.CTkToplevel()
    cur_prompt.title("Setup 2FA")
    cur_prompt.geometry("700x790")
    cur_frame = customtkinter.CTkFrame(cur_prompt)
    cur_frame.pack(padx=20, pady=20, expand=True)
    cur_label = customtkinter.CTkLabel(cur_frame, image=qr_code_image, text=f"Manual 2FA Key: {twoFA_key}", compound="top")
    cur_label.pack(padx=20, pady=20)
    twoFA_entry = customtkinter.CTkEntry(cur_frame, placeholder_text="Enter 2FA Code Here", width=200, height=35, border_width=2, corner_radius=10)
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
            app.deiconify()
        else:
            cur_label.configure(image=qr_code_image, text=f"Manual 2FA Key: {twoFA_key}" + "\nIncorrect Code", compound="top")
            twoFA_entry.delete(0, "end")
    submit_2FA_b = customtkinter.CTkButton(cur_frame, text="Submit", command=submit_2FA)
    submit_2FA_b.pack(padx=20, pady=10)
    cur_label.image = qr_code_image

# Selects an algorithm for the password managing logic (and to stick to)
def select_base() -> str:
    letter_range = string.ascii_lowercase[23:25]
    rand_letter = random.choice(letter_range)
    return rand_letter

def check_base() -> str:
    enter_helper()
    if os.path.exists("manager.json"):
        with open("manager.json", "r") as file:
            data = json.load(file)
        base = data[0]["yes"]
    else:
        base = select_base()
    exit_helper()
    return base

# Stores the user's given password in the hidden directory.
def store(word: str, desc: str) -> None:
    base = check_base()
    enter_helper()
    if base == "z":
        yes = PM_Z(word, desc)
    elif base == "y":
        yes = PM_Y(word, desc)
    elif base == "x":
        yes = PM_X(word, desc)
    yes.setup()
    yes.encrypt()
    yes.save_info()
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
            with open('manager.json', 'r') as file:
                full_data = json.load(file)
            full_data[0]["data"] = [entry for entry in full_data[0]["data"] if entry.get('desc') != desc]
            with open('manager.json', 'w') as file:
                json.dump(full_data, file, indent=4)
            exit_helper()
            return 2
        else:
            return 3
    else:
        return 3

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
    with open("manager.json", "r") as file:
        full_data = json.load(file)
    data_section = full_data[0]["data"]
    exit_helper()
    return data_section

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

# Import a file containing password (that was exported from the program) and give the user to merge passwords or override.
def import_info(merge_decision) -> str:
    file_path = filedialog.askopenfilename(
        defaultextension=".json",
        filetypes=[("JSON files", "*.json")],
        title="Import",
        initialfile="export.json"
    )
    if file_path:
        with open(file_path, "r") as file:
            given_json = json.load(file)
        method = given_json[0]["yes"]
        if given_json[0]["exported_by"] == "PM" and (given_json[0]["yes"] in ("z", "y", "x")):
            base = given_json[0]["yes"]
            passyword_count = len(given_json[0]["data"])
            for i in range(passyword_count):
                data_section = given_json[0]["data"][i]
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
        message = "The file selected does not exist"
        return message, file_path
    if merge_decision:
        file_base = check_base()
        export_base = given_json[0]["yes"]
        export_data = given_json[0]["data"]
        try:
            enter_helper()
            with open("manager.json", "r") as file:
                file_data = json.load(file)
            exit_helper()
        except FileNotFoundError:
            file_destination = os.getcwd()
            file_destination = os.path.join(file_destination, "manager.json")
            try:
                shutil.copy2(file_path, file_destination)
                message = "File successfully imported. Would you like to keep the exported file?"
                exit_helper()
            except:
                message = "The file selected was not exported by this program or has been corrupted"
            return message, file_path
        current_descs = [desc.get('desc') for desc in file_data[0]["data"]]
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
        with open("manager.json", "r") as file:
            export = json.load(file)
        exit_helper()
        if len(export[0]["data"]) == 0:
            message = "There are no passwords currently stored"
            return message
    else:
        message = "The file does not exist (Try storing some passwords)"
        return message
    main_info = access()
    file_path = filedialog.asksaveasfilename(
        defaultextension=".json",
        filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        title="Export",
        initialfile="export.json"
    )
    if file_path:
        enter_helper()
        with open(file_path, "w") as file:
            json.dump(export, file, indent=4)
        message = "File successfully exported"
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
    yes_button = customtkinter.CTkButton(master=framework, text="Yes", command=lambda decision=1: conf_type(decision))
    yes_button.place(relx=0.35, rely=0.6, anchor=tkinter.CENTER)
    no_button = customtkinter.CTkButton(master=framework, text="No", command=lambda decision=0: conf_type(decision))
    no_button.place(relx=0.65, rely=0.6, anchor=tkinter.CENTER)
    return yes_button, no_button

# Used for subwindows that provide the user with two options to choose from
def binary_buttons(framework, conf_type, b1, b2):
    yes_button = customtkinter.CTkButton(master=framework, text=b1, command=lambda decision=1: conf_type(decision))
    yes_button.pack(side=tkinter.LEFT, padx=(20, 10), pady=20)
    no_button = customtkinter.CTkButton(master=framework, text=b2, command=lambda decision=0: conf_type(decision))
    no_button.pack(side=tkinter.RIGHT, padx=(10, 20), pady=20)
    return yes_button, no_button

def main():
    grant_perms(".helper")

if __name__ == "__main__":
    main()