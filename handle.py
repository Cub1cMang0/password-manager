import main_work
from math import floor
import pygetwindow
import base64
import pyotp, qrcode, shutil, bcrypt, subprocess
import customtkinter as ctk
import tkinter
import tkinter.colorchooser
from PIL import Image
import pyperclip, random, string, json, os, sys
import cryptography, secrets


FIRST_COLOR = None
SECOND_COLOR = None
THIRD_COLOR = None
FOURTH_COLOR = None
TEXT_COLOR = None
COLOR_THEME = None
FONT = None

# Used to change the global variables  that are used to set the theme of the GUI
def update_theme(theme_color: str) -> None:
    global FIRST_COLOR
    global SECOND_COLOR
    global THIRD_COLOR
    global FOURTH_COLOR
    if theme_color == "red":
        FIRST_COLOR = "#800000"
        SECOND_COLOR = "#D30000"
        THIRD_COLOR = "#770000"
        FOURTH_COLOR = "#B30303"
    elif theme_color == "orange":
        FIRST_COLOR = "#EE6A0B"
        SECOND_COLOR = "#FF6A00"
        THIRD_COLOR = "#DD6713"
        FOURTH_COLOR = "#EF820D"
    elif theme_color == "yellow":
        FIRST_COLOR = "#FFD300"
        SECOND_COLOR = "#FFF200"
        THIRD_COLOR = "#E4CD05"
        FOURTH_COLOR = "#FCE205"
    elif theme_color == "green":
        FIRST_COLOR = "#0B6623"
        SECOND_COLOR = "#3BB143"
        THIRD_COLOR = "#03583C"
        FOURTH_COLOR = "#00A86B"
    elif theme_color == "blue":
        FIRST_COLOR = "#000080"
        SECOND_COLOR = "#3944BC"
        THIRD_COLOR = "#122766"
        FOURTH_COLOR = "#1134A6"
    elif theme_color == "purple":
        FIRST_COLOR = "#6F2DA8"
        SECOND_COLOR = "#A45EE9"
        THIRD_COLOR = "#5C0291"
        FOURTH_COLOR = "#8F00FF"
    elif theme_color == "black":
        FIRST_COLOR = "#212122"
        SECOND_COLOR = "#26282A"
        THIRD_COLOR = "#231F20"
        FOURTH_COLOR = "#353839"
    elif theme_color == "white":
        FIRST_COLOR = "#FFFFFF"
        SECOND_COLOR = "#F8F8FF"
        THIRD_COLOR = "#FCF9F9"
        FOURTH_COLOR = "#F7F6F4"
    return FIRST_COLOR, SECOND_COLOR, THIRD_COLOR, FOURTH_COLOR

def no_theme() -> None:
    global FIRST_COLOR
    global SECOND_COLOR
    global THIRD_COLOR
    global FOURTH_COLOR
    global TEXT_COLOR
    if ctk.get_appearance_mode() == "Dark":
        if FIRST_COLOR == None:
            FIRST_COLOR = "#242424"
        if SECOND_COLOR == None:
            SECOND_COLOR = "#2b2b2b"
        if THIRD_COLOR == None:
            THIRD_COLOR = "#1d1e1e"
        TEXT_COLOR = "#FFFFFF"
    else:
        if FIRST_COLOR == None:
            FIRST_COLOR = "#f9f9fa"
        if SECOND_COLOR == None:
            SECOND_COLOR = "#dbdbdb"
        if THIRD_COLOR == None:
            THIRD_COLOR = "#ebebeb"
        TEXT_COLOR = "#000000"
    if FOURTH_COLOR == None:
        FOURTH_COLOR = "#1f6aa5"

# Sets the selected them to all CTk objects
def set_theme(widget):
    for child in widget.winfo_children():
        if getattr(child, "no_theme", False):
            continue
        elif isinstance(child, ctk.CTkToplevel):
            child.configure(fg_color=FIRST_COLOR)
        elif isinstance(child, ctk.CTkFrame) or isinstance(child, ctk.CTkScrollableFrame):
            child.configure(fg_color=SECOND_COLOR)
        elif isinstance(child, ctk.CTkButton):
            child.configure(fg_color=FOURTH_COLOR)
        elif isinstance(child, ctk.CTkEntry) or isinstance(child, ctk.CTkCheckBox):
            child.configure(fg_color=FIRST_COLOR, border_color=THIRD_COLOR)
        elif isinstance(child, ctk.CTkTextbox):
            child.configure(fg_color=THIRD_COLOR)
        set_theme(child)

# Used to execute the change in theme color whilst saving the user's selection (at least the ones that utilize the color attribute)
def color_change(color: str, app) -> None:
    FIRST_COLOR, SECOND_COLOR, THIRD_COLOR, FOURTH_COLOR = update_theme(color)
    save_theme()
    set_theme(app)
    app.configure(fg_color=FIRST_COLOR)

# Save the user's selected theme
def save_theme() -> None:
    main_work.enter_helper()
    main_work.grant_perms("master.json")
    with open("master.json", "r") as file:
        data = json.load(file)
    first_theme = True
    for section in data:
        if "theme" in section:
            section["theme"] = (FIRST_COLOR, SECOND_COLOR, THIRD_COLOR, FOURTH_COLOR)
            first_theme = False
    if first_theme:
        new_theme = {"theme": (FIRST_COLOR, SECOND_COLOR, THIRD_COLOR, FOURTH_COLOR)}
        data.append(new_theme)
    with open("master.json", "w") as new_file:
        json.dump(data, new_file, indent=4)
    main_work.rm_perms("master.json")
    main_work.exit_helper()

# Loads in the user's previously selected color theme
def load_theme(app) -> tuple[str, str, str, str]:
    main_work.enter_helper()
    if os.path.exists("master.json"):
        main_work.grant_perms("master.json")
        with open("master.json", "r") as file:
            data = json.load(file)
        global FIRST_COLOR
        global SECOND_COLOR
        global THIRD_COLOR
        global FOURTH_COLOR
        try:
            for section in data:
                if "theme" in section:
                    FIRST_COLOR, SECOND_COLOR, THIRD_COLOR, FOURTH_COLOR = section["theme"]
                    break
        except:
            FIRST_COLOR, SECOND_COLOR, THIRD_COLOR, FOURTH_COLOR = (None, None, None, None)
        main_work.rm_perms("master.json")
        main_work.exit_helper()
    else:
        main_work.exit_helper()
        FIRST_COLOR, SECOND_COLOR, THIRD_COLOR, FOURTH_COLOR = (None, None, None, None)
    no_theme()
    set_theme(app)
    return FIRST_COLOR, SECOND_COLOR, THIRD_COLOR, FOURTH_COLOR

def update_font(font_name: str) -> None:
    global FONT
    FONT = ctk.CTkFont(family=font_name, weight="normal")

# Sets the user's selected font to all CTk Objects (at least the ones that utilize the font attribute)
def set_font(font_name, widget):
    for child in widget.winfo_children():
        if getattr(child, "no_font", False):
            continue
        if isinstance(child, (ctk.CTkButton, ctk.CTkEntry, ctk.CTkLabel, ctk.CTkTextbox)):
            child.configure(font=FONT)
        set_font(font_name, child)

# Set the user's selected text color to all CTk objects (at least the ones that utilize the font attribute)
def text_color_change(text_color: str, widget):
    for child in widget.winfo_children():
        if isinstance(child, (ctk.CTkButton, ctk.CTkLabel, ctk.CTkTextbox)):
            child.configure(text_color=text_color)
        elif isinstance(child, ctk.CTkEntry):
            child.configure(text_color=text_color, placeholder_text_color=text_color)
        text_color_change(text_color, child)

# Save text info from the user's theme
def save_text_info() -> None:
    global FONT
    global TEXT_COLOR
    main_work.enter_helper()
    main_work.grant_perms("master.json")
    with open("master.json", "r") as file:
        data = json.load(file)
    first_text_theme = True
    for section in data:
        if "text_theme" in section:
            section["text_theme"] = (FONT.cget("family"), TEXT_COLOR)
            first_text_theme = False
    if first_text_theme:
        text_data = {"text_theme": (FONT.cget("family"), TEXT_COLOR)}
        data.append(text_data)
    with open("master.json", "w") as new_file:
        json.dump(data, new_file, indent=4)
    main_work.rm_perms("master.json")
    main_work.exit_helper()

# Loads the user's text theme
def load_text_theme(app) -> tuple[str, str]:
    main_work.enter_helper()
    if os.path.exists("master.json"):
        main_work.grant_perms("master.json")
        with open("master.json", "r") as file:
            data = json.load(file)
        global FONT
        global TEXT_COLOR
        try:
            for section in data:
                if "text_theme" in section:
                    FONT, TEXT_COLOR = section["text_theme"]
                    break
        except:
            FONT = None
        main_work.rm_perms("master.json")
        main_work.exit_helper()
    else:
        main_work.exit_helper()
        FONT = None
    if FONT == None:
        FONT = "Arial"
    update_font(FONT)
    set_font(FONT, app)
    text_color_change(TEXT_COLOR, app)
    return FONT, TEXT_COLOR

def save_font_theme(font_name, app) -> None:
    update_font(font_name)
    set_font(font_name, app)
    save_text_info()

def save_text_theme(text_color: str, app) -> None:
    text_color_change(text_color, app)
    save_text_info()

# Set the user's custom color to the GUI's section (i.e. CTkFrame/CTkScrollableFrame, CTkButton, etc.)
def customize_section_color(section: str, app) -> None: 
    chosen_color = tkinter.colorchooser.askcolor(title="Choose Color")
    no_theme()
    if chosen_color[1]:
        if section == "Background/Entry":
            global FIRST_COLOR
            FIRST_COLOR = chosen_color[1]
        elif section == "Frames":
            global SECOND_COLOR
            SECOND_COLOR = chosen_color[1]
        elif section == "Output Text":
            global THIRD_COLOR
            THIRD_COLOR = chosen_color[1]
        elif section == "Buttons":
            global FOURTH_COLOR
            FOURTH_COLOR = chosen_color[1]
        set_theme(app)
        save_theme()

def customize_text_color(app) -> None:
    chosen_color = tkinter.colorchooser.askcolor(title="Choose Color")
    if chosen_color[1]:
        global TEXT_COLOR
        TEXT_COLOR = chosen_color[1]
        save_text_theme(TEXT_COLOR, app)

def save_custom_colors(section: str, app) -> None:
    customize_section_color(section, app)
    app.configure(fg_color=FIRST_COLOR)
    save_theme()

# Returns a PIL.Image of the qr code setup for 2FA.
def open_image():
    main_work.enter_helper()
    image = Image.open("setup.png")
    main_work.exit_helper()
    return image

# Provides the user with a QR Code and url to set up 2FA on their phone, computer, or whatever.
def setup_qr_code_image() -> str:
    main_work.enter_helper()
    key = pyotp.random_base32()
    uri = pyotp.totp.TOTP(key).provisioning_uri(
        name='2FA',
        issuer_name='POM')
    qrcode.make(uri).save("setup.png")
    main_work.exit_helper()
    return key

# Standard 2FA check for security
def check_2FA(code: int) -> bool:
    main_work.enter_helper()
    main_work.grant_perms("master.json")
    with open("master.json", "r") as file:
        data = json.load(file)
    main_work.rm_perms("master.json")
    main_work.exit_helper()
    source = None
    for section in data:
        if "2FA" in section:
            source = section["2FA"]
    totp = pyotp.TOTP(source)
    result = totp.verify(code)
    return result

# 2FA disabling logic
def disable_2FA() -> None:
    main_work.enter_helper()
    main_work.grant_perms("master.json")
    with open("master.json", "r") as file:
        data = json.load(file)
    for section in data:
        if "2FA" in section:
            section.pop("2FA", None)
    data = [section for section in data if section]
    with open("master.json", "w") as file:
        json.dump(data, file, indent=4)
    main_work.rm_perms("master.json")
    main_work.exit_helper()

# Used to set custom taskbar icon to CTkToplevel windows
def set_toplevel_icon(window):
    if sys.platform == "win32":
        icon_path = os.path.join(os.getcwd(), "mini_icons", "app_icon.ico")
        window.after(250, lambda: window.iconbitmap(icon_path))
    else:

        icon_path = os.path.join(os.getcwd(), "mini_icons", "app_icon.png")
        try:
            image = tk.PhotoImage(file=icon_path)
            window.after(250, lambda: window.iconphoto(False, image))
        except Exception as e:
            print(f"Failed to set iconphoto: {e}")

# Since 2FA can be enabled later and startup, it makes sense to create a function for it
def setup2FA(yb, nb, success_function=None) -> None:
    yb.pack_forget()
    nb.pack_forget()
    twoFA_key = setup_qr_code_image()
    qr_code = open_image()
    qr_code_image = ctk.CTkImage(light_image=qr_code, dark_image=qr_code, size=(550, 550))
    cur_prompt = ctk.CTkToplevel(fg_color=FIRST_COLOR)
    set_toplevel_icon(cur_prompt)
    cur_prompt.title("Setup 2FA")
    cur_prompt.geometry("700x790")
    cur_frame = ctk.CTkFrame(cur_prompt, fg_color=SECOND_COLOR)
    cur_frame.pack(padx=20, pady=20, expand=True)
    cur_label = ctk.CTkLabel(cur_frame, image=qr_code_image, text=f"Manual 2FA Key: {twoFA_key}", text_color=TEXT_COLOR, font=FONT, compound="top")
    cur_label.pack(padx=20, pady=20)
    twoFA_entry = ctk.CTkEntry(cur_frame, placeholder_text="Enter 2FA Code Here", fg_color=FIRST_COLOR, border_color=THIRD_COLOR, placeholder_text_color=TEXT_COLOR, text_color=TEXT_COLOR, font=FONT, width=200, height=35, border_width=2, corner_radius=10)
    twoFA_entry.pack(padx=20,pady=0)
    def submit_2FA():
        code_2FA = twoFA_entry.get()
        totp = pyotp.TOTP(twoFA_key)
        successful = totp.verify(code_2FA)
        if successful:
            main_work.enter_helper()
            main_work.grant_perms("master.json")
            with open("master.json", "r") as file:
                data = json.load(file)
            twoFA = {"2FA" : twoFA_key}
            data.append(twoFA)
            with open("master.json", "w") as file:
                json.dump(data, file, indent=4)
            main_work.rm_perms("master.json")
            main_work.exit_helper()
            cur_prompt.destroy()
            if not isinstance(success_function, type(None)):
                success_function()
        else:
            cur_label.configure(image=qr_code_image, text=f"Manual 2FA Key: {twoFA_key}" + "\nIncorrect code", compound="top")
            twoFA_entry.delete(0, "end")
    submit_2FA_b = ctk.CTkButton(cur_frame, text="Submit", command=submit_2FA, fg_color=FOURTH_COLOR, text_color=TEXT_COLOR, font=FONT, hover=False)
    submit_2FA_b.pack(padx=20, pady=10)
    cur_label.image = qr_code_image
    cur_prompt.grab_set()

def recover_account(rec_button, previous_prompt, success_function) -> None:
    previous_prompt.destroy()
    rec_button.pack_forget()
    recover_prompt = ctk.CTkToplevel(fg_color=FIRST_COLOR)
    set_toplevel_icon(recover_prompt)
    recover_prompt.title("Recover Account")
    recover_prompt.geometry("720x480")
    recover_frame = ctk.CTkFrame(recover_prompt, fg_color=SECOND_COLOR)
    recover_frame.pack(padx=100, pady=100, expand=True, fill="both")
    recover_label = ctk.CTkLabel(recover_frame, text="Enter the recovery key that was provided during setup", font=FONT, text_color=TEXT_COLOR)
    recover_label.pack(padx=20, pady=20)
    recover_entry = ctk.CTkEntry(recover_frame, placeholder_text="Enter Recovery Key Here", placeholder_text_color=TEXT_COLOR, text_color=TEXT_COLOR, font=FONT, fg_color=FIRST_COLOR, border_color=THIRD_COLOR)
    recover_entry.pack(padx=20, pady=20)
    def submit_recovery_key():
        successful = main_work.check_recovery_key(recover_entry.get())
        if successful:
            recover_prompt.destroy()
            success_function()
        else:
            recover_label.configure(text="Incorrect recovery key")
            recover_entry.delete(0, "end")
    submit_key = ctk.CTkButton(recover_frame, text="Submit", command=submit_recovery_key, font=FONT, text_color=TEXT_COLOR, fg_color=FOURTH_COLOR, hover=False)
    submit_key.pack(padx=20, pady=20)
    recover_prompt.grab_set()


def retrieve_2FA_key() -> str:
    main_work.enter_helper()
    with open("manager.json", "r") as file:
        data = json.load(file)
    main_work.exit_helper()
    return data["saltier"]

# Selects an algorithm for the password managing logic (and to stick to)
def select_base() -> str:
    letter_range = string.ascii_lowercase[23:25]
    rand_letter = random.choice(letter_range)
    return rand_letter

def check_base() -> str:
    main_work.enter_helper()
    if os.path.exists("manager.json"):
        main_work.grant_perms("manager.json")
        key, re_enc_data, storage_data = main_work.dec_file(main_work.QUI, main_work.AUTH_TYPE, "manager.json")
        base = storage_data["yes"]
        main_work.re_enc_file(key, re_enc_data, storage_data, "manager.json")
        main_work.rm_perms("manager.json")
    else:
        base = select_base()
    main_work.exit_helper()
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
                entry_label.configure(text="Password is too short")
            elif length >= 8 and length < 16:
                entry_label.configure(text="Ok")
            elif length > 15 and length < 65:
                entry_label.configure(text="Strong")
            elif length > 64:
                entry_label.configure(text="Password is too long")
            else:
                entry_label.configure(text="")
        else:
            if length <= 2:
                entry_label.configure(text="Weak")
            elif length >=3 and length < 5:
                entry_label.configure(text="Ok")
            elif length >= 5:
                entry_label.configure(text="Strong")
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
            if selection[0][1] not in ("# of Letters", ''):
                letters_length = int(selection[0][1])
                selection_length += letters_length
            if selection[0][0] == 1:
                selected.append("Letters")
        elif i == 1:
            if selection[1][1] not in ("# of Numbers", ''):
                numbers_length = int(selection[1][1])
                selection_length += numbers_length
            if selection[1][0]:
                selected.append("Numbers")
        elif i == 2:
            if selection [2][1] not in ("# of Symbols", ''):
                symbols_length = int(selection[2][1])
                selection_length += symbols_length
            if selection[2][0] == 1:
                selected.append("Symbols")
    if passy_length < selection_length:
        return f"Password length and requested characters don't match ({passy_length} vs {selection_length})" 
    elif selection[0][0] == 0 and selection [1][0] == 0 and selection [2][0] == 0:
        return "Password criteria hasn't been selected"
    elif selection[0][1] == "# of Letters" and selection [1][1] == "# of Numbers" and selection [2][1] == "# of Symbols" and selection[0][0] == 1 and selection [1][0] == 1 and selection [2][0] == 1:
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
            char_type =random.choice(selected)
            random_amount = random.randint(1, remaining)
            if char_type == "Letters":
                passyword += ''.join(random.choice(string.ascii_letters) for _ in range(random_amount))
            elif char_type == "Numbers":
                passyword += ''.join(random.choice(string.digits) for _ in range(random_amount))
            elif char_type == "Symbols":
                passyword += ''.join(random.choice("!@#$%^&*()-_=+[]{};:,.?/") for _ in range(random_amount))
            remaining -= random_amount
    passyword = list(passyword)
    random.shuffle(passyword)
    return ''.join(passyword)

# Stores the user's given password in the hidden directory.
def store(word: str, desc: str) -> None:
    base = check_base()
    main_work.enter_helper()
    if os.path.exists("manager.json"):
        main_work.grant_perms("manager.json")
        key, re_enc_data, storage_data = main_work.dec_file(main_work.QUI, main_work.AUTH_TYPE, "manager.json")
        desc_section = storage_data["data"]
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
    main_work.exit_helper()
    if base == "z":
        yes = main_work.POM_Z(word, desc)
    elif base == "y":
        yes = main_work.POM_Y(word, desc)
    elif base == "x":
        yes = main_work.POM_X(word, desc)
    yes.setup()
    yes.encrypt()
    yes.save_info()

# Deletes a password that the user stored. Will return certain numbers depending if it was successful or not.
def delete(word: str, desc: str) -> int:
    base = check_base()
    if base == "z":
        yes = main_work.POM_Z(None, None)
    elif base == "y":
        yes = main_work.POM_Y(None, None)
    elif base == "x":
        yes = main_work.POM_X(None, None)
    success = yes.load_info(desc)
    if success:
        yes.decrypt()
        check = yes.password.decode()
        if word == check:
            main_work.enter_helper()
            main_work.grant_perms("manager.json")
            key, re_enc_data, storage_data = main_work.dec_file(main_work.QUI, main_work.AUTH_TYPE, "manager.json")
            storage_data["data"] = [entry for entry in storage_data["data"] if entry.get('desc') != desc]
            main_work.re_enc_file(key, re_enc_data, storage_data, "manager.json")
            main_work.rm_perms("manager.json")
            main_work.exit_helper()
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
        yes = main_work.POM_Z(None, None)
    elif base == "y":
        yes = main_work.POM_Y(None, None)
    elif base == "x":
        yes = main_work.POM_X(None, None)
    success = yes.load_info(desc)
    if success:
        yes.decrypt()
        here_it_is = yes.password.decode()
        return here_it_is
    else:
        return ''

# Provides access to manager.json (specifically the sensative stuff)
def access():
    main_work.enter_helper()
    try:
        main_work.grant_perms("manager.json")
        key, re_encrypt_data, storage_data = main_work.dec_file(main_work.QUI, main_work.AUTH_TYPE, "manager.json")
        data_section = storage_data["data"]
        main_work.re_enc_file(key, re_encrypt_data, storage_data, "manager.json")
        main_work.exit_helper()
    except FileNotFoundError:
        return None
    return data_section

# Sets the user's master password
def master(passyword: str) -> None:
    main_work.enter_helper()
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
        "hash" : hashed_master
    }
    data = []
    data.append(info)
    main_work.exit_helper()
    if not main_work.is2FAsetup():
        main_work.enter_helper()
        if os.path.exists("master.json"):
            main_work.grant_perms("master.json")
        with open("master.json", "w") as file:
            json.dump(data, file, indent=4)
        main_work.rm_perms("master.json")
        main_work.exit_helper()
    else:
        main_work.enter_helper()
        main_work.grant_perms("master.json")
        with open("master.json", "r") as file:
            data = json.load(file)
        for data_entry in data:
            if "salt" in data_entry:
                data_entry["salt"] = user_salt
            if "hash" in data_entry:
                data_entry["hash"] = hashed_master
        with open("master.json", "w") as file:
            json.dump(data, file, indent=4)
        main_work.rm_perms("master.json")
        main_work.exit_helper()

def save_recovery_key(recover_key: str):
    user_salt = bcrypt.gensalt()
    hashed_rec_key = bcrypt.hashpw(recover_key.encode(), user_salt)
    user_salt = base64.b64encode(user_salt).decode("utf-8")
    hashed_rec_key = base64.b64encode(hashed_rec_key).decode("utf-8")
    info = {
        "rec_salt": user_salt,
        "rec_hash": hashed_rec_key,
    }
    main_work.enter_helper()
    main_work.grant_perms("master.json")
    with open("master.json", "r") as file:
        data = json.load(file)
    data.append(info)
    with open("master.json", "w") as new_file:
        json.dump(data, new_file, indent=4)
    main_work.rm_perms("master.json")
    main_work.exit_helper()

# Import a file containing password (that was exported from the program) and give the user to merge passwords or override.
def import_info(merge_decision, master_passyword: str) -> str:
    file_path = tkinter.filedialog.askopenfilename(
        defaultextension=".json",
        filetypes=[("JSON files", "*.json")],
        title="Import",
        initialfile="export.json"
    )
    if file_path:
        try:
            given_key, given_re_enc_data, given_storage_data = main_work.dec_file(master_passyword, main_work.AUTH_TYPE, file_path)
            if given_key != "Incorrect master password or failed 2FA authentication" and given_storage_data["exported_by"] == "POM" and given_storage_data["yes"] in ("x", "y", "z"):
                base = given_storage_data["yes"]
                passyword_count = len(given_storage_data["data"])
                for i in range(passyword_count):
                    data_section = given_storage_data["data"][i]
                    if base == "z":
                        try:
                            assert data_section["desc"] not in [None, '']
                            assert data_section["enc_k"] not in [None, '']
                            assert data_section["non"] not in [None, '']
                            assert data_section["cipher_t"] not in [None, '']
                            assert data_section["tag"] not in [None, '']
                        except AssertionError:
                            return "The file selected was not exported by this program or has been corrupted since 1987", "Error"
                    elif base == "y":
                        try:
                            assert data_section["desc"] not in [None, '']
                            assert data_section["enc_k"] not in [None, '']
                            assert data_section["key"] not in [None, '']
                            assert data_section["iv"] not in [None, '']
                        except AssertionError:
                            return "The file selected was not exported by this program or has been corrupted since 1987", "Error"
                    elif base == "x":
                        try:
                            assert data_section["desc"] not in [None, '']
                            assert data_section["enc_k"] not in [None, '']
                            assert data_section["key"] not in [None, '']
                            assert data_section["non"] not in [None, '']
                        except AssertionError:
                            return "The file selected was not exported by this program or has been corrupted since 1987", "Error"
            elif given_key == "Incorrect master password or failed 2FA authentication":
                return "The master password is incorrect", None
            elif given_storage_data["exported_by"] != "POM" or given_storage_data["yes"] not in ("z", "y", "x"):
                return "The file selected was not exported by this program or has been corrupted", "Error"
        except cryptography.fernet.InvalidToken:
            return "The master password is incorrect", None
        except UnboundLocalError:
            return "The file selected was not exported by this program or has been corrupted", "Error"
    else:
        message = "The file selected does not exist"
        return message, file_path
    if merge_decision:
        file_base = check_base()
        export_base = given_storage_data["yes"]
        export_data = given_storage_data["data"]
        main_work.enter_helper()
        try:
            main_work.grant_perms("manager.json")
            key, re_enc_data, storage_data = main_work.dec_file(main_work.QUI, main_work.AUTH_TYPE, "manager.json")
            main_work.rm_perms("manager.json")
            main_work.exit_helper()
        except subprocess.CalledProcessError:
            file_destination = os.getcwd()
            file_destination = os.path.join(file_destination, "manager.json")
            try:
                shutil.copy2(file_path, file_destination)
                message = "File successfully imported. Would you like to keep the exported file?"
                main_work.rm_perms("manager.json")
                main_work.exit_helper()
            except:
                message = "The file selected was not exported by this program or has been corrupted"
            return message, file_path
        current_descs = [desc.get('desc') for desc in storage_data["data"]]
        current_descs = set(current_descs)
        for data_section in export_data:
            description = data_section["desc"]
            if description in current_descs:
                if file_base == "z":
                    yes = main_work.POM_Z(None, None)
                elif file_base == "y":
                    yes = main_work.POM_Y(None, None)
                elif file_base == "x":
                    yes = main_work.POM_X(None, None)
                yes.load_info(description)
                yes.decrypt()
                passyword = yes.password.decode()
                description = description + " (imported)"
            else:
                if export_base == "z":
                    yes = main_work.POM_Z(None, None)
                    yes.key = data_section["key"]
                    yes.nonce = data_section["non"]
                    yes.cipher_t = data_section["cipher_t"]
                    yes.auth_t = data_section["tag"]
                elif export_base == "y":
                    yes = main_work.POM_Y(None, None)
                    yes.password = base64.b64decode(data_section["enc_k"])
                    yes.key = base64.b64decode(data_section["key"])
                    yes.iv = base64.b64decode(data_section["iv"])
                elif export_base == "x":
                    yes = main_work.POM_X(None, None)
                    yes.password = base64.b64decode(data_section["enc_k"])
                    yes.key = base64.b64decode(data_section["key"])
                    yes.nonce = base64.b64decode(data_section["non"])
                yes.description = data_section["desc"]
                yes.decrypt()
                passyword = yes.password.decode()
            store(passyword, description)
        message = "File successfully imported. Would you like to keep the exported file?"
    elif not merge_decision:
        main_work.enter_helper()
        file_destination = os.getcwd()
        file_destination = os.path.join(file_destination, "manager.json")
        try:
            shutil.copy2(file_path, file_destination)
            message = "File successfully imported. Would you like to keep the exported file?"
            main_work.exit_helper()
        except:
            message = "The file selected was not exported by this program or has been corrupted"
    return message, file_path

# Used to export the user's passwords encrypted with warning (its the only way to import passwords)
def export_info_enc() -> str:
    message = ''
    main_work.enter_helper()
    if os.path.exists("manager.json"):
        key, re_enc_data, storage_data = main_work.dec_file(main_work.QUI, main_work.AUTH_TYPE, "manager.json")
        main_work.exit_helper()
        if len(storage_data["data"]) == 0:
            message = "There are no passwords currently stored"
            return message, None
    else:
        message = "The file does not exist (Try storing some passwords)"
        main_work.exit_helper()
        return message, None
    file_path = tkinter.filedialog.asksaveasfilename(
        defaultextension=".json",
        filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        title="Export",
        initialfile="export.json"
    )
    if file_path:
        main_work.enter_helper()
        exported_file = os.path.join(os.getcwd(), "manager.json")
        try:
            shutil.copy2(exported_file, file_path)
            message = "File successfully exported"
        except:
            message = "The file or path specified does not exist or is corrupt"
        main_work.exit_helper()
    else:
        message = "The file or path specified does not exist"
    return message, file_path

def wipe_passywords() -> str:
    main_work.enter_helper()
    if os.path.exists("manager.json"):
        main_work.grant_perms("manager.json")
        key, re_enc_data, storage_data = main_work.dec_file(main_work.QUI, "master", "manager.json")
        if len(storage_data["data"]) == 0:
            main_work.exit_helper()
            return "There are no passwords to delete (try storing some)"
        storage_data["data"] = []
        main_work.re_enc_file(key, re_enc_data, storage_data, "manager.json")
        main_work.rm_perms("manager.json")
        main_work.exit_helper()
        return "Passwords have been successfully wiped"
    else:
        main_work.exit_helper()
        return "There are no passwords to delete (try storing some)"

# Used to check if the user has already gone through the setup phase.
def first_time() -> bool:
    if os.path.exists(".helper"):
        main_work.enter_helper()
        if os.path.exists("master.json"):
            isFirst = False
        else:
            isFirst = True
        main_work.exit_helper()
        return isFirst
    else:
        main_work.hidden_dir(".helper")
        return True

# Used to check for the presence of manager.json
def present() -> bool:
    main_work.enter_helper()
    exists = os.path.exists("manager.json")
    main_work.exit_helper()
    return exists

# Used for the main window instead of sub windows
def big_yes_no_buttons(framework, conf_type):
    yes_button = ctk.CTkButton(master=framework, text="Yes", command=lambda decision=1: conf_type(decision), text_color=TEXT_COLOR, font=FONT, fg_color=FOURTH_COLOR, hover=False)
    yes_button.place(relx=0.35, rely=0.6, anchor=tkinter.CENTER)
    no_button = ctk.CTkButton(master=framework, text="No", command=lambda decision=0: conf_type(decision), text_color=TEXT_COLOR, font=FONT, fg_color=FOURTH_COLOR, hover=False)
    no_button.place(relx=0.65, rely=0.6, anchor=tkinter.CENTER)
    return yes_button, no_button

# Used for subwindows that provide the user with two options to choose from
def binary_buttons(framework, conf_type, b1, b2):
    yes_button = ctk.CTkButton(master=framework, text=b1, command=lambda decision=1: conf_type(decision), text_color=TEXT_COLOR, font=FONT, fg_color=FOURTH_COLOR, hover=False)
    yes_button.pack(side=tkinter.LEFT, padx=60, pady=20)
    no_button = ctk.CTkButton(master=framework, text=b2, command=lambda decision=0: conf_type(decision), text_color=TEXT_COLOR, font=FONT, fg_color=FOURTH_COLOR, hover=False)
    no_button.pack(side=tkinter.RIGHT, padx=60, pady=20)
    return yes_button, no_button

def load_lockout_data():
    main_work.enter_helper()
    if os.path.exists("lockout.json"):
        main_work.grant_perms("lockout.json")
        with open("lockout.json", "r") as f:
            main_work.rm_perms("lockout.json")
            main_work.exit_helper()
            return json.load(f)
    main_work.exit_helper()
    return {"attempts": 0, "remaining": 0}

def save_lockout_data(attempts: int, remaining: int):
    main_work.enter_helper()
    if os.path.exists("lockout.json"):
        main_work.grant_perms("lockout.json")
    with open("lockout.json", "w") as f:
        json.dump({"attempts": attempts, "remaining": remaining}, f)
    main_work.rm_perms("lockout.json")
    main_work.exit_helper()

def clear_lockout():
    main_work.enter_helper()
    if os.path.exists("lockout.json"):
        main_work.grant_perms("lockout.json")
        os.remove("lockout.json")
    main_work.exit_helper()

class HoverTooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip = None
        widget.bind("<Enter>", self.on_enter)
        widget.bind("<Leave>", self.on_leave)

    def on_enter(self, event):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx()
        y += self.widget.winfo_rooty() + 20
        self.tooltip = tkinter.Toplevel(self.widget)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{x}+{y}")
        label = tkinter.Label(self.tooltip, text=self.text, background="lightyellow", relief="solid", borderwidth=1, wraplength=300)
        label.pack()

    def on_leave(self, event):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None

def main():
    main_work.enter_helper()
    main_work.grant_perms("master.json")
    main_work.grant_perms("manager.json")

if __name__ == "__main__":
    main()