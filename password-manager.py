from handle import *
vault_timer = None
generate_timer = None

# Prompts the user if they are sure with their decision of storing their password
def confirm_storage():
    word = entry_pass.get()
    desc = entry_description.get()
    if desc == '':
        entry_input.set("Password descriptions cannot be empty!")
        app.after(4000, lambda: rm_message(entry_input))
        return
    store_button.place_forget()
    entry_input.set("Are you sure you want to store this password?")
    def handle_storage(decision: int):           # Handles password storage decision
        if decision == 0:
            rm_message(entry_input)
        if decision == 1:
            store(word, desc)
            dump_desc()
            entry_input.set("Password has been stored!")    
            entry_pass.delete(0, 'end')
            entry_description.delete(0, 'end')
            app.after(4000, lambda: rm_message(entry_input))
        yes_button.place_forget()
        no_button.place_forget()
        store_button.place(relx=0.5, rely=0.6, anchor=tkinter.CENTER)
    yes_button, no_button = big_yes_no_buttons(entry_frame, handle_storage)

# Fetch the user's requested password in the output textbox and make it disappear after 10 seconds. Also refreshes 10 second timer
def fetch_requested(d: str):
    global vault_timer
    vault_output.configure(state="normal")
    output = fetch(d)
    if not output == '':
        vault_output.delete("0.0", "end")
        vault_output.insert("0.0", output)
        vault_output.configure(state="disabled")
        if 'vault_timer' in globals() and vault_timer is not None:
            vault_output.after_cancel(vault_timer)
        def clear_output():
            vault_output.configure(state="normal")
            vault_output.delete("0.0", "end")
            vault_output.configure(state="disabled")
            global vault_timer
            vault_timer = None
        vault_timer = vault_output.after(10000, clear_output)

def rm_message(message_input):
    message_input.set("")

# Used to set the master password for teh user the first time. Also, gives the user an option to enable 2FA.
def set_main():
    twoFA_already = is2FAsetup()
    prompt = ctk.CTkToplevel()
    prompt.title("Setup")
    prompt.geometry("720x480")
    set_m_frame = ctk.CTkFrame(prompt)
    set_m_frame.pack(padx=20, pady=20, expand=True)
    question = ctk.CTkLabel(set_m_frame, text=("Before you get started, you need to set up a master password"
                                                    " to access all of the passwords you will be storing."
                                                    " Make sure that it's at least 20+ characters long!"
                                                    "\n (Note: It can be changed later.)" )
                                            , wraplength=360)
    question.pack(padx=20, pady=20)
    answer = ctk.CTkEntry(set_m_frame, width=200)
    answer.pack(padx=20, pady=10)
    def submit():
        password = answer.get()
        if len(password) < 20:
            question.configure(text="Password is too short! Enter a master password 20+ characters long!", wraplength=360)
            return
        elif len(password) > 64:
            question.configure(text="Bro you are not Mr. President. Enter a master password less than 65 characters long!", wraplength=360)
            return
        master(password)
        answer.pack_forget()
        submit_b.pack_forget()
        if twoFA_already:
            prompt.destroy()
            app.deiconify()
        else:
            question.configure(set_m_frame, text="Would you like to enable 2FA? (Note: 2FA is required to reset master password)")
            def twoFA_decision(decision: int):
                if decision == 0:
                    update_2FA_status("Disable 2FA")
                    prompt.destroy()
                    app.deiconify()
                if decision == 1:
                    prompt.destroy()
                    setup2FA(yes_button, no_button, app)
                    update_2FA_status("Enable 2FA")
            yes_button, no_button = binary_buttons(set_m_frame, twoFA_decision, "Yes", "No")
    submit_b = ctk.CTkButton(set_m_frame, text="Submit", command=submit)
    submit_b.pack(pady=20)
    prompt.grab_set()

#Of course, the classic master password check to make sure that no one besides the user can get access to the application. Or use 2FA if the user enabled it
def main_login() -> None:
    attempt = 0
    prompt = ctk.CTkToplevel()
    prompt.title("Login")
    prompt.geometry("720x480")
    def master_login_logic(twoFA_enabled: bool):
        for child in prompt.winfo_children():
            child.destroy()
        frame = ctk.CTkFrame(prompt)
        frame.pack(padx=20, pady=20, expand=True)
        if not twoFA_enabled:
            check = ctk.CTkLabel(frame, text="2FA must be enabled to login via this method")
            check.pack(padx=20, pady=20)
            prompt.after(4000, lambda: check.configure(text="Please enter your master password"))
        else:
            check = ctk.CTkLabel(frame, text="Please enter your master password", wraplength=360)
        check.pack(padx=20, pady=20)
        password_entry = ctk.CTkEntry(frame, placeholder_text="Enter password here", width=200)
        password_entry.pack(padx=20, pady=20)
        def master_login():
            given_password = password_entry.get()
            correct = check_master(given_password)
            nonlocal attempt
            if correct:
                prompt.destroy()
                app.deiconify()
                main_work.QUI = given_password
                main_work.AUTH_TYPE = "master"
                exists = present()
                if (exists):
                    dump_desc()
                return
            else:
                attempt += 1
                if attempt == 5:
                    sys.exit()
                check.configure(text=f"Password is incorrect, you have {5-attempt} attempts left.", wraplength=360)
        check_password = ctk.CTkButton(frame, text="Login", command=master_login)
        check_password.pack(pady=10)
        use_2FA = ctk.CTkButton(frame, text="Login via 2FA", command=login_2FA_logic)
        use_2FA.pack(pady=10)
    def login_2FA_logic():
        for child in prompt.winfo_children():
            child.destroy()
        is2FA = is2FAsetup()
        frame_2FA = ctk.CTkFrame(prompt)
        frame_2FA.pack(padx=20, pady=20, expand=True)
        if not is2FA:
            master_login_logic(False)
            return
        check_twoFA = ctk.CTkLabel(frame_2FA, text="Enter the 2FA code found in your authenticator to login", wraplength=360)
        check_twoFA.pack(padx=20, pady=20)
        twoFA_entry = ctk.CTkEntry(frame_2FA, placeholder_text="Enter 2FA code here", width=200)
        twoFA_entry.pack(padx=20, pady=20)
        def authenticate_2FA():
            successful = check_2FA(twoFA_entry.get())
            if successful:
                prompt.destroy()
                app.deiconify()
                main_work.QUI = retrieve_2FA_key()
                main_work.AUTH_TYPE = "2fa"
                exists = present()
                if (exists):
                    dump_desc()
                return
            if not successful:
                check_twoFA.configure(text="Incorrect Code")
                prompt.after(4000, lambda: check_twoFA.configure(text="Enter the 2FA code found in your authenticator to login"))
                twoFA_entry.delete(0, "end")
        check_code = ctk.CTkButton(frame_2FA, text="Login", command=authenticate_2FA)
        check_code.pack(pady=10)
        use_master = ctk.CTkButton(frame_2FA, text="Login via master password", command=lambda: master_login_logic(True))
        use_master.pack(pady=10)
    master_login_logic(True)
    prompt.grab_set()

# Asks the user if they are sure with exporting their passwords.
def confirm_export() -> None:
    export_prompt = ctk.CTkToplevel()
    export_prompt.title("Export")
    export_prompt.geometry("720x480")
    export_frame = ctk.CTkFrame(export_prompt)
    export_frame.pack(padx=20, pady=20, expand=True)
    export_label = ctk.CTkLabel(export_frame, text=("Are you sure you want to export all your stored passwords?"
                                                             "\n(Warning: It's recommended to keep the file in a safe location)"), wraplength=360)
    export_label.pack(padx=20, pady=20)
    def export_decision(decision: int) -> None:      # Gives the user the option to export their passwords.
        if decision == 0:
            export_prompt.destroy()
            return
        if decision == 1:
            message, file = export_info_enc()
            if file == '':
                export_prompt.destroy()
            else:
                export_label.configure(text=message)
                if message == "File successfully exported":
                    warning_label = ctk.CTkLabel(master=export_frame, text="WARNING: KEEP TRACK OF YOUR CURRENT MASTER PASSWORD IN ORDER TO IMPORT THIS FILE IN THE FUTURE", text_color="red", wraplength=360)
                    warning_label.pack(padx=10)
                ok_button = ctk.CTkButton(export_frame, text="Ok", command= lambda: export_prompt.destroy())
                ok_button.pack(padx=20, pady=20)
        yes_button.pack_forget()
        no_button.pack_forget()
    yes_button, no_button = binary_buttons(export_frame, export_decision, "Yes", "No")
    export_prompt.grab_set()

# Gives the user the option to import their passwords from a previously exported file.
def confirm_import() -> None:
    import_prompt = ctk.CTkToplevel()
    import_prompt.title("Import")
    import_prompt.geometry("720x480")
    import_frame = ctk.CTkFrame(import_prompt)
    import_frame.pack(padx=20, pady=20, expand=True)
    import_label = ctk.CTkLabel(import_frame, text=("Are you sure you want to import passwords from a previously exported file?"), wraplength=360)
    import_label.pack(padx=20, pady=20)
    def import_decision(decision: int) -> None:
        if decision == 0:
            import_prompt.destroy()
            return
        if decision == 1:
            import_label.configure(text="Do you want to merge the passwords found in both files or override the current one with the export?")
            yes_button.pack_forget()
            no_button.pack_forget()
            def merge_decision(decision: int) -> None:
                if decision == 1:
                    merge = True
                if decision == 0:
                    merge = False
                import_label.configure(text="To import your file, you must enter the master password you used to export this file")
                merge_button.pack_forget()
                override_button.pack_forget()
                master_entry = ctk.CTkEntry(master=import_frame, placeholder_text="Enter Master Password Here")
                master_entry.pack(padx=20, pady=20, expand=True)
                def validate_import() -> None:
                    message, file = import_info(merge, master_entry.get())
                    if file == '':
                        import_prompt.destroy()
                    elif message == "The master password is incorrect":
                        import_label.configure(text="Incorrect Master Password")
                    else:
                        import_label.configure(text=message)
                        import_button.pack_forget()
                        master_entry.pack_forget()
                        dump_desc()
                    def destroy_export_decision(decision: int) -> None:
                        if decision == 1:
                            import_prompt.destroy()
                            return
                        if decision == 0:
                            os.remove(file)
                            import_prompt.destroy()
                    keep_button, delete_button = binary_buttons(import_frame, destroy_export_decision, "Keep", "Delete")
                import_button = ctk.CTkButton(master=import_frame, text="Import", width=0, command= validate_import)
                import_button.pack(padx=20, pady=20)
            merge_button, override_button = binary_buttons(import_frame, merge_decision, "Merge", "Override")
    yes_button, no_button = binary_buttons(import_frame, import_decision, "Yes", "No")
    import_prompt.grab_set()

def confirm_reset() -> None:
    reset_master_prompt = ctk.CTkToplevel()
    reset_master_prompt.title("Reset Master Password")
    reset_master_prompt.geometry("720x480")
    reset_master_frame = ctk.CTkFrame(reset_master_prompt)
    reset_master_frame.pack(padx=20, pady=20, expand=True)
    reset_master_label = ctk.CTkLabel(reset_master_frame, text=("Are you sure you want to reset your master password?"
                                                                        " (Note: 2FA must be enabled to reset your master password)"), wraplength=360)
    reset_master_label.pack(padx=20, pady=20)
    def reset_master_decision(decision: int) -> None:
        if decision == 0:
            reset_master_prompt.destroy()
            return
        if decision == 1:
            if not is2FAsetup():
                reset_master_label.configure(text="You must have 2FA enabled to reset your master password!")
                reset_master_prompt.after(4000, lambda: reset_master_label.configure(text=("Are you sure you want to reset your master password?"
                                                                                    " (Note: 2FA must be enabled to reset your master password)")))
            if is2FAsetup():
                yes_button.pack_forget()
                no_button.pack_forget()
                reset_master_label.pack_forget()
                for child in reset_master_frame.winfo_children():
                    child.destroy()
                reset_master_prompt.geometry("720x480")
                reset_label = ctk.CTkLabel(reset_master_frame, text="Check your authenticator to enter your 2FA code")
                reset_label.pack(padx=20, pady=20)
                twoFA_entry = ctk.CTkEntry(master=reset_master_frame, placeholder_text="Enter 2FA Code Here", width=200, height=35, border_width=2, corner_radius=10)
                twoFA_entry.pack(padx=20, pady=20)
                def submit_2FA():
                    code_2FA = twoFA_entry.get()
                    successful = check_2FA(code_2FA)
                    if successful:
                        reset_master_prompt.destroy()
                        set_main()
                    else:
                        reset_label.configure(text="Incorrect Code")
                        twoFA_entry.delete(0, "end")
                submit_2FA_b = ctk.CTkButton(reset_master_frame, text="Submit", command=submit_2FA)
                submit_2FA_b.pack(padx=20, pady=10)
    yes_button, no_button = binary_buttons(reset_master_frame, reset_master_decision, "Yes", "No")
    reset_master_prompt.grab_set()

# Used to restart the program when the user disables 2FA to avoid side effects
def restart_program_2FA(prompt) -> None:
    prompt.destroy()
    main_login()
    
# Gives the user the option to (begrudgingly) disable 2FA 
def confirm_disable_2FA() -> None:
    disable_2FA_prompt = ctk.CTkToplevel()
    disable_2FA_prompt.title("Disable 2FA")
    disable_2FA_prompt.geometry("720x480")
    disable_2FA_frame = ctk.CTkFrame(disable_2FA_prompt)
    disable_2FA_frame.pack(padx=20, pady=20, expand=True)
    disable_2FA_label = ctk.CTkLabel(disable_2FA_frame, text="Are you sure you want to disable 2FA? (Not Recommended)", wraplength=360)
    disable_2FA_label.pack(padx=20, pady=20)
    def disable_2FA_decision(decision: int):
        if decision == 0:
            disable_2FA_prompt.destroy()
            return
        if decision == 1:
            disable_2FA()
            disable_2FA_label.pack_forget()
            for child in disable_2FA_frame.winfo_children():
                child.destroy()
            disable_2FA_prompt.geometry("720x480")
            disable_success_label = ctk.CTkLabel(disable_2FA_frame, text="2FA has been successfully disabled, the program will now restart", wraplength=360)
            disable_success_label.pack(padx=20, pady=20)
            ok_button = ctk.CTkButton(disable_2FA_frame, text="Ok", command= lambda prompt=disable_2FA_prompt: restart_program_2FA(prompt))
            ok_button.pack(padx=20, pady=20)
            update_2FA_status("Disable 2FA")
            app.withdraw()
        yes_button.pack_forget()
        no_button.pack_forget()
    yes_button, no_button = binary_buttons(disable_2FA_frame, disable_2FA_decision, "Yes", "No")
    disable_2FA_prompt.grab_set()

# Gives the user the option to enable 2FA if they didn't during the setup
def confirm_enable_2FA() -> None:
    enable_2FA_prompt = ctk.CTkToplevel()
    enable_2FA_prompt.title("Enable 2FA")
    enable_2FA_prompt.geometry("720x480")
    enable_2FA_frame = ctk.CTkFrame(enable_2FA_prompt)
    enable_2FA_frame.pack(padx=20, pady=20, expand=True)
    enable_2FA_label = ctk.CTkLabel(enable_2FA_frame, text="Are you sure you want to enable 2FA? (Recommended)", wraplength=360)
    enable_2FA_label.pack(padx=20, pady=20)
    def enable_2FA_decision(decision: int):
        if decision == 0:
            enable_2FA_prompt.destroy()
            return
        if decision == 1:
            enable_2FA_prompt.destroy()
            setup2FA(yes_button, no_button, app)
            update_2FA_status("Enable 2FA")
    yes_button, no_button = binary_buttons(enable_2FA_frame, enable_2FA_decision, "Yes", "No")
    enable_2FA_prompt.grab_set()

def desc_search(event):
    entry_widget = event.widget
    search_desc = entry_widget.get()
    if search_desc == '':
        dump_desc()
    data = access()
    for child in storage_content.winfo_children():
        child.destroy()
    storage_content.grid_columnconfigure(0, weight=1)
    for i in range(len(data)):
        try:
            current_desc = data[i]["desc"]
            if search_desc in current_desc:
                desc_label = ctk.CTkLabel(storage_content, text=current_desc)
                desc_label.grid(row=i, column=0, sticky="w", padx=side_spacing, pady=upper_spacing)
                show_button = ctk.CTkButton(storage_content, text="Show Password", command=lambda d=current_desc: fetch_requested(d))
                show_button.grid(row=i, column=1, sticky="e", padx=side_spacing, pady=upper_spacing)
        except KeyError:        # I realized that this would happen if the user enters the app without any passwords stored.
            return

# Give the user the option to update their password itself, the description, or both.
def update_info(description: str) -> None:
    update_prompt = ctk.CTkToplevel()
    update_prompt.title("Update password information")
    update_prompt.geometry("720x480")
    update_frame = ctk.CTkFrame(update_prompt)
    update_frame.pack(padx=20, pady=20, expand=True)
    og_passyword = fetch(description)
    og_description = description
    passyword_sv = ctk.StringVar(value=og_passyword)
    description_sv = ctk.StringVar(value=og_description)
    def entry_change(*args):
        if len(passyword_entry.get()) == 0 or len(description_entry.get()) == 0:
            save_button.configure(state="disabled", fg_color="gray")
        elif passyword_entry.get() != og_passyword or description_entry.get() != og_description:
            save_button.configure(state="normal", fg_color="#1f6aa5")
        else:
            save_button.configure(state="disabled", fg_color="gray")
    passyword_sv.trace_add("write", entry_change)
    description_sv.trace_add("write", entry_change)
    passyword_entry = ctk.CTkEntry(update_frame, width=200, height=35, textvariable=passyword_sv)
    passyword_entry.pack(padx=20, pady=20)
    description_entry = ctk.CTkEntry(update_frame, width=200, height=35, textvariable=description_sv)
    description_entry.pack(padx=20, pady=20)
    def update_info_decision(decision: int) -> None:
        if decision == 1:
            new_passyword = passyword_entry.get()
            new_description = description_entry.get()
            delete(og_passyword, og_description)
            store(new_passyword, new_description)
            dump_desc()
            update_prompt.destroy()
        if decision == 0:
            update_prompt.destroy()
    save_button, cancel_button = binary_buttons(update_frame, update_info_decision, "Save", "Cancel")
    save_button.configure(state="disabled", fg_color="gray")
    update_prompt.grab_set()

def clear_out():
    vault_output.configure(state="normal")
    vault_output.delete("0.0", "end")
    vault_output.configure(state="disabled")

def delete_info(word: str, desc: str) -> None:
    confirm_delete = f"Are you sure you want to delete {desc}?"
    global vault_timer
    if vault_timer is not None:
        app.after_cancel(vault_timer)
        vault_timer = None
    if vault_output.get("1.0", "end-1c") == confirm_delete:
        delete(word, desc)
        dump_desc()
        vault_output.configure(state="normal")
        vault_output.delete("0.0", "end")
        vault_output.insert("0.0", f"{desc} has been successfully deleted")
        vault_output.configure(state="disabled")
    else:
        vault_output.configure(state="normal")
        vault_output.delete("0.0", "end")
        vault_output.insert("0.0", confirm_delete)
        vault_output.configure(state="disabled")
    vault_timer = app.after(5000, clear_out)

first = first_time()

app = ctk.CTk()
if first:
    app.withdraw()
    set_main()
else:
    app.withdraw()
    main_login()

screen_w = app.winfo_screenwidth()
screen_h = app.winfo_screenheight()

app.geometry(f"{screen_w}x{screen_h}")
app.title("password-manager")

# The frame that contains the area to store passwords
entry_frame_w = floor(screen_w * 0.3)
entry_frame_h = floor(screen_h * 0.37)
corner_spacing = floor(screen_w * 0.01302)

entry_frame = ctk.CTkFrame(master=app, width=entry_frame_w, height=entry_frame_h, corner_radius=5)
entry_frame.place(x=corner_spacing, y=corner_spacing)

entry_label = ctk.CTkLabel(master=entry_frame, text="Store Passwords", font=("Arial", 15))
entry_label.place(relx=0.5, rely=0.01, anchor=tkinter.N)
entry_input = StringVar()

entry_pass = ctk.CTkEntry(master=entry_frame, placeholder_text="Password", width=200, height=35, border_width=2, corner_radius=10)
entry_pass.place(relx=0.5, rely=0.2, anchor=tkinter.CENTER)

entry_description = ctk.CTkEntry(master=entry_frame, placeholder_text="Description", width=200, height=35, border_width=2, corner_radius=10)
entry_description.place(relx=0.5, rely=0.4, anchor=tkinter.CENTER)

store_button = ctk.CTkButton(master=entry_frame, text="Store", command=confirm_storage)
store_button.place(relx=0.5, rely=0.6, anchor=tkinter.CENTER)
store_message = ctk.CTkLabel(master=entry_frame, textvariable = entry_input, width=120, height=25, corner_radius=8)    
store_message.place(relx=0.5, rely=0.75, anchor=tkinter.CENTER)

PLACEHOLDERS = {"Password Length", "# of Letters", "# of Numbers", "# of Symbols"}

# Used to make sure a CTkEntry only accepts numbers
def only_numbers(P) -> bool:
    if P == "" or P in PLACEHOLDERS:
        return True
    return P.isdigit()

# Enables/Disables CTkEntry whenever the checkbox is checked/unchecked
def e_d_entries(checkbox, entry, pc) -> None:
    if checkbox.get() == 1:
        entry.configure(state="normal")
        entry.configure(validate="key", validatecommand=(only_nums, "%P"))
        if entry.get() == pc:
            entry.delete(0, "end")
            entry.focus()
        elif entry.get() == "":
             entry.focus()
    else:
        entry.configure(state="normal")
        if entry.get() != "":
            entry.delete(0, "end")
        entry.configure(placeholder_text=pc)
        entry.configure(state="disabled")

# Fetches the state of checkboxes to figure out what the user wants in their password.
def fetch_cb_states() -> list:
    checkbox_states = []
    if generate_cb_letters.get() == 1:
        checkbox_states.append((1, generate_letters_entry.get()))
    else:
        checkbox_states.append((0, generate_letters_entry.get()))
    if generate_cb_numbers.get() == 1:
        checkbox_states.append((1, generate_numbers_entry.get()))
    else:
        checkbox_states.append((0, generate_numbers_entry.get()))
    if generate_cb_symbols.get() == 1:
        checkbox_states.append((1, generate_symbols_entry.get()))
    else:
        checkbox_states.append((0, generate_symbols_entry.get()))
    return checkbox_states


# The frame that contains the area to generate passwords.
generate_frame_w = entry_frame_w
generate_frame_h = entry_frame_h
generate_frame = ctk.CTkFrame(master=app, width=generate_frame_w, height=(generate_frame_h * 1.05), corner_radius=5)
generate_frame.place(x=corner_spacing, y=generate_frame_h + (2 * corner_spacing))
generate_label = ctk.CTkLabel(master=generate_frame, text="Password Generator", font=("Arial", 15))
generate_label.place(relx=0.5, rely=0.01, anchor=tkinter.N)
only_nums = app.register(only_numbers)

# Section that deals with password length
generate_pass_strength = ctk.CTkLabel(master=generate_frame, text="")
generate_pass_strength.place(relx=0.5, rely=0.26, anchor=tkinter.N)
generate_pass_length = ctk.CTkEntry(master=generate_frame, placeholder_text="Password Length", validate="key", validatecommand=(only_nums, "%P"))
generate_pass_length.place(relx=0.5, rely=0.16, anchor=tkinter.N)
generate_pass_length.bind("<KeyRelease>", lambda event: check_strength("Password Length", generate_pass_length, generate_pass_strength))

# Section that deals with # of letters in the password to generate
cb_generate_let_var = ctk.IntVar()
generate_letters_entry = ctk.CTkEntry(master=generate_frame, placeholder_text="# of Letters")
generate_letters_entry.place(relx=0.3, rely=0.45, anchor=tkinter.W)
letters_entry_strength = ctk.CTkLabel(master=generate_frame, text="")
letters_entry_strength.place(relx=0.6, rely=0.45, anchor=tkinter.W)
generate_letters_entry.bind("<KeyRelease>", lambda event: check_strength("Letters", generate_letters_entry, letters_entry_strength))
generate_cb_letters = ctk.CTkCheckBox(master=generate_frame, text="", variable=cb_generate_let_var, command=lambda: e_d_entries(cb_generate_let_var, generate_letters_entry, "# of Letters"), width=0)
generate_cb_letters.place(relx=0.2, rely=0.45, anchor=tkinter.W)

# Section that deals with # of numbers in the password to generate
cb_generate_num_var = ctk.IntVar()
generate_numbers_entry = ctk.CTkEntry(master=generate_frame, placeholder_text="# of Numbers")
generate_numbers_entry.place(relx=0.3, rely=0.6, anchor=tkinter.W)
numbers_entry_strength = ctk.CTkLabel(master=generate_frame, text="")
numbers_entry_strength.place(relx=0.6, rely=0.6, anchor=tkinter.W)
generate_numbers_entry.bind("<KeyRelease>", lambda event: check_strength("Numbers", generate_numbers_entry, numbers_entry_strength))
generate_cb_numbers = ctk.CTkCheckBox(master=generate_frame, text="", variable=cb_generate_num_var, command=lambda: e_d_entries(cb_generate_num_var, generate_numbers_entry, "# of Numbers"), width=0)
generate_cb_numbers.place(relx=0.2, rely=0.6, anchor=tkinter.W)

cb_generate_sym_var = ctk.IntVar()
generate_symbols_entry = ctk.CTkEntry(master=generate_frame, placeholder_text="# of Symbols")
generate_symbols_entry.place(relx=0.3, rely=0.75, anchor=tkinter.W)
symbols_entry_strength = ctk.CTkLabel(master=generate_frame, text="")
symbols_entry_strength.place(relx=0.6, rely=0.75, anchor=tkinter.W)
generate_symbols_entry.bind("<KeyRelease>", lambda event: check_strength("Symbols", generate_symbols_entry, symbols_entry_strength))
generate_cb_symbols = ctk.CTkCheckBox(master=generate_frame, text="", variable=cb_generate_sym_var, command=lambda: e_d_entries(cb_generate_sym_var, generate_symbols_entry, "# of Symbols"), width=0)
generate_cb_symbols.place(relx=0.2, rely=0.75, anchor=tkinter.W)

generate_output = ctk.CTkTextbox(master=app, width=generate_frame_w, height=floor((screen_h - generate_frame_h) * 0.13))
generate_output.configure(state="disabled")
generate_output.place(x=corner_spacing, y=(screen_h * 0.82))

e_d_entries(cb_generate_let_var, generate_letters_entry, "# of Letters")
e_d_entries(cb_generate_num_var, generate_numbers_entry, "# of Numbers")
e_d_entries(cb_generate_sym_var, generate_symbols_entry, "# of Symbols")

def output_generate_result() -> None:
    global generate_timer
    generate_output.configure(state="normal")
    message = generate_passyword(fetch_cb_states(), generate_pass_length, generate_letters_entry, generate_numbers_entry, generate_symbols_entry)
    if not message == '':
        generate_output.delete("0.0", "end")
        generate_output.insert("0.0", message)
        generate_output.configure(state="disabled")
        if 'generate_timer' in globals() and generate_timer is not None:
            generate_output.after_cancel(generate_timer)
        def clear_generate_output():
            generate_output.configure(state="normal")
            generate_output.delete("0.0", "end")
            generate_output.configure(state="disabled")
            global generate_timer
            generate_timer = None
        generate_timer = generate_output.after(10000, clear_generate_output)

def copy_passyword(output_box) -> None:
    output_box.configure(state="normal")
    passyword = output_box.get("0.0", "end")
    output_box.configure(state="disabled")
    pyperclip.copy(passyword.strip())

generate_passyword_button = ctk.CTkButton(master=generate_frame, text="Generate", command=lambda: output_generate_result())
generate_passyword_button.place(relx=0.5, rely=0.85, anchor=tkinter.N)

clipboard = Image.open(os.path.join(os.path.join(os.getcwd(), "mini_icons"), "clipboard.png"))
clipboard_img = ctk.CTkImage(light_image=clipboard, dark_image=clipboard, size=(20, 20))
generate_copy_button = ctk.CTkButton(master=generate_output, text='', image=clipboard_img, command=lambda: copy_passyword(generate_output), fg_color="#1d1e1e", width=0)
generate_copy_button.place(relx=1.0, rely=0.25, anchor=tkinter.E)

# The frame that contains the area that displays password descriptions and their show buttons
vault_frame_w = floor(screen_w * 0.4)
vault_frame_h = floor(screen_h - (screen_h * 0.27))
vault_frame = ctk.CTkFrame(master=app, width=vault_frame_w, height=vault_frame_h, corner_radius=5)
vault_frame.place(x=(screen_w - vault_frame_w - corner_spacing), y=corner_spacing)

# Storage Frame's message output box
vault_output = ctk.CTkTextbox(master=app, width=vault_frame_w, height=floor((screen_h - vault_frame_h) * 0.31))
vault_output.configure(state="disable")
vault_output.place(x=(screen_w - vault_frame_w - corner_spacing), y=(screen_h * 0.82))

vault_copy_button = ctk.CTkButton(master=vault_output, text='', image=clipboard_img, command=lambda: copy_passyword(vault_output), fg_color="#1d1e1e", width=0)
vault_copy_button.place(relx=1.0, rely=0.25, anchor=tkinter.E)

search_bar = ctk.CTkEntry(master=vault_frame, width=(vault_frame_w * 0.97), placeholder_text="🔍 Search")
search_bar.pack(padx=10, pady=10)
search_bar.bind("<Return>", desc_search)

# Storage Frame's scrollbar
storage_content = ctk.CTkScrollableFrame(
    master=vault_frame,
    width=vault_frame_w - corner_spacing,
    height=vault_frame_h,
    corner_radius=5,
    fg_color="#2b2b2b"
)
storage_content.pack(fill="both", expand=True)

side_spacing = floor(screen_h * 0.01851)
upper_spacing = floor(screen_w * 0.009255)

# Storage Frame's function to output all the descriptions of passwords and buttons to reveal a corresponding password that fades after 10 seconds
def dump_desc():
    cwd = os.path.join(os.getcwd(), "mini_icons")
    pencil = Image.open(os.path.join(cwd, "pencil.png"))
    recycle = Image.open(os.path.join(cwd, "recycle-bin.png"))
    pencil_img = ctk.CTkImage(light_image=pencil, dark_image=pencil, size=(20, 20))
    recycle_img = ctk.CTkImage(light_image=recycle, dark_image=recycle, size=(20, 20))
    data = access()
    if data == None:
        return
    for child in storage_content.winfo_children():
        child.destroy()
    storage_content.grid_columnconfigure(0, weight=1)
    for i in range(len(data)):
        try:
            desc_label = ctk.CTkLabel(storage_content, text=data[i]["desc"])
            desc_label.grid(row=i, column=0, sticky="w", padx=side_spacing, pady=upper_spacing)
            show_button = ctk.CTkButton(storage_content, text="Show Password", command=lambda d=data[i]["desc"]: fetch_requested(d), fg_color="#2b2b2b", width=0)
            show_button.grid(row=i, column=0, sticky="e")
            update_button = ctk.CTkButton(storage_content, text='', image=pencil_img, command=lambda d=data[i]["desc"]: update_info(d), fg_color="#2b2b2b", width=0)
            update_button.grid(row=i, column=1, sticky="e")
            delete_button = ctk.CTkButton(storage_content, text='', image=recycle_img, command=lambda d=data[i]["desc"]: delete_info(fetch(d), d), fg_color="#2b2b2b", width=0)
            delete_button.grid(row=i, column=2, sticky="e")
        except KeyError:        # I realized that this would happen if the user enters the app without any passwords stored.
            return

menu_bar = tkinter.Menu(app)
file_menu = tkinter.Menu(menu_bar, tearoff=0)
file_menu.add_command(label="Import", command=confirm_import)
file_menu.add_command(label="Export", command=confirm_export)
file_menu.add_command(label="Exit", command=lambda: sys.exit())

settings_menu = tkinter.Menu(menu_bar, tearoff=0)

# Needs to use static array of commands and their names because of how tkinter handles tcl commands
settings_items = [
    ("Enable 2FA", confirm_enable_2FA),
    ("Disable 2FA", confirm_disable_2FA),
    ("Reset Master Password", confirm_reset)
]

# Pretty much used to dynamically update the 2FA options in the settings options
def update_2FA_status(twoFA_option: str):
    global settings_items
    updated_menu = []
    if twoFA_option == "Enable 2FA":
        updated_menu.append(("Disable 2FA", confirm_disable_2FA))
    else:
        updated_menu.append(("Enable 2FA", confirm_enable_2FA))
    for title, cmd in settings_items:
        if title not in ("Enable 2FA", "Disable 2FA"):
            updated_menu.append((title, cmd))
    settings_items = updated_menu
    settings_menu.delete(0, 'end')
    for title, cmd in settings_items:
        settings_menu.add_command(label=title, command=cmd)

if is2FAsetup():
    settings_menu.add_command(label="Disable 2FA", command=confirm_disable_2FA)
else:
    settings_menu.add_command(label="Enable 2FA", command=confirm_enable_2FA)
    
settings_menu.add_command(label="Reset Master Password", command=confirm_reset)
menu_bar.add_cascade(label="File", menu=file_menu)
menu_bar.add_cascade(label="Settings", menu=settings_menu)
app.config(menu=menu_bar)

app.mainloop()