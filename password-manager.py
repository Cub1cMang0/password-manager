from handle import *

# Prompts the user if they are sure with their decision of storing their password
def confirm_storage():
    store_button.place_forget()
    entry_input.set("Are you sure you want to store this password?")
    def handle_storage(decision: int):           # Handles password storage decision
        if decision == 0:
            rm_message(entry_input)
        if decision == 1:
            word = user_pass.get()
            desc = entry_description.get()
            store(word, desc)
            entry_input.set("Password has been stored!")    
            user_pass.delete(0, 'end')
            entry_description.delete(0, 'end')
            app.after(4000, lambda: rm_message(entry_input))
        yes_button.place_forget()
        no_button.place_forget()
        store_button.place(relx=0.5, rely=0.6, anchor=tkinter.CENTER)
        dump_desc()
    yes_button, no_button = big_yes_no_buttons(entry_frame, handle_storage)

# Prompts the user if they are sure with their decision of deleting their password
def confirm_deletion():
    deletion_button.place_forget()
    deletion_input.set("Are you sure you want to delete this password?")
    def handle_deletion(decision: int):      # Handles password deletion
        if decision == 0:
            rm_message(deletion_input)
        if decision == 1:
            word = deletion_pass.get()
            desc = deletion_description.get()
            result = delete(word, desc)
            if result == 2:
                deletion_input.set("Password has been successfully deleted")
                deletion_pass.delete(0, 'end')
                deletion_description.delete(0, 'end')
                dump_desc()
                app.after(4000, lambda: rm_message(deletion_input))
            else:
                deletion_input.set("The description or password entered is incorrect")
        yes_button.place_forget()
        no_button.place_forget()
        deletion_button.place(relx=0.5, rely=0.6, anchor=tkinter.CENTER)
    yes_button, no_button = big_yes_no_buttons(deletion_frame, handle_deletion)

# Fetch the user's requested password in the output textbox and make it disappear after 10 seconds. Also refreshes 10 second timer
def fetch_requested(d: str):
    global current_timer
    show_output.configure(state="normal")
    output = fetch(d)
    if not output == '':
        show_output.delete("0.0", "end")
        show_output.insert("0.0", output)
        show_output.configure(state="disable")
        if 'current_timer' in globals() and current_timer is not None:
            show_output.after_cancel(current_timer)
        def clear_output():
            show_output.configure(state="normal")
            show_output.delete("0.0", "end")
            show_output.configure(state="disabled")
            global current_timer
            current_timer = None
        current_timer = show_output.after(10000, clear_output)

def rm_message(message_input):
    message_input.set("")

# Used to set the master password for teh user the first time. Also, gives the user an option to enable 2FA.
def set_main():
    twoFA_already = is2FAsetup()
    prompt = customtkinter.CTkToplevel()
    prompt.title("Setup")
    prompt.geometry("720x480")
    set_m_frame = customtkinter.CTkFrame(prompt)
    set_m_frame.pack(padx=20, pady=20, expand=True)
    question = customtkinter.CTkLabel(set_m_frame, text=("Before you get started, you need to set up a master password"
                                                    " to access all of the passwords you will be storing."
                                                    " Make sure that it's at least 20+ characters long!"
                                                    "\n (Note: It can be changed later.)" )
                                            , wraplength=360)
    question.pack(padx=20, pady=20)
    answer = customtkinter.CTkEntry(set_m_frame, width=200)
    answer.pack(padx=20, pady=10)
    def submit():
        password = answer.get()
        if len(password) < 20:
            question.configure(text="Password is too short! Enter a master password 20+ characters long!", wraplength=360)
            return
        elif len(password) > 50:
            question.configure(text="Bro you are not Mr. President. Enter a master password less than 50+ characters long!", wraplength=360)
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
                    prompt.destroy()
                    app.deiconify()
                if decision == 1:
                    prompt.destroy()
                    finished = setup2FA(yes_button, no_button, app)
            yes_button, no_button = small_yes_no_buttons(set_m_frame, twoFA_decision)
    submit_b = customtkinter.CTkButton(set_m_frame, text="Submit", command=submit)
    submit_b.pack(pady=20)
    prompt.grab_set()

#Of course, the classic master password check to make sure that no one besides the user can get access to the application. Or use 2FA if the user enabled it
def main_login() -> None:
    attempt = 0
    prompt = customtkinter.CTkToplevel()
    prompt.title("Login")
    prompt.geometry("720x480")
    def master_login_logic(twoFA_enabled: bool):
        for child in prompt.winfo_children():
            child.destroy()
        frame = customtkinter.CTkFrame(prompt)
        frame.pack(padx=20, pady=20, expand=True)
        if not twoFA_enabled:
            check = customtkinter.CTkLabel(frame, text="2FA must be enabled to login via this method")
            check.pack(padx=20, pady=20)
            prompt.after(4000, lambda: check.configure(text="Please enter your master password"))
        else:
            check = customtkinter.CTkLabel(frame, text="Please enter your master password", wraplength=360)
        check.pack(padx=20, pady=20)
        password_entry = customtkinter.CTkEntry(frame, placeholder_text="Enter password here", width=200)
        password_entry.pack(padx=20, pady=20)
        def master_login():
            given_password = password_entry.get()
            correct = check_master(given_password)
            nonlocal attempt
            correct = True
            if correct:
                prompt.destroy()
                app.deiconify()
                return
            else:
                attempt += 1
                if attempt == 5:
                    sys.exit()
                check.configure(text=f"Password is incorrect, you have {5-attempt} attempts left.", wraplength=360)
        check_password = customtkinter.CTkButton(frame, text="Login", command=master_login)
        check_password.pack(pady=10)
        use_2FA = customtkinter.CTkButton(frame, text="Login via 2FA", command=login_2FA_logic)
        use_2FA.pack(pady=10)
    def login_2FA_logic():
        for child in prompt.winfo_children():
            child.destroy()
        is2FA = is2FAsetup()
        frame_2FA = customtkinter.CTkFrame(prompt)
        frame_2FA.pack(padx=20, pady=20, expand=True)
        if not is2FA:
            master_login_logic(False)
            return
        check_twoFA = customtkinter.CTkLabel(frame_2FA, text="Enter the 2FA code found in your authenticator to login", wraplength=360)
        check_twoFA.pack(padx=20, pady=20)
        twoFA_entry = customtkinter.CTkEntry(frame_2FA, placeholder_text="Enter 2FA code here", width=200)
        twoFA_entry.pack(padx=20, pady=20)
        def authenticate_2FA():
            successful = check_2FA(twoFA_entry.get())
            if successful:
                prompt.destroy()
                app.deiconify()
            if not successful:
                check_twoFA.configure(text="Incorrect Code")
                prompt.after(4000, lambda: check_twoFA.configure(text="Enter the 2FA code found in your authenticator to login"))
                twoFA_entry.delete(0, "end")
        check_code = customtkinter.CTkButton(frame_2FA, text="Login", command=authenticate_2FA)
        check_code.pack(pady=10)
        use_master = customtkinter.CTkButton(frame_2FA, text="Login via master password", command=lambda: master_login_logic(True))
        use_master.pack(pady=10)
    master_login_logic(True)
    prompt.grab_set()

# Asks the user if they are sure with exporting their passwords.
def confirm_export() -> None:
    export_prompt = customtkinter.CTkToplevel()
    export_prompt.title("Export")
    export_prompt.geometry("720x480")
    export_frame = customtkinter.CTkFrame(export_prompt)
    export_frame.pack(padx=20, pady=20, expand=True)
    export_label = customtkinter.CTkLabel(export_frame, text=("Are you sure you want to export all your stored passwords?"
                                                             "\n(Note: It's not recommended to keep a file with your passwords in plain text on your computer)"), wraplength=360)
    export_label.pack(padx=20, pady=20)
    def export_decision(decision: int) -> None:      # Gives the user the option to, (begrudgingly), export their passwords in a non-encrypted json file for whatever reason
        if decision == 0:
            export_prompt.destroy()
            return
        if decision == 1:
            main_info = access()
            export = []
            for section in main_info:
                desc = section["desc"]
                passy = fetch(desc)
                data = {
                    "desc": desc,
                    "pass": passy
                }
                export.append(data)
            file_path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                title="export"
            )
            if file_path:
                with open(file_path, "w") as file:
                    json.dump(export, file, indent=4)
            export_prompt.destroy()
        yes_button.pack_forget()
        no_button.pack_forget()
    yes_button, no_button = small_yes_no_buttons(export_frame, export_decision)
    export_prompt.grab_set()

def confirm_reset() -> None:
    reset_master_prompt = customtkinter.CTkToplevel()
    reset_master_prompt.title("Reset Master Password")
    reset_master_prompt.geometry("720x480")
    reset_master_frame = customtkinter.CTkFrame(reset_master_prompt)
    reset_master_frame.pack(padx=20, pady=20, expand=True)
    reset_master_label = customtkinter.CTkLabel(reset_master_frame, text=("Are you sure you want to reset your master password?"
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
                reset_label = customtkinter.CTkLabel(reset_master_frame, text="Check your authenticator to enter your 2FA code")
                reset_label.pack(padx=20, pady=20)
                twoFA_entry = customtkinter.CTkEntry(master=reset_master_frame, placeholder_text="Enter 2FA Code Here", width=200, height=35, border_width=2, corner_radius=10)
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
                submit_2FA_b = customtkinter.CTkButton(reset_master_frame, text="Submit", command=submit_2FA)
                submit_2FA_b.pack(padx=20, pady=10)
    yes_button, no_button = small_yes_no_buttons(reset_master_frame, reset_master_decision)
    reset_master_prompt.grab_set()
    
# Gives the user the option to (begrudgingly) disable 2FA 
def confirm_disable_2FA() -> None:
    disable_2FA_prompt = customtkinter.CTkToplevel()
    disable_2FA_prompt.title("Disable 2FA")
    disable_2FA_prompt.geometry("720x480")
    disable_2FA_frame = customtkinter.CTkFrame(disable_2FA_prompt)
    disable_2FA_frame.pack(padx=20, pady=20, expand=True)
    disable_2FA_label = customtkinter.CTkLabel(disable_2FA_frame, text="Are you sure you want to disable 2FA? (Not Recommended)", wraplength=360)
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
            disable_success_label = customtkinter.CTkLabel(disable_2FA_frame, text="2FA has been successfully disabled", wraplength=360)
            disable_success_label.pack(padx=20, pady=20)
            ok_button = customtkinter.CTkButton(disable_2FA_frame, text="Ok", command= lambda: disable_2FA_prompt.destroy())
            ok_button.pack(padx=20, pady=20)
        yes_button.pack_forget()
        no_button.pack_forget()
    yes_button, no_button = small_yes_no_buttons(disable_2FA_frame, disable_2FA_decision)
    disable_2FA_prompt.grab_set()

# Gives the user the option to enable 2FA if they didn't during the setup
def confirm_enable_2FA() -> None:
    enable_2FA_prompt = customtkinter.CTkToplevel()
    enable_2FA_prompt.title("Enable 2FA")
    enable_2FA_prompt.geometry("720x480")
    enable_2FA_frame = customtkinter.CTkFrame(enable_2FA_prompt)
    enable_2FA_frame.pack(padx=20, pady=20, expand=True)
    enable_2FA_label = customtkinter.CTkLabel(enable_2FA_frame, text="Are you sure you want to enable 2FA? (Recommended)", wraplength=360)
    enable_2FA_label.pack(padx=20, pady=20)
    def enable_2FA_decision(decision: int):
        if decision == 0:
            enable_2FA_prompt.destroy()
            return
        if decision == 1:
            enable_2FA_prompt.destroy()
            setup2FA(yes_button, no_button, app)
    yes_button, no_button = small_yes_no_buttons(enable_2FA_frame, enable_2FA_decision)
    enable_2FA_prompt.grab_set()

first = first_time()

app = customtkinter.CTk()
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
entry_frame = customtkinter.CTkFrame(master=app, width=entry_frame_w, height=entry_frame_h, corner_radius=5)
corner_spacing = floor(screen_w * 0.01302)
entry_frame.place(x=corner_spacing, y=corner_spacing)

entry_input = StringVar()

# Entry Frame's password entry
user_pass = customtkinter.CTkEntry(master=entry_frame, placeholder_text="Password", width=200, height=35, border_width=2, corner_radius=10)
user_pass.place(relx=0.5, rely=0.2, anchor=tkinter.CENTER)

# Entry Frame's description entry
entry_description = customtkinter.CTkEntry(master=entry_frame, placeholder_text="Description", width=200, height=35, border_width=2, corner_radius=10)
entry_description.place(relx=0.5, rely=0.4, anchor=tkinter.CENTER)

# Entry Frame's storage button
store_button = customtkinter.CTkButton(master=entry_frame, text="Store", command=confirm_storage)
store_button.place(relx=0.5, rely=0.6, anchor=tkinter.CENTER)

# Entry Frame's storage message
store_message = customtkinter.CTkLabel(master=entry_frame, textvariable = entry_input, width=120, height=25, corner_radius=8)    
store_message.place(relx=0.5, rely=0.75, anchor=tkinter.CENTER)

# The frame that contains the area to store passwords
deletion_frame_w = entry_frame_w
deletion_frame_h = entry_frame_h
deletion_frame = customtkinter.CTkFrame(master=app, width=deletion_frame_w, height=deletion_frame_h, corner_radius=5)
deletion_frame.place(x=corner_spacing, y=deletion_frame_h + (8.15 * corner_spacing))

deletion_input = StringVar()

deletion_message = customtkinter.CTkLabel(master=deletion_frame, textvariable = deletion_input, width=120, height=25, corner_radius=8)
deletion_message.place(relx=0.5, rely=0.75, anchor=tkinter.CENTER)

deletion_pass = customtkinter.CTkEntry(master=deletion_frame, placeholder_text="Password to delete", width=200, height=35, border_width=2, corner_radius=10)
deletion_pass.place(relx=0.5, rely=0.2, anchor=tkinter.CENTER)

deletion_description = customtkinter.CTkEntry(master=deletion_frame, placeholder_text="Description", width=200, height=35, border_width=2, corner_radius=10)
deletion_description.place(relx=0.5, rely=0.4, anchor=tkinter.CENTER)

deletion_button = customtkinter.CTkButton(master=deletion_frame, text="Delete", command=confirm_deletion)
deletion_button.place(relx=0.5, rely=0.6, anchor=tkinter.CENTER)

# The frame that contains the area that displays password descriptions and their show buttons
storage_frame_w = floor(screen_w * 0.4)
storage_frame_h = floor(screen_h - (screen_h * 0.2))
storage_frame = customtkinter.CTkFrame(master=app, width=storage_frame_w, height=storage_frame_h, corner_radius=5)
storage_frame.place(x=(screen_w - storage_frame_w - corner_spacing), y=corner_spacing)

# Storage Frame's message output box
show_output = customtkinter.CTkTextbox(master=app, width=storage_frame_w, height=floor((screen_h - storage_frame_h) * 0.4))
show_output.configure(state="disable")
show_output.place(x=(screen_w - storage_frame_w - corner_spacing), y=storage_frame_h + (2 * corner_spacing))

# Storage Frame's scrollbar
storage_content = customtkinter.CTkScrollableFrame(
    master=storage_frame,
    width=storage_frame_w - corner_spacing,
    height=storage_frame_h,
    corner_radius=5,
    fg_color="transparent"
)
storage_content.pack(fill="both", expand=True)

side_spacing = floor(screen_h * 0.01851)
upper_spacing = floor(screen_w * 0.009255)

# Storage Frame's function to output all the descriptions of passwords and buttons to reveal a corresponding password that fades after 10 seconds
def dump_desc():
    data = access()
    for child in storage_content.winfo_children():
        child.destroy()
    storage_content.grid_columnconfigure(0, weight=1)
    for i in range(len(data)):
        try:
            desc_label = customtkinter.CTkLabel(storage_content, text=data[i]["desc"])
            desc_label.grid(row=i, column=0, sticky="w", padx=side_spacing, pady=upper_spacing)
            show_button = customtkinter.CTkButton(storage_content, text="Show Password", command=lambda d=data[i]["desc"]: fetch_requested(d))
            show_button.grid(row=i, column=1, sticky="e", padx=side_spacing, pady=upper_spacing)
        except KeyError:        # I realized that this would happen if the user enters the app without any passwords stored.
            return

exists = present()
if (exists):
    dump_desc()

menu_bar = tkinter.Menu(app)
file_menu = tkinter.Menu(menu_bar, tearoff=0)
file_menu.add_command(label="Export", command=confirm_export)
file_menu.add_command(label="Exit", command=lambda: sys.exit())

settings_menu = tkinter.Menu(menu_bar, tearoff=0)
if is2FAsetup():
    settings_menu.add_command(label="Disable 2FA", command=confirm_disable_2FA)
else:
    settings_menu.add_command(label="Enable 2FA", command=confirm_enable_2FA)
settings_menu.add_command(label="Reset Master Password", command=confirm_reset)

menu_bar.add_cascade(label="File", menu=file_menu)
menu_bar.add_cascade(label="Settings", menu=settings_menu)
app.config(menu=menu_bar)

app.mainloop()