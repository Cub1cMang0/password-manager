from handle import *

# Working on figuring out if I should require 2FA or ask the user if they would like to set it up?

def yes_no_buttons(framework, conf_type):
    yes_button = customtkinter.CTkButton(master=framework, text="Yes", command=lambda decision=1: conf_type(decision))
    yes_button.place(relx=0.35, rely=0.6, anchor=tkinter.CENTER)
    no_button = customtkinter.CTkButton(master=framework, text="No", command=lambda decision=0: conf_type(decision))
    no_button.place(relx=0.65, rely=0.6, anchor=tkinter.CENTER)
    return yes_button, no_button

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
    yes_button, no_button = yes_no_buttons(entry_frame, handle_storage)

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
                app.after(4000, lambda: rm_message(deletion_input))
            else:
                deletion_input.set("The description or password entered is incorrect")
        deletion_button.place(relx=0.5, rely=0.6, anchor=tkinter.CENTER)
    yes_button, no_button = yes_no_buttons(deletion_frame, handle_deletion)

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
        question.configure(set_m_frame, text="Would you like to enable 2FA? (Note: 2FA is required to reset master password)")
        def twoFA_decision(decision: int):
            if decision == 0:
                prompt.destroy()
                app.deiconify()
            if decision == 1:
                yes_button.pack_forget()
                no_button.pack_forget()
                twoFA_key = setup_2FA()
                qr_code = open_image()
                qr_code_image = customtkinter.CTkImage(light_image=qr_code, dark_image=qr_code, size=(550, 550))
                prompt.geometry("700x790")
                set_m_frame = customtkinter.CTkFrame(prompt)
                set_m_frame.pack(padx=20, pady=20, expand=True)
                question.configure(image=qr_code_image, text=f"Manual 2FA Key: {twoFA_key}", compound="top")
                twoFA_entry = customtkinter.CTkEntry(master=set_m_frame, placeholder_text="Enter 2FA Code Here", width=200, height=35, border_width=2, corner_radius=10)
                twoFA_entry.pack(padx=20,pady=0)
                def submit_2FA():
                    code_2FA = twoFA_entry.get()
                    successful = check_2FA(code_2FA)
                    if successful:
                        prompt.destroy()
                        app.deiconify()
                    else:
                        question.configure(image=qr_code_image, text=f"Manual 2FA Key: {twoFA_key}" + "\nIncorrect Code", compound="top")
                        twoFA_entry.delete(0, "end")
                submit_2FA_b = customtkinter.CTkButton(set_m_frame, text="Submit", command=submit_2FA)
                submit_2FA_b.pack(padx=20, pady=10)
                question.image = qr_code_image
        yes_button = customtkinter.CTkButton(master=set_m_frame, text="Yes", command=lambda decision=1: twoFA_decision(decision))
        yes_button.pack(side=tkinter.LEFT, padx=(20, 10), pady=20) # Use pack for placement
        no_button = customtkinter.CTkButton(master=set_m_frame, text="No", command=lambda decision=0: twoFA_decision(decision))
        no_button.pack(side=tkinter.RIGHT, padx=(10, 20), pady=20) # Use pack for placement
    submit_b = customtkinter.CTkButton(set_m_frame, text="Submit", command=submit)
    submit_b.pack(pady=20)
    prompt.grab_set()

#Of course, the classic master password check to make sure that no one besides the user can get access to the application.
def login() -> None:
    attempt = 0
    prompt = customtkinter.CTkToplevel()
    prompt.title("Login")
    prompt.geometry("720x480")
    frame = customtkinter.CTkFrame(prompt)
    frame.pack(padx=20, pady=20, expand=True)
    check = customtkinter.CTkLabel(frame, text="Please enter your master password", wraplength=360)
    check.pack(padx=20, pady=20)
    password_entry = customtkinter.CTkEntry(frame, width=200)
    password_entry.pack(padx=20, pady=20)
    def check_attempt():
        given_password = password_entry.get()
        correct = check_master(given_password)
        nonlocal attempt
        if correct:
            prompt.destroy()
            app.deiconify()
            return
        else:
            attempt += 1
            if attempt == 5:
                sys.exit()
            check.configure(text=f"Password is incorrect, you have {5-attempt} left.", wraplength=360)
    check_password = customtkinter.CTkButton(frame, text="Login", command=check_attempt)
    check_password.pack(pady=20)
    prompt.grab_set()

first = first_time()

app = customtkinter.CTk()
if first:
    app.withdraw()
    set_main()
else:
    app.withdraw()
    login()

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

app.mainloop()