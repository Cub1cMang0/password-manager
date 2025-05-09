import customtkinter, tkinter
from tkinter import *
from handle import *
from math import floor
import pygetwindow

# Just handling password storage and messages
def successful_storage():
    word = user_pass.get()
    desc = description.get()
    store(word, desc)
    user_input.set("Password has been stored!")
    app.after(2000, rm_message)

def fetch_requested(d: str):
    show_output.configure(state="normal")
    output = fetch(d)
    show_output.delete("0.0", "end")
    show_output.insert("0.0", output)
    show_output.configure(state="disable")
    def clear_output():
        show_output.configure(state="normal")
        show_output.delete("0.0", "end")
        show_output.configure(state="disabled")
    show_output.after(10000, clear_output)

def rm_message():
    user_input.set("")

first = first_time()

# Used to set the master password for teh user the first time, the line above makese sure this ran after successfully setting a master password
def set_main():
    prompt = customtkinter.CTkToplevel()
    prompt.title("Setup")
    prompt.geometry("720x480")
    frame = customtkinter.CTkFrame(prompt)
    frame.pack(padx=20, pady=20, expand=True)
    question = customtkinter.CTkLabel(frame, text=("Before you get started, you need to set up a master password"
                                                    " to access all of the passwords you will be storing."
                                                    " Make sure that it's at least 20+ characters long!"
                                                    "\n (Note: It can be changed later.)" )
                                            , wraplength=360)
    question.pack(padx=20, pady=20)
    answer = customtkinter.CTkEntry(frame, width=200)
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
        prompt.destroy()
        app.deiconify()
    submit_b = customtkinter.CTkButton(frame, text="Submit", command=submit)
    submit_b.pack(pady=20)
    prompt.grab_set()

#Of course, the classic master password check to make sure that no one besides the user can get access to the application. Might prompt the user again if they want to reveal a password.
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
        correct = True
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

entry_frame_w = floor(screen_w * 0.3)
entry_frame_h = floor(screen_h * 0.37)
entry_frame = customtkinter.CTkFrame(master=app, width=entry_frame_w, height=entry_frame_h, corner_radius=5)
corner_spacing = floor(screen_w * 0.01302)
entry_frame.place(x=corner_spacing, y=corner_spacing)

user_input = StringVar()
user_pass = customtkinter.CTkEntry(master=entry_frame, placeholder_text="Password", width=200, height=35, border_width=2, corner_radius=10)
user_pass.place(relx=0.5, rely=0.2, anchor=tkinter.CENTER)

description = customtkinter.CTkEntry(master=entry_frame, placeholder_text="Description", width=200, height=35, border_width=2, corner_radius=10)
description.place(relx=0.5, rely=0.4, anchor=tkinter.CENTER)

store_button = customtkinter.CTkButton(master=entry_frame, text="Store", command=successful_storage)
store_button.place(relx=0.5, rely=0.6, anchor=tkinter.CENTER)

store_message = customtkinter.CTkLabel(master=entry_frame, textvariable = user_input,
                            width=120, height=25, corner_radius=8)
                            
store_message.place(relx=0.5, rely=0.75, anchor=tkinter.CENTER)

storage_frame_w = floor(screen_w * 0.4)
storage_frame_h = floor(screen_h - (screen_h * 0.2))
storage_frame = customtkinter.CTkFrame(master=app, width=storage_frame_w, height=storage_frame_h, corner_radius=5)
storage_frame.place(x=(screen_w - storage_frame_w - corner_spacing), y=corner_spacing)

idk = floor((screen_h - storage_frame_h) * 0.4)
show_output = customtkinter.CTkTextbox(master=app, width=storage_frame_w, height=idk)
show_output.configure(state="disable")
show_output.place(x=(screen_w - storage_frame_w - corner_spacing), y=storage_frame_h + (2 * corner_spacing))

storage_content = customtkinter.CTkScrollableFrame(
    master=storage_frame,
    width=storage_frame_w,
    height=storage_frame_h,
    corner_radius=5,
    fg_color="transparent"
)
storage_content.pack(fill="both", expand=True)

side_spacing = floor(screen_h * 0.01851)
upper_spacing = floor(screen_w * 0.009255)

# Pretty much functions to output all the descriptions of passwords and buttons to reveal a corresponding password that fades after 10 seconds
def dump_desc():
    data = access()
    storage_content.grid_columnconfigure(0, weight=1)
    for i in range(len(data)):
        desc_label = customtkinter.CTkLabel(storage_content, text=data[i]["desc"])
        desc_label.grid(row=i, column=0, sticky="w", padx=side_spacing, pady=upper_spacing)
        show_button = customtkinter.CTkButton(storage_content, text="Show Password", command=lambda d=data[i]["desc"]: fetch_requested(d))
        show_button.grid(row=i, column=1, sticky="e", padx=side_spacing, pady=upper_spacing)

exists = present()
if (exists):
    dump_desc()

app.mainloop()