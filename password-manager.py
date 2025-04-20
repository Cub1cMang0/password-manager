import customtkinter, tkinter
from tkinter import *
from handle import *

def button_callback():
    word = user_pass.get()
    desc = description.get()
    store(word, desc)
    text_var.set("Password has been stored!")
    app.after(2000, rm_message)

def rm_message():
    text_var.set("")

def set_main():
    prompt = customtkinter.CTkToplevel()
    prompt.title("Setup")
    frame = customtkinter.CTkFrame(prompt)
    frame.pack(padx=20, pady=20, expand=True)
    question = customtkinter.CTkLabel(frame, text="Before you get started, you need to set up a master password")
    question.pack(padx=20, pady=20)
    answer = customtkinter.CTkEntry(frame, width=200)
    answer.pack(padx=20, pady=10)
    def submit():
        password = answer.get()
        master(password)
        prompt.destroy()
        app.deiconify()
    submit_b = customtkinter.CTkButton(frame, text="Submit", command=submit)
    submit_b.pack(pady=20)
    prompt.grab_set()

app = customtkinter.CTk()

app.withdraw()

app.geometry("1024x768")
app.title("Password Manager")

frame = customtkinter.CTkFrame(master=app, width=600, height=400, bg_color="black", fg_color="grey", corner_radius=5)
frame.pack(padx=20, pady=20)

text_var = StringVar()

user_pass = customtkinter.CTkEntry(master=frame, placeholder_text="Password", width=200, height=35, border_width=2, corner_radius=10)
user_pass.place(relx=0.5, rely=0.2, anchor=tkinter.CENTER)

description = customtkinter.CTkEntry(master=frame, placeholder_text="Description", width=200, height=35, border_width=2, corner_radius=10)
description.place(relx=0.5, rely=0.4, anchor=tkinter.CENTER)

button = customtkinter.CTkButton(master=frame, text="Store", command=button_callback)
button.place(relx=0.5, rely=0.6, anchor=tkinter.CENTER)

label = customtkinter.CTkLabel(master=frame, textvariable = text_var,
                            width=120, height=25, fg_color=("black", "gray"), corner_radius=8)
                            
label.place(relx=0.5, rely=0.75, anchor=tkinter.CENTER)

set_main()

app.mainloop()