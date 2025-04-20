from main_work import *

def store(word: str, desc: str) -> None:
    yes = manage(word, desc)
    yes.setup()
    yes.encrypt()
    if os.path.exists(".helper"):
        os.chdir(".helper")
        yes.save_info()
        os.chdir("..")
    else:
        hidden_dir(".helper")
        os.chdir(".helper")
        yes.save_info()
        os.chdir("..")

def master(passyword: str) -> None:
    os.chdir(".helper")
    set_master(passyword)
    os.chdir("..")

def main():
    return

if __name__ == "__main__":
    main()