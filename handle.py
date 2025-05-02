from main_work import *

def store(word: str, desc: str) -> None:
    yes = manage(word, desc)
    yes.setup()
    yes.encrypt()
    if os.path.exists(".helper"):
        grant_perms(".helper")
        os.chdir(".helper")
        yes.save_info()
        os.chdir("..")
    else:
        hidden_dir(".helper")
        os.chdir(".helper")
        yes.save_info()
        os.chdir("..")
    rm_perms(".helper")

def access():
    grant_perms(".helper")
    os.chdir(".helper")
    with open("manager.json", "r") as file:
        data = json.load(file)
    os.chdir("..")
    rm_perms(".helper")
    return data

def master(passyword: str) -> None:
    grant_perms(".helper")
    os.chdir(".helper")
    set_master(passyword)
    os.chdir("..")
    rm_perms(".helper")

def first_time() -> bool:
    grant_perms(".helper")
    os.chdir(".helper")
    if os.path.exists("master.json"):
        os.chdir("..")
        rm_perms(".helper")
        return False
    else:
        os.chdir("..")
        rm_perms(".helper")
        return True

def present() -> bool:
    grant_perms(".helper")
    os.chdir(".helper")
    exists = os.path.exists("manager.json")
    os.chdir("..")
    rm_perms(".helper")
    return exists

def main():
    return

if __name__ == "__main__":

