from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, sys, shutil
import json
import bcrypt
from base64 import b64encode, b64decode
import ctypes
import subprocess

def hidden_dir(dir_name: str) -> None:
    if not dir_name.startswith('.'):
        dir_name = f".{dir_name}"
    os.makedirs(dir_name, exist_ok=True)
    if sys.platform == "win32":
        ctypes.windll.kernel32.SetFileAttributesW(dir_name, 0x02)

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
    grant_perms(".helper")
    os.chdir(".helper")
    with open("master.json", "w") as file:
        json.dump(data, file, indent=4)
    os.chdir("..")
    rm_perms(".helper")

def check_master(password):
    grant_perms(".helper")
    os.chdir(".helper")
    if os.path.exists("master.json"):
        grant_perms("master.json")
        with open("master.json", "r") as file:
            info = json.load(file)
        user_salt = data["salt"]
        stored_hash = data["hash"]
        user_salt = b64decode(user_salt)
        stored_hash = b64decode(stored_hash)
        rm_perms("master.json")
        os.chdir("..")
        rm_perms(".helper")
        hashed_pass = bcrypt.hashpw(password.encode(), user_salt)
        if hashed_pass == stored_hash:
            return True
        else:
            return False
    else:
        os.chdir("..")
        rm_perms(".helper")
        return False

def rm_perms(item: str) -> None:
    if sys.platform == "win32":
        subprocess.run(["icacls", item, "/inheritance:r"], check=True)
        subprocess.run(["icacls", item, "/deny", "Everyone:F"], check=True)
    else:
        os.chmod(item, 0)

def grant_perms(item: str):
    if sys.platform == "win32":
        subprocess.run(["icacls", item, "/grant", "Everyone:F"], check=True)
    else:
        os.chmod(item, stat.S_IXUSR)

def lockup() -> None:
    os.chdir(".helper")
    rm_perms("main_work.py")
    os.chdir("..")
    rm_perms(".helper")

def startup() -> None:
    grant_perms(".helper")
    os.chdir(".helper")
    grant_perms("main_work.py")
    os.chdir("..")

class manage:
    
    def __init__(self, password: str, description: str):
        if password != None and description != None:
            self.password = password.encode()
            self.desc = description
        else:
            self.password = None
            self.desc = None
        self.nonce = None
        self.key = None
        self.aesgcm = None
        self.cipher_t = None
        self.auth_t = None

    def setup(self):
        self.nonce = os.urandom(12)
        self.key = AESGCM.generate_key(bit_length=256)
        self.aesgcm = AESGCM(self.key)

    def encrypt(self) -> None:
        encrypted = self.aesgcm.encrypt(self.nonce, self.password, None)
        self.cipher_t = encrypted[:-16]
        self.auth_t = encrypted[-16:]

    def decrypt(self) -> None:
        full_info = self.cipher_t + self.auth_t
        self.password = self.aesgcm.decrypt(self.nonce, full_info, None)

    def save_info(self) -> None:
        data = {
            "desc" : self.desc,
            "enc_k" : b64encode(self.key).decode("utf-8"),
            "non" : b64encode(self.nonce).decode("utf-8"),
            "cipher_t" : b64encode(self.cipher_t).decode("utf-8"),
            "tag" : b64encode(self.auth_t).decode("utf-8")
        }
        if os.path.exists("manager.json"):
            with open("manager.json", "r") as file:
                try:
                    existing = json.load(file)
                except json.JSONDecodeError:
                    existing = []
        else:
            existing = []
        existing.append(data)
        with open("manager.json", "w") as file:
            json.dump(existing, file, indent=4)

    def load_info(self, description) -> None:
        try:
            with open("manager.json", "r") as file:
                data = json.load(file)
            for section in data:
                if section["desc"] == description:
                    self.key = b64decode(section["enc_k"])
                    self.nonce = b64decode(section["non"])
                    self.cipher_t = b64decode(section["cipher_t"])
                    self.auth_t = b64decode(section["tag"])
                    self.aesgcm = AESGCM(self.key)
        except FileNotFoundError:
            return


def main():
    return
    

if __name__ == "__main__":
    main()