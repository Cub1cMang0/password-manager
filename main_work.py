from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import os, sys, shutil, string, random
import json
import bcrypt
import ctypes
import subprocess
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
import base64

QUI = 1

# Idk why I have this. I might delete it later since I'll give the user the hidden dir in the repo
def hidden_dir(dir_name: str) -> None:
    if not dir_name.startswith('.'):
        dir_name = f".{dir_name}"
    os.makedirs(dir_name, exist_ok=True)
    if sys.platform == "win32":
        ctypes.windll.kernel32.SetFileAttributesW(dir_name, 0x02)

# Master password checking logic
def check_master(passyword) -> bool:
    enter_helper()
    if os.path.exists("master.json"):
        grant_perms("master.json")
        with open("master.json", "r") as file:
            data = json.load(file)
        for section in data:
            user_salt = section["salt"]
            stored_hash = section["hash"]
            break
        user_salt = base64.b64decode(user_salt)
        stored_hash = base64.b64decode(stored_hash)
        rm_perms("master.json")
        exit_helper()
        passyword = str(passyword)
        hashed_pass = bcrypt.hashpw(passyword.encode(), user_salt)
        if hashed_pass == stored_hash:
            return True
        else:
            return False
    else:
        exit_helper()
        return False

# Remvoes file permissions to the given file
def rm_perms(item: str) -> None:
    if sys.platform == "win32":
        subprocess.run(
            ["icacls", item, "/inheritance:r"],
            check=True, 
            stdout=subprocess.DEVNULL)
        subprocess.run(
            ["icacls", item, "/deny", "Everyone:F"], 
            check=True,
            stdout=subprocess.DEVNULL)
    else:
        os.chmod(item, 0)

# Grants file permissions to the given file
def grant_perms(item: str):
    if sys.platform == "win32":
        subprocess.run(
            ["icacls", item, "/grant", "Everyone:F"], 
            check=True, 
            stdout=subprocess.DEVNULL
        )
    else:
        os.chmod(item, stat.S_IXUSR)

# Simple function to reduce the two lines in the function
def enter_helper():
    grant_perms(".helper")
    os.chdir(".helper")

# Simple function to reduce the two lines in the function
def exit_helper():
    os.chdir("..")
    rm_perms(".helper")

# Creates a derive key for file encryption using a master password and a salt
def create_key(passyword: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    return base64.urlsafe_b64encode(kdf.derive(passyword.encode()))

# Encrypts .json files using a derived key
def enc_file(master_passyword: str, file_location: str, imported_file: bool) -> None:
    if imported_file:
        salt = os.urandom(16)
    else:
        grant_perms("master.json")
        with open("master.json", "r") as file:
            master_data = json.load(file)
        rm_perms("master.json")
        salt = base64.b64decode(master_data[0]["saltier"])
    key = create_key(master_passyword, salt)
    fernet = Fernet(key)
    with open(file_location, "r") as f:
        file_data = f.read()
    enc_data = fernet.encrypt(file_data.encode())
    complete = base64.urlsafe_b64encode(salt + enc_data)
    with open(file_location, "wb") as enc_file:
        enc_file.write(complete)

def dec_file(master_passyword: str, file_location: str) -> None:
    with open(file_location, "rb") as file:
        complete = base64.urlsafe_b64decode(file.read())
    enc_data = complete[16:]
    salt = complete[:16]
    key = create_key(master_passyword, salt)
    fernet = Fernet(key)
    dec_data = fernet.decrypt(enc_data)
    with open(file_location, "w") as dec_file:
        dec_file.write(dec_data.decode())

# AES algorithm
class PM_Z:    
    def __init__(self, password: str, description: str):
        if password != None and description != None:
            self.password = password.encode()
            self.description = description
        else:
            self.password = None
            self.description = None
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
            "desc": self.description,
            "enc_k": base64.b64encode(self.key).decode(),
            "non": base64.b64encode(self.nonce).decode(),
            "cipher_t": base64.b64encode(self.cipher_t).decode(),
            "tag": base64.b64encode(self.auth_t).decode()
        }
        meta_data = {
            "exported_by": "PM",
            "data": [data],
            "yes": "z"
        }
        if os.path.exists("manager.json"):
            grant_perms("manager.json")
            dec_file(QUI, "manager.json")
            with open("manager.json", "r") as file:
                try:
                    existing = json.load(file)
                    existing[0]["data"].append(data)
                except json.JSONDecodeError:
                    existing = [meta_data]
        else:
            existing = [meta_data]
        with open("manager.json", "w") as file:
            json.dump(existing, file, indent=4)
        enc_file(QUI, "manager.json", False)
        rm_perms("manager.json")

    def load_info(self, description: str) -> bool:
        try:
            enter_helper()
            grant_perms("manager.json")
            dec_file(QUI, "manager.json")
            with open("manager.json", "r") as file:
                file_data = json.load(file)
            data = file_data[0]["data"]
            enc_file(QUI, "manager.json", False)
            rm_perms("manager.json")
            exit_helper()
            for section in data:
                if section["desc"] == description:
                    self.key = section["enc_k"]
                    self.nonce = section["non"]
                    self.cipher_t = section["cipher_t"]
                    self.auth_t = section["tag"]
                    self.aesgcm = AESGCM(self.key)
                    return True
            return False
        except FileNotFoundError:
            return False

class PM_Y:
    def __init__(self, password: str, description: str):
        if password != None and description != None:
            self.password = password.encode()
            self.description = description
        else:
            self.password = None
            self.description = None
        self.key = None
        self.iv = None

    def setup(self) -> None:
        random_jumble = string.ascii_letters + string.digits + string.punctuation
        self.key = (''.join(random.choices(random_jumble, k=56))).encode()

    def encrypt(self) -> None:
        cipher = Blowfish.new(self.key, Blowfish.MODE_CBC)
        self.iv = cipher.iv
        self.password = cipher.encrypt(pad(self.password, Blowfish.block_size))

    def decrypt(self) -> None:
        self.password = unpad((Blowfish.new(self.key, Blowfish.MODE_CBC, iv=self.iv)).decrypt(self.password), Blowfish.block_size)

    def save_info(self) -> None:
        data = {
            "desc": self.description,
            "enc_k": base64.b64encode(self.password).decode(),
            "key": base64.b64encode(self.key).decode(),
            "iv": base64.b64encode(self.iv).decode()
        }
        meta_data = {
            "exported_by": "PM",
            "data": [data],
            "yes": "y"
        }
        if os.path.exists("manager.json"):
            grant_perms("manager.json")
            dec_file(QUI, "manager.json")
            with open("manager.json", "r") as file:
                try:
                    existing = json.load(file)
                    existing[0]["data"].append(data)
                except json.JSONDecodeError:
                    existing = [meta_data]
        else:
            existing = [meta_data]
        with open("manager.json", "w") as file:
            json.dump(existing, file, indent=4)
        enc_file(QUI, "manager.json", False)
        rm_perms("manager.json")

    def load_info(self, description: str) -> bool:
        try:
            enter_helper()
            grant_perms("manager.json")
            dec_file(QUI, "manager.json")
            with open("manager.json", "r") as file:
                file_data = json.load(file)
            data = file_data[0]["data"]
            enc_file(QUI, "manager.json", False)
            rm_perms("manager.json")
            exit_helper()
            for section in data:
                if section["desc"] == description:
                    self.password = base64.b64decode(section["enc_k"])
                    self.key = base64.b64decode(section["key"])
                    self.iv = base64.b64decode(section["iv"])
                    return True
            return False
        except FileNotFoundError:
            return False

class PM_X:
    def __init__(self, password: str, description: str):
        if password != None and description != None:
            self.password = password.encode()
            self.description = description
        else:
            self.password = None
            self.description = None
        self.key = None
        self.nonce = None
    
    def setup(self) -> None:
        self.key = os.urandom(32)
        self.nonce = os.urandom(16)

    def encrypt(self) -> None:
        alg = algorithms.ChaCha20(self.key, self.nonce)
        ciph = Cipher(alg, mode=None, backend=default_backend())
        enc = ciph.encryptor()
        self.password = enc.update(self.password)

    def decrypt(self) -> None:
        alg = algorithms.ChaCha20(self.key, self.nonce)
        ciph = Cipher(alg, mode=None, backend=default_backend())
        dec = ciph.decryptor()
        self.password = dec.update(self.password)

    def save_info(self) -> None:
        data = {
            "desc": self.description,
            "enc_k": base64.b64encode(self.password).decode(),
            "key": base64.b64encode(self.key).decode(),
            "non": base64.b64encode(self.nonce).decode(),
        }
        meta_data = {
            "exported_by": "PM",
            "data": [data],
            "yes": "x"
        }
        if os.path.exists("manager.json"):
            grant_perms("manager.json")
            dec_file(QUI, "manager.json")
            with open("manager.json", "r") as file:
                try:
                    existing = json.load(file)
                    existing[0]["data"].append(data)
                except json.JSONDecodeError:
                    existing = [meta_data]
        else:
            existing = [meta_data]
        with open("manager.json", "w") as file:
            json.dump(existing, file, indent=4)
        enc_file(QUI, "manager.json", False)
        rm_perms("manager.json")

    def load_info(self, description: str) -> bool:
        try:
            enter_helper()
            grant_perms("manager.json")
            dec_file(QUI, "manager.json")
            with open("manager.json", "r") as file:
                file_data = json.load(file)
            data = file_data[0]["data"]
            enc_file(QUI, "manager.json", False)
            rm_perms("manager.json")
            exit_helper()
            for section in data:
                if section["desc"] == description:
                    self.password = base64.b64decode(section["enc_k"])
                    self.key = base64.b64decode(section["key"])
                    self.nonce = base64.b64decode(section["non"])
                    return True
            return False
        except FileNotFoundError:
            return False

def main():
    dec_file("EggsNBacon", "export.json")

if __name__ == "__main__":
    main()