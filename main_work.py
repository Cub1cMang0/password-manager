from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import os, sys, string, random
import json
import bcrypt
import ctypes
import subprocess
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
import base64
from hashlib import sha256


QUI = None
AUTH_TYPE = None

# Idk why I have this. I might delete it later since I'll give the user the hidden dir in the repo
def hidden_dir(dir_name: str) -> None:
    if not dir_name.startswith('.'):
        dir_name = f".{dir_name}"
    os.makedirs(dir_name, exist_ok=True)
    if sys.platform == "win32":
        ctypes.windll.kernel32.SetFileAttributesW(dir_name, 0x02)

# Check if the user has 2FA setup (used to avoid or prompt the user of using features that requrie 2FA to be setup).
def is2FAsetup() -> bool:
    enter_helper()
    if not os.path.exists("master.json"):
        exit_helper()
        return False
    grant_perms("master.json")
    with open("master.json", "r") as file:
        data = json.load(file)
    rm_perms("master.json")
    exit_helper()
    source = None
    for section in data:
        if "2FA" in section:
            source = section["2FA"]
    if source == None:
        return False
    elif source != None:
        return True

# Master password checking logic
def check_master(passyword) -> bool:
    enter_helper()
    if os.path.exists("master.json"):
        grant_perms("master.json")
        with open("master.json", "r") as file:
            data = json.load(file)
        for section in data:
            if "salt" in section:
                user_salt = section["salt"]
            if "hash" in section:
                stored_hash = section["hash"]
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
    
def check_recovery_key(recovery_key) -> bool:
    enter_helper()
    if os.path.exists("master.json"):
        grant_perms("master.json")
        with open("master.json", "r") as file:
            data = json.load(file)
        for section in data:
            if "rec_salt" in section:
                user_salt = section["rec_salt"]
            if "rec_hash" in section:
                stored_rec_hash = section["rec_hash"]
        user_salt = base64.b64decode(user_salt)
        stored_rec_hash = base64.b64decode(stored_rec_hash)
        rm_perms("master.json")
        exit_helper()
        rec_key = str(recovery_key)
        hashed_rec_key = bcrypt.hashpw(rec_key.encode(), user_salt)
        if hashed_rec_key == stored_rec_hash:
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
def create_key(sussy_secret: str, salt: bytes = None) -> bytes:
    if salt:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
        return base64.urlsafe_b64encode(kdf.derive(sussy_secret.encode()))
    else:
        d_key = hashes.Hash(hashes.SHA256(), backend=default_backend())
        d_key.update(sussy_secret.encode())
        return base64.urlsafe_b64encode(d_key.finalize())

# Encrypts .json files using a derived key
def enc_file(master_passyword: str, file_location: str):
    salty = os.urandom(16)
    v_key = Fernet.generate_key()
    key_mp = create_key(master_passyword, salty)
    fernet_mp = Fernet(key_mp)
    if is2FAsetup():
        saltier = ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(32))
        key_2fa = create_key(saltier)
        fernet_2fa = Fernet(key_2fa)
        enc_v_key_2fa = fernet_2fa.encrypt(v_key)
    else:
        key_2fa = None
    enc_v_key_mp = fernet_mp.encrypt(v_key)
    with open(file_location, "r") as f:
        file_data = f.read()
    fernet_vault = Fernet(v_key)
    enc_data = fernet_vault.encrypt(file_data.encode())
    essentials = {
        "v_key_master": enc_v_key_mp.decode(),
        "v_key_2fa": None,
        "salty": base64.b64encode(salty).decode(),
        "saltier": None,
        "data": enc_data.decode()
    }
    if key_2fa != None:
        essentials["v_key_2fa"] = enc_v_key_2fa.decode()
        essentials["saltier"] = saltier
    with open(file_location, "w") as file:
        json.dump(essentials, file, indent=4)

def dec_file(master_passyword: str, auth_type: str, file_location: str) -> None:
    with open(file_location, "r") as file:
        complete = json.load(file)
    salty = base64.b64decode(complete["salty"])
    enc_v_key = complete["v_key_master"] if auth_type == "master" else complete["v_key_2fa"]
    if auth_type == "master":
        key = create_key(master_passyword, salty)
    elif auth_type == "2fa":
        saltier_str = complete.get("saltier")
        if saltier_str is None:
            return "2FA saltier not found in file.", None, None
        key = create_key(saltier_str)
    else:
        return "Invalid authentication type.", None, None
    fernet = Fernet(key)
    try:
        v_key = fernet.decrypt(enc_v_key.encode())
    except:
        return "Incorrect master password or failed 2FA authentication", None, None
    fernet_vault = Fernet(v_key)
    dec_data = fernet_vault.decrypt(complete["data"].encode())
    return v_key, complete, json.loads(dec_data.decode())

def re_enc_file(v_key: bytes, complete: dict, new_data: dict, file_location: str) -> None:
    fernet_vault = Fernet(v_key)
    enc_data = fernet_vault.encrypt(json.dumps(new_data).encode())
    complete_data = {
        "v_key_master": complete["v_key_master"],
        "v_key_2fa": complete["v_key_2fa"],
        "salty": complete["salty"],
        "saltier": complete["saltier"],
        "data": enc_data.decode()
    }
    with open(file_location, "w") as file:
        json.dump(complete_data, file, indent=4)

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
            key, re_enc_data, storage_data = dec_file(QUI, AUTH_TYPE, "manager.json")
            storage_data[0]["data"].append(data)
            re_enc_file(key, re_enc_data, storage_data, "manager.json")
        else:
            existing = [meta_data]
            with open("manager.json", "w") as file:
                json.dump(existing, file, indent=4)
            enc_file(QUI, "manager.json")
            rm_perms("manager.json")

    def load_info(self, description: str) -> bool:
        enter_helper()
        try:
            grant_perms("manager.json")
            key, re_enc_file, storage_data = dec_file(QUI, AUTH_TYPE, "manager.json")
            data = storage_data[0]["data"]
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
            exit_helper()
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
            key, re_enc_data, storage_data = dec_file(QUI, AUTH_TYPE, "manager.json")
            storage_data[0]["data"].append(data)
            re_enc_file(key, re_enc_data, storage_data, "manager.json")
        else:
            existing = [meta_data]
            with open("manager.json", "w") as file:
                json.dump(existing, file, indent=4)
            enc_file(QUI, "manager.json")
            rm_perms("manager.json")

    def load_info(self, description: str) -> bool:
        enter_helper()
        try:
            grant_perms("manager.json")
            key, re_enc_data, storage_data = dec_file(QUI, AUTH_TYPE, "manager.json")
            data = storage_data[0]["data"]
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
            exit_helper()
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
            key, re_enc_data, storage_data = dec_file(QUI, AUTH_TYPE, "manager.json")
            storage_data[0]["data"].append(data)
            re_enc_file(key, re_enc_data, storage_data, "manager.json")
        else:
            existing = [meta_data]
            with open("manager.json", "w") as file:
                json.dump(existing, file, indent=4)
            enc_file(QUI, "manager.json")
            rm_perms("manager.json")

    def load_info(self, description: str) -> bool:
        enter_helper()
        try:
            grant_perms("manager.json")
            key, re_enc_data, storage_data = dec_file(QUI, AUTH_TYPE, "manager.json")
            data = storage_data[0]["data"]
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
            exit_helper()
            return False

def main():
    return
    
if __name__ == "__main__":
    main()