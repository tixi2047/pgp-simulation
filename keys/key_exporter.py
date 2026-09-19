import os
from cryptography.hazmat.primitives import serialization

class KeyExporter:

    def extract_value(self, data, field):

        for line in data.splitlines():
            line = line.strip()
            if line.startswith(field + ":"):

                return line.split(":",1)[1].strip()

        return ""

    def export_private_key_pair(self, key, filename):

        folder = "./extern/private_keys"

        os.makedirs(folder,exist_ok=True)

        filepath = os.path.join(folder,filename)

        public_pem = key["PublicKey"].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        iv = key["IV"].hex()
        encrypted_private = key["EncryptedPrivateKey"].hex()

        with open(filepath, "w") as file:
            file.write(
                "-----BEGIN PGP PRIVATE KEY PAIR-----\n\n"
                f"Timestamp: {key['Timestamp']}\n"
                f"KeyID: {key['KeyID']}\n"
                f"Name: {key['Name']}\n"
                f"Email: {key['Email']}\n"
                f"Algorithm: {key['Algorithm']}\n"
                f"KeySize: {key['KeySize']}\n"
                f"IV: {iv}\n\n"
                f"{public_pem.strip()}\n\n"
                "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
                f"{encrypted_private}\n"
                "-----END ENCRYPTED PRIVATE KEY-----\n\n"
                "-----END PGP PRIVATE KEY PAIR-----"
            )

        return filepath

    def import_private_key_pair(self, filename):

        with open(filename, "r") as file:
            data = file.read()

        timestamp = self.extract_value(data,"Timestamp")

        key_id = self.extract_value(data,"KeyID")

        name = self.extract_value(data,"Name")

        email = self.extract_value(data,"Email")

        algorithm = self.extract_value(data,"Algorithm")

        key_size = int(self.extract_value(data,"KeySize"))

        iv = bytes.fromhex(self.extract_value(data,"IV"))

        # PUBLIC KEY

        start = data.find("-----BEGIN PUBLIC KEY-----")

        end = data.find("-----END PUBLIC KEY-----") + len("-----END PUBLIC KEY-----")

        public_pem = data[start:end].encode()

        try:
            public_key = serialization.load_pem_public_key(public_pem)
        except Exception as e:
            print("GRESKA:", e)
            print(repr(public_pem.decode()))
            raise

        # ENCRYPTED PRIVATE KEY

        start = data.find("-----BEGIN ENCRYPTED PRIVATE KEY-----")

        end = data.find("-----END ENCRYPTED PRIVATE KEY-----")

        encrypted_private = data[start + len("-----BEGIN ENCRYPTED PRIVATE KEY-----"):end].strip()

        encrypted_private = bytes.fromhex(encrypted_private)

        temp = {
            "Timestamp": timestamp,
            "KeyID": key_id,
            "Name": name,
            "Email": email,
            "Algorithm": algorithm,
            "KeySize": key_size,
            "IV": iv,
            "PublicKey": public_key,
            "EncryptedPrivateKey": encrypted_private
        }

        return temp
