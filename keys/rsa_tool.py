import hashlib
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from Crypto.Cipher import CAST
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


class RSATool:

    def generate_key_pair(self, name, email, key_size, password):

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size)

        public_key = private_key.public_key()

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        key_hash = hashlib.sha1(public_pem).digest()

        key_id = key_hash[-8:].hex().upper()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        password_hash = hashlib.sha1(password.encode()).digest()

        # CAST5 16-byte key
        cast_key = password_hash[:16]

        iv = get_random_bytes(CAST.block_size)

        cipher = CAST.new(cast_key, CAST.MODE_CBC, iv)# creating the CAST CBC cipher object

        padded_private_key = pad(private_pem, CAST.block_size)

        # encrypting the private key

        encrypted_private_key = cipher.encrypt(
            padded_private_key
        )

        timestamp = datetime.now().strftime("%d.%m.%Y %H:%M:%S")

        public_key_info = {

            "Timestamp": timestamp,
            "KeyID": key_id,
            "Name": name,
            "Email": email,
            "Algorithm": "RSA",
            "KeySize": key_size,
            "PublicKey": public_key
        }

        private_key_info = {

            "Timestamp": timestamp,
            "KeyID": key_id,
            "Name": name,
            "Email": email,
            "Algorithm": "RSA",
            "KeySize": key_size,
            "IV": iv,
            "PublicKey": public_key,
            "EncryptedPrivateKey": encrypted_private_key,
        }

        return public_key_info, private_key_info

    def decrypt_private_key(self,encrypted_private_key,iv,password,original_public_key):

        password_hash = hashlib.sha1(
            password.encode()
        ).digest()

        cast_key = password_hash[:16]

        cipher = CAST.new(
            cast_key,
            CAST.MODE_CBC,
            iv
        )

        try:

            decrypted = cipher.decrypt(encrypted_private_key)

            private_pem = unpad(
                decrypted,
                CAST.block_size
            )

            private_key = serialization.load_pem_private_key(private_pem,password=None)

            derived_public_key = private_key.public_key()

            original_public_numbers = (
                original_public_key.public_numbers()
            )

            derived_public_numbers = (
                derived_public_key.public_numbers()
            )

            if original_public_numbers != derived_public_numbers:
                return None

            return private_key

        except Exception:

            return None
