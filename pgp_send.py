import hashlib
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils
import zlib
from Crypto.Cipher import AES, CAST
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from cryptography.hazmat.primitives.asymmetric import padding
import base64
import os
import random

class PGPSend:

    def __init__(
            self,
            message,
            filename,
            is_signature_checked,
            name_sender,
            email_sender,
            keyid_sender,
            password,
            is_compressed_checked,
            is_encrypt_checked,
            name_receiver,
            email_receiver,
            keyid_receiver,
            algorithm,
            is_radix64_checked,
            destination_path,
            private_ring,
            public_ring,
            rsa_tool
    ):

        self.message = message
        self.filename = filename

        self.is_signature_checked = is_signature_checked
        self.name_sender = name_sender
        self.email_sender = email_sender
        self.keyid_sender = keyid_sender
        self.password = password

        self.is_compressed_checked = is_compressed_checked

        self.is_encrypt_checked = is_encrypt_checked
        self.name_receiver = name_receiver
        self.email_receiver = email_receiver
        self.keyid_receiver = keyid_receiver
        self.algorithm = algorithm

        self.is_radix64_checked = is_radix64_checked

        self.destination_path = destination_path

        self.private_ring = private_ring
        self.public_ring = public_ring
        self.rsa_tool = rsa_tool

        self.timestamp1 = None
        self.extended_message = None

        self.signed_message=None
        self.compressed_message=None
        self.encrypted_message=None
        self.radix64_message=None


    def create_extended_message(self):

        self.timestamp1 = datetime.now().strftime("%d.%m.%Y %H:%M:%S")

        self.extended_message = (
                self.message
                + "====="
                + self.filename
                + "====="
                + self.timestamp1
        )

        return self.extended_message

    def sign(self):

        # looking for a private key

        key = self.private_ring.get_key_by_email(self.email_sender)

        if key is None:
            raise Exception("Private key not found!")

        print("private ring", key)

        # Decryption of the private key

        private_key = self.rsa_tool.decrypt_private_key(
            key["EncryptedPrivateKey"],
            key["IV"],
            self.password,
            key["PublicKey"]
        )

        if private_key is None:
            raise Exception("Wrong password!")
        """
        I don't need this because RSA already has this built-in
        SHA1 hash
        
        hashed_extended_message = hashlib.sha1(self.extended_message.encode()).digest()
        """

        # RSA signature

        encrypted_hashed_extended_message = private_key.sign(
            self.extended_message.encode(),
            padding.PKCS1v15(),
            hashes.SHA1()
        )

        timestamp2 = datetime.now().strftime("%d.%m.%Y %H:%M:%S")

        leading_2_octets = (encrypted_hashed_extended_message[:2].hex().upper())

        sender_key_id = key["KeyID"]

        self.signed_message = (
                self.extended_message
                + "====="
                + encrypted_hashed_extended_message.hex()
                + "====="
                + leading_2_octets
                + "====="
                + sender_key_id
                + "====="
                + timestamp2
        )

        return self.signed_message

    def compress(self, message):

        compressed_message = zlib.compress(message.encode())
        self.compressed_message = compressed_message

        return self.compressed_message

    def generate_session_key(self):

        return get_random_bytes(16)

    def symmetric_encrypt(self, data, session_key):

        if self.algorithm == "AES128":

            cipher = AES.new(session_key,AES.MODE_CBC)

        elif self.algorithm == "CAST5":

            cipher = CAST.new(session_key,CAST.MODE_CBC)

        else:

            raise Exception("Unsupported algorithm")

        encrypted = cipher.encrypt(
            pad(
                data,
                cipher.block_size
            )
        )

        return cipher.iv,encrypted

    def encrypt_session_key(self,session_key,public_key):

        encrypted_session_key = public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(
                    algorithm=hashes.SHA256()
                ),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return encrypted_session_key

    def radix64_encode(self, data):

        encoded = base64.b64encode(data)

        return encoded.decode()

    def encrypt(self):

        # finding the recipient

        receiver = self.public_ring.get_key_by_email(self.email_receiver)

        if receiver is None:
            raise Exception("Receiver public key not found!")

        receiver_public_key_id = receiver["KeyID"]
        receiver_public_key = receiver["PublicKey"]

        # session key generation

        session_key = self.generate_session_key()

        # symmetric message encryption

        iv,encrypted_compressed_message = (
            self.symmetric_encrypt(
                self.compressed_message,
                session_key
            )
        )

        # RSA encryption of the session key

        encrypted_session_key = (
            self.encrypt_session_key(
                session_key,
                receiver_public_key
            )
        )

        encrypted_message = (
                encrypted_compressed_message.hex()
                + "====="
                + iv.hex()
                + "====="
                + encrypted_session_key.hex()
                + "====="
                + receiver_public_key_id
        )

        self.encrypted_message =encrypted_message

        return self.encrypted_message

    def create_file(self, final_message):

        folder = self.destination_path

        os.makedirs(folder,exist_ok=True)

        filename = self.filename

        if not filename.endswith(".txt"):
            filename += ".txt"

        filepath = os.path.join(folder,filename)

        # if a true random ID exists

        while os.path.exists(filepath):
            random_id = random.randint(0,1000)

            name, extension = os.path.splitext(filename)

            new_filename = (
                    name
                    + "_"
                    + str(random_id)
                    + extension
            )

            filepath = os.path.join(folder,new_filename)

        with open(filepath,"w",encoding="utf-8") as file:

            file.write(final_message)

        return filepath

    def create_file_content(self):

        content = (

                self.radix64_message

                + "====="

                + "Signature:"
                + str(int(self.is_signature_checked))

                + "====="

                + "Compression:"
                + str(int(self.is_compressed_checked))

                + "====="

                + "Encryption:"
                + str(int(self.is_encrypt_checked))

                + "====="

                + "Algorithm:"
                + str(self.algorithm)

                + "====="

                + "Radix64:"
                + str(int(self.is_radix64_checked))

        )

        return content

    def send(self):

        print("\n========== PGP ==========")

        print("Message:")
        print(self.message)

        print("\nFilename:")
        print(self.filename)

        print("\nSignature:", self.is_signature_checked)

        if self.is_signature_checked:
            print("Sender:")
            print("Name:", self.name_sender)
            print("Email:", self.email_sender)
            print("KeyID:", self.keyid_sender)
            print("Password:", self.password)

        print("\nCompression:", self.is_compressed_checked)

        print("\nEncryption:", self.is_encrypt_checked)

        if self.is_encrypt_checked:
            print("Receiver:")
            print("Name:", self.name_receiver)
            print("Email:", self.email_receiver)
            print("KeyID:", self.keyid_receiver)
            print("Algorithm:", self.algorithm)

        print("\nRadix64:", self.is_radix64_checked)

        print("\n=========================")

        extended_message = self.create_extended_message()

        print("Extended message:")
        print(extended_message)

        # sign

        if self.is_signature_checked:
            signed_message = self.sign()

            print("\nSigned message:")
            print(signed_message)

        else:
            self.signed_message=self.extended_message


        if self.is_compressed_checked:

            compressed_message = self.compress(
                self.signed_message
            )

            print("\nCompressed message:")
            print(compressed_message)

        else:
            self.compressed_message = self.signed_message.encode()

        # encrypt

        if self.is_encrypt_checked:

            encrypted_message = self.encrypt()

            print("\nEncrypted message:")
            print(encrypted_message)

        else:
            self.encrypted_message = self.compressed_message


        if self.is_radix64_checked:

            encrypted_message= self.encrypted_message

            if isinstance(encrypted_message, str):
                encrypted_message = encrypted_message.encode()

            self.radix64_message = self.radix64_encode(
                encrypted_message
            )
            print("\nRadix-64 message:")
            print(self.radix64_message)
        else:
            self.radix64_message = self.encrypted_message

        # save to file

        file_content = self.create_file_content()
        saved_file = self.create_file(file_content)
        print("Saved:",saved_file)


