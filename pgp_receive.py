from datetime import datetime
import base64
from Crypto.Cipher import AES, CAST
from Crypto.Util.Padding import unpad
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import zlib
from cryptography.exceptions import InvalidSignature

class PGPReceive:

    def __init__(
            self,
            private_ring,
            public_ring,
            rsa_tool,
            message_content,
            password
    ):

        self.private_ring = private_ring
        self.public_ring = public_ring
        self.rsa_tool = rsa_tool
        self.password=password

        self.message_content = message_content

        self.received_message = None
        self.is_signature_checked = 0
        self.is_compressed_checked = 0
        self.is_encrypt_checked = 0
        self.algorithm = None
        self.is_radix64_checked = 0

        self.after_decoded_radix_message= None

        self.encrypted_compressed_message = None
        self.iv = None
        self.encrypted_session_key = None
        self.receiver_public_key_id = None

        self.decrypted_session_key = None
        self.decrypted_compressed_message = None

        self.decompressed_message = None

        self.extended_message = None

        self.signature = None
        self.leading_2_octets = None
        self.sender_key_id = None
        self.signature_timestamp = None

        self.original_message = None
        self.original_filename = None
        self.message_timestamp = None

        self.is_valid_signature=None
        self.author_name=None
        self.author_email=None

    def parse_message(self):

        metadata_index = self.message_content.rfind("Signature:")

        if metadata_index == -1:
            raise Exception("Metadata not found")

        # everything before Signature is the message
        self.received_message = (
            self.message_content[:metadata_index]
        )

        if self.received_message.endswith("====="):
            self.received_message = (
                self.received_message[:-5]
            )

        metadata = (self.message_content[metadata_index:])

        self.is_signature_checked = 0
        self.is_compressed_checked = 0
        self.is_encrypt_checked = 0
        self.algorithm = None
        self.is_radix64_checked = 0

        parts = metadata.split("=====")

        for part in parts:

            if part.startswith("Signature:"):

                self.is_signature_checked = int(part.split(":")[1])

            elif part.startswith("Compression:"):

                self.is_compressed_checked = int(part.split(":")[1])

            elif part.startswith("Encryption:"):

                self.is_encrypt_checked = int(part.split(":")[1])

            elif part.startswith("Algorithm:"):

                self.algorithm = (part.split(":")[1])

            elif part.startswith("Radix64:"):

                self.is_radix64_checked = int(part.split(":")[1])

        return self.received_message

    def radix64_decode(self):

        decoded = base64.b64decode(self.received_message)

        return decoded

    def separate_encrypted_message(self):

        # if the message after radix64 decode is in bytes
        if isinstance(self.after_decoded_radix_message, bytes):

            message = (self.after_decoded_radix_message.decode())

        else:
            message = self.after_decoded_radix_message

        parts = message.split("=====")

        if len(parts) != 4:
            raise Exception("Invalid encrypted message format")

        self.encrypted_compressed_message = bytes.fromhex(parts[0])

        self.iv = bytes.fromhex(parts[1])

        self.encrypted_session_key = bytes.fromhex(parts[2])

        self.receiver_public_key_id = parts[3]

        print("\nEncrypted message separated:")

        print("Encrypted compressed message:",self.encrypted_compressed_message)

        print("IV:",self.iv.hex())

        print("Encrypted session key:",self.encrypted_session_key.hex())

        print("Receiver key ID:",self.receiver_public_key_id)

    def decrypt(self):

        # finding the corresponding private key

        receiver = self.private_ring.get_key(
            self.receiver_public_key_id
        )

        if receiver is None:
            raise Exception("Receiver private key not found!")

        # decryption of the private key

        private_key = self.rsa_tool.decrypt_private_key(
            receiver["EncryptedPrivateKey"],
            receiver["IV"],
            self.password,
            receiver["PublicKey"]
        )

        if private_key is None:
            raise Exception("Wrong password!")

        # RSA decryption of the session key

        try:

            self.decrypted_session_key = private_key.decrypt(
                self.encrypted_session_key,
                padding.OAEP(
                    mgf=padding.MGF1(
                        algorithm=hashes.SHA256()
                    ),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

        except Exception:
            raise Exception("Cannot decrypt session key")

        # Symmetric message decryption

        if self.algorithm == "AES128":

            cipher = AES.new(
                self.decrypted_session_key,
                AES.MODE_CBC,
                iv=self.iv
            )

        elif self.algorithm == "CAST5":

            cipher = CAST.new(
                self.decrypted_session_key,
                CAST.MODE_CBC,
                iv=self.iv
            )

        else:

            raise Exception("Unsupported algorithm")

        try:

            self.decrypted_compressed_message = unpad(
                cipher.decrypt(
                    self.encrypted_compressed_message
                ),
                cipher.block_size
            )

        except Exception:
            raise Exception("Message decryption failed")

        print("\nSession key:")
        print(self.decrypted_session_key.hex())

        print("\nAfter decryption:")
        print(self.decrypted_compressed_message)

        return self.decrypted_compressed_message

    def decompress(self):

        self.decompressed_message = zlib.decompress(
            self.decrypted_compressed_message
        )

        print("\nAfter decompression:")
        print(self.decompressed_message)

        return self.decompressed_message

    def separate_signed_message(self):

        signed_message = self.decompressed_message.decode()

        parts = signed_message.split("=====")

        self.extended_message = ("=====".join(parts[:3]))

        self.signature = bytes.fromhex(parts[3])

        self.leading_2_octets = parts[4]

        self.sender_key_id = parts[5]

        self.signature_timestamp = parts[6]

        # splitting the extended message

        extended_parts = self.extended_message.split("=====")

        self.original_message = extended_parts[0]

        self.original_filename = extended_parts[1]

        self.message_timestamp = extended_parts[2]

        print("\nAfter separating signed message:")

        print(
            "Original message:",
            self.original_message
        )

        print(
            "Filename:",
            self.original_filename
        )

        print(
            "Message timestamp:",
            self.message_timestamp
        )

        print(
            "Signature:",
            self.signature.hex()
        )

        print(
            "Leading 2 octets:",
            self.leading_2_octets
        )

        print(
            "Sender Key ID:",
            self.sender_key_id
        )

        print(
            "Signature timestamp:",
            self.signature_timestamp
        )

    def unsign(self):

        """

        # Intentionally corrupting the signature
        self.signature = (
            self.signature[:-1]
            + bytes([self.signature[-1] ^ 0xFF])
        )
        """

        # finding the sender's public key

        sender = self.public_ring.get_key(self.sender_key_id)

        if sender is None:
            raise Exception("Sender public key not found!")

        sender_public_key = sender["PublicKey"]

        try:

            sender_public_key.verify(
                self.signature,
                self.extended_message.encode(),
                padding.PKCS1v15(),
                hashes.SHA1()
            )

            self.is_valid_signature = True
            self.author_name=sender["Name"]
            self.author_email=sender["Email"]
            print("\nSignature VALID.")


        except InvalidSignature:

            print("\nSignature INVALID.")
            self.is_valid_signature = False
            self.author_name=sender["Name"]
            self.author_email=sender["Email"]


    def receive(self):

        try:

            print("\n========== PGP RECEIVE ==========")

            self.parse_message()

            print("Original encrypted part:")
            print(self.received_message)

            print("\nMetadata:")

            print(
                "Signature:",
                self.is_signature_checked
            )

            print(
                "Compression:",
                self.is_compressed_checked
            )

            print(
                "Encryption:",
                self.is_encrypt_checked
            )

            print(
                "Algorithm:",
                self.algorithm
            )

            print(
                "Radix64:",
                self.is_radix64_checked
            )

            print("\n=================================")

            # Inverse Radix64 decoding

            if self.is_radix64_checked:
                self.after_decoded_radix_message = self.radix64_decode() # data is in bytes

                print("\nAfter Radix64 decode:")

                print(self.after_decoded_radix_message)
            else:
                self.after_decoded_radix_message= self.received_message.encode()


            if self.is_encrypt_checked:

                self.separate_encrypted_message()
                self.decrypt()
            else:

                self.decrypted_compressed_message = (self.after_decoded_radix_message)

            if self.is_compressed_checked:

                self.decompress()

            else:

                self.decompressed_message = (self.decrypted_compressed_message)

            print("\nMessage after decompression:")
            print(self.decompressed_message)

            if self.is_signature_checked:

                self.separate_signed_message()
                self.unsign()

            else:

                text = self.decompressed_message.decode()

                parts = text.split("=====")

                self.original_message = parts[0]

                self.original_filename = parts[1]

                self.message_timestamp = parts[2]

            final_result = {

                "message": self.original_message,

                "filename": self.original_filename,

                "timestamp": self.message_timestamp,

                "signature_valid": self.is_valid_signature,

                "author_name": self.author_name,

                "author_email": self.author_email
            }

            return final_result

        except Exception as e:

            return {"error": str(e)}