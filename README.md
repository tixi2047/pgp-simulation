# 🔑 PGP Simulation

The objective of this project is to gain a deeper understanding of the PGP (Pretty Good Privacy) scheme for electronic mail protection, its core capabilities, and its practical usage. To achieve this, the application is designed and implemented in **Python** with a user-friendly graphical interface (GUI), delivering a complete cryptographic toolkit.

---

## 🚀 Key Features

* **RSA Key Management**: Generate new key pairs and securely delete existing ones.
* **Import & Export**: Support for importing and exporting public keys or complete key pairs in `.pem` format.
* **Key Rings**: Dedicated views for both public and private key rings displaying comprehensive metadata.
* **Secure Transmission (Send)**: Compose and encrypt/sign messages with customizable cryptographic layers.
* **Secure Reception (Receive)**: Parse incoming message files, automatically recognize packets, and perform decryption and verification.

---

## 🔐 Key Generation & Security

* **User Input**: During key generation, users specify their **Name**, **Email**, and **Key Size** (1024 or 2048 bits).
* **Password Protection**: Private keys are encrypted and protected by a user-defined password upon creation.
* **Access Control**: Every subsequent access to a private key (for signing, exporting, or decrypting) strictly requires password validation.
* **Visibility**: All generated and imported keys are clearly visible and organized within the respective key ring interfaces.

---

## ✉️ Message Sending Workflow

When sending a message, users can configure multiple security and processing layers:
* **Confidentiality (Encryption)**: Choose a recipient's public key and a symmetric cipher (**AES-128** or **CAST5**).
* **Authenticity (Signing)**: Choose a private key to sign the message using **SHA-1** for hash generation.
* **Data Processing**: Options for compression and Radix-64 conversion.
* **Output Generation**: Produces a structured export file at a user-selected destination containing all the necessary packets for the recipient.

---

## 📥 Message Receiving Workflow

Upon receiving a message, the application handles end-to-end processing:
* **File Selection**: Load the target message file from local storage.
* **Automatic Parsing**: Recognizes the embedded package structure.
* **Decryption & Verification**: Performs automated decryption and signature verification.
* **Status Feedback**: Displays signature verification success status and the author's details if a signature is present.
* **Storage & Error Handling**: Allows saving the recovered original message to a chosen destination, with clear warning dialogs for any decryption or verification failures.

---

## 💻 How to Run

Open your terminal in the root directory of the project and run the following commands:
```bash
pip install -r installed_libs.txt

python main.py
