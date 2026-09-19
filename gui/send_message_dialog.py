from PyQt6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QTextEdit,
    QPushButton,
    QLabel,
    QCheckBox,
    QRadioButton,
    QMessageBox,
    QLineEdit
)

from PyQt6.QtGui import QFont
from gui.private_key_selection_dialog import PrivateKeySelectionDialog
from gui.public_key_selection_dialog import PublicKeySelectionDialog
from pgp_send import PGPSend
from PyQt6.QtWidgets import QFileDialog
import os


class SendMessageDialog(QDialog):

    def __init__(self, private_ring, public_ring, rsa_tool):

        super().__init__()

        self.private_ring = private_ring
        self.public_ring = public_ring
        self.rsa_tool = rsa_tool

        # private key for signing
        self.selected_private_key = None

        # private key information
        self.selected_private_key_info = None
        self.password = None
        self.destination_path = "./extern/dec_messages"

        # public key for encryption
        self.selected_public_key = None

        self.setWindowTitle("Send Message")
        self.setGeometry(400, 100, 600, 650)
        self.init_ui()

    def init_ui(self):

        layout = QVBoxLayout()
        title = QLabel("Send Message")
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)

        title.setFont(title_font)

        layout.addWidget(title)
        layout.addWidget(QLabel("Message:"))

        self.message_area = QTextEdit()

        layout.addWidget(self.message_area)

        layout.addWidget(QLabel("File name:"))

        self.file_name_input = QLineEdit()

        layout.addWidget(self.file_name_input)

        self.choose_destination_button = QPushButton("Choose Destination")

        self.choose_destination_button.clicked.connect(self.choose_destination)

        layout.addWidget(self.choose_destination_button)

        # Signature

        self.signature_checkbox = QCheckBox("Signature")

        layout.addWidget(self.signature_checkbox)

        self.signature_checkbox.stateChanged.connect(self.select_private_key)

        # Compress

        self.compress_checkbox = QCheckBox("Compress")

        layout.addWidget(self.compress_checkbox)

        # Encrypt

        self.encrypt_checkbox = QCheckBox("Encrypt")

        layout.addWidget(self.encrypt_checkbox)

        self.encrypt_checkbox.stateChanged.connect(self.encrypt_changed)

        self.encrypt_checkbox.stateChanged.connect(self.select_public_key)

        # algorithms

        self.cast_radio = QRadioButton("CAST5")

        self.aes_radio = QRadioButton("AES128")

        self.cast_radio.setChecked(True)

        self.cast_radio.setEnabled(False)

        self.aes_radio.setEnabled(False)

        layout.addWidget(self.cast_radio)
        layout.addWidget(self.aes_radio)

        # Radix64

        self.radix_checkbox = QCheckBox("Radix-64")

        layout.addWidget(self.radix_checkbox)

        # Send

        self.send_button = QPushButton("Send")

        self.send_button.clicked.connect(self.send_message)

        layout.addWidget(self.send_button)

        self.setStyleSheet("""

            QDialog {
                background-color: #ADD8E6;
            }

            QLabel {
                color: #003366;
                font-size: 15px;
            }

            QTextEdit {

                background-color: white;
                color: #003366;
                border: 2px solid #003366;
                border-radius: 6px;
                padding: 5px;
                font-size: 14px;

            }

            QLineEdit {

                background-color: white;
                color: #003366;
                border: 2px solid #003366;
                border-radius: 6px;
                padding: 5px;
                font-size: 14px;

            }

            QCheckBox {
                color: #003366;
                font-size: 14px;

            }

            QRadioButton {

                color: #003366;
                font-size: 14px;
            }

            QPushButton {

                background-color: white;
                color: #003366;
                border: 2px solid #003366;
                border-radius: 8px;
                padding: 10px;
                font-size: 16px;

            }

            QPushButton:hover {

                background-color: #DFF6FF;

            }

            QPushButton:pressed {

                background-color: #87CEEB;

            }
            
        """)

        self.setLayout(layout)

    def encrypt_changed(self):

        enabled = self.encrypt_checkbox.isChecked()

        self.cast_radio.setEnabled(enabled)
        self.aes_radio.setEnabled(enabled)

    def choose_destination(self):

        path = QFileDialog.getExistingDirectory(
            self,
            "Choose destination folder",
            "./extern/dec_messages"
        )

        if path:
            self.destination_path = path
            print("Selected destination:", self.destination_path)

    def select_private_key(self):

        if self.signature_checkbox.isChecked():

            dialog = PrivateKeySelectionDialog(self.private_ring, self.rsa_tool)

            if dialog.exec():
                self.selected_private_key = (dialog.decrypted_private_key)

                self.selected_private_key_info = (dialog.selected_key)

                self.password = dialog.password

    def select_public_key(self):

        if self.encrypt_checkbox.isChecked():

            dialog = PublicKeySelectionDialog(self.public_ring)

            if dialog.exec():
                self.selected_public_key = (dialog.selected_key)

    def send_message(self):

        message = self.message_area.toPlainText()

        if not message:
            QMessageBox.warning(self, "Error", "Message is empty!")
            return

        print("\n========== SEND MESSAGE ==========")

        print("private key: ", self.selected_private_key)
        print("selected private key info: ", self.selected_private_key_info)
        print("passwword", self.password)
        print("selected public key: ", self.selected_public_key)

        print("\nMessage:")

        print(message)

        print("\nFile name:")

        print(self.file_name_input.text())

        print("\nSignature:")

        if self.signature_checkbox.isChecked():

            print("Enabled")

            if self.selected_private_key_info:

                print("Name:", self.selected_private_key_info["Name"])

                print("Email:", self.selected_private_key_info["Email"])

                print("Key ID:", self.selected_private_key_info["KeyID"])

                print("Algorithm:", self.selected_private_key_info["Algorithm"])

                print("Key size:", self.selected_private_key_info["KeySize"])

            else:
                print("No private key selected")

        else:

            print("Disabled")

        print("\nEncryption:")

        if self.encrypt_checkbox.isChecked():

            print("Enabled")

            if self.selected_public_key:

                print("Name:", self.selected_public_key["Name"])

                print("Email:", self.selected_public_key["Email"])

                print("Key ID:", self.selected_public_key["KeyID"])

                print("Algorithm:", self.selected_public_key["Algorithm"])

                print("Key size:", self.selected_public_key["KeySize"])

            else:

                print("No public key selected")

            if self.cast_radio.isChecked():

                print("Symmetric algorithm: CAST5")

            elif self.aes_radio.isChecked():

                print("Symmetric algorithm: AES128")

        else:

            print("Disabled")

        print("\nCompression:")

        if self.compress_checkbox.isChecked():
            print("Enabled")
        else:
            print("Disabled")

        print("\nRadix-64:")

        if self.radix_checkbox.isChecked():

            print("Enabled")

        else:
            print("Disabled")

        print("\n=================================\n")

        QMessageBox.information(self, "Success", "Options printed in console!")

        # ----------------------------------------------------------------

        algorithm = None

        if self.encrypt_checkbox.isChecked():

            if self.cast_radio.isChecked():
                algorithm = "CAST5"
            else:
                algorithm = "AES128"

        pgp = PGPSend(
            message=message,
            filename=self.file_name_input.text(),

            is_signature_checked=self.signature_checkbox.isChecked(),

            name_sender=self.selected_private_key_info["Name"] if self.selected_private_key_info else None,
            email_sender=self.selected_private_key_info["Email"] if self.selected_private_key_info else None,
            keyid_sender=self.selected_private_key_info["KeyID"] if self.selected_private_key_info else None,
            password=self.password if self.password else None,

            is_compressed_checked=self.compress_checkbox.isChecked(),
            is_encrypt_checked=self.encrypt_checkbox.isChecked(),

            name_receiver=self.selected_public_key["Name"] if self.selected_public_key else None,
            email_receiver=self.selected_public_key["Email"] if self.selected_public_key else None,
            keyid_receiver=self.selected_public_key["KeyID"] if self.selected_public_key else None,

            algorithm=algorithm,

            is_radix64_checked=self.radix_checkbox.isChecked(),
            private_ring=self.private_ring,
            public_ring=self.public_ring,
            rsa_tool=self.rsa_tool,
            destination_path=self.destination_path
        )

        pgp.send()
        self.close()
