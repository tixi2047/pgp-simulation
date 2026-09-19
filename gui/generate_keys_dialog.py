from PyQt6.QtWidgets import (
    QDialog,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QRadioButton,
    QMessageBox
)
from PyQt6.QtGui import QFont
from keys.public_ring import PublicKeyRing
from keys.private_ring import PrivateKeyRing
import re

class GenerateKeysDialog(QDialog):

    def __init__(self, rsa_tool, public_ring: PublicKeyRing, private_ring: PrivateKeyRing):

        super().__init__()

        self.rsa_tool = rsa_tool
        self.public_ring = public_ring
        self.private_ring = private_ring

        self.setWindowTitle("Generate RSA Keys")
        self.setGeometry(600, 200, 400, 450)

        self.init_ui()

    def init_ui(self):

        layout = QVBoxLayout()

        title = QLabel("Generate RSA Keys")
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title.setFont(title_font)

        layout.addWidget(title)

        layout.addWidget(QLabel("Name:"))
        self.name_input = QLineEdit()
        layout.addWidget(self.name_input)

        layout.addWidget(QLabel("Email:"))
        self.email_input = QLineEdit()
        layout.addWidget(self.email_input)

        layout.addWidget(QLabel("Key size:"))
        self.radio_1024 = QRadioButton("1024 bits")
        self.radio_2048 = QRadioButton("2048 bits")

        self.radio_2048.setChecked(True)
        layout.addWidget(self.radio_1024)
        layout.addWidget(self.radio_2048)


        layout.addWidget(QLabel("Password:"))
        self.password_input = QLineEdit()

        self.password_input.setEchoMode(
            QLineEdit.EchoMode.Password
        )
        layout.addWidget(self.password_input)

        self.generate_button = QPushButton("Generate")
        self.generate_button.clicked.connect(self.generate_keys)
        layout.addWidget(self.generate_button)

        self.setStyleSheet("""

            QDialog {
                background-color: #ADD8E6;
            }

            QLabel {

                color: #003366;
                font-size: 15px;

            }

            QLineEdit {

                background-color: white;
                border: 2px solid #003366;
                border-radius: 6px;
                padding: 5px;

            }

            QRadioButton {

                color: #003366;
                font-size: 14px;

            }

            QPushButton {

                background-color: #90EE90;
                color: #003366;
                border: 2px solid #006400;
                border-radius: 8px;
                font-size: 16px;
                padding: 10px;

            }

            QPushButton:hover {

                background-color: #98FB98;

            }

            QPushButton:pressed {

                background-color: #66CDAA;

            }

        """)

        self.setLayout(layout)

    def is_valid_email(self, email):

        pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
        return re.match(pattern, email) is not None

    def generate_keys(self):

        name = self.name_input.text()
        email = self.email_input.text()
        password = self.password_input.text()

        if self.radio_1024.isChecked():
            key_size = 1024
        else:
            key_size = 2048

        if not name or not email or not password:

            QMessageBox.warning(self, "Error", "All fields are required!")
            return

        if not self.is_valid_email(email):

            QMessageBox.warning(self, "Error", "Invalid email format!")
            return

        public_key, private_key = self.rsa_tool.generate_key_pair(name, email, key_size, password)

        self.public_ring.add_key(public_key)
        print(self.public_ring.get_all_keys())

        self.private_ring.add_key(private_key)
        print(self.private_ring.get_all_keys())

        QMessageBox.information(self, "Success", "RSA key pair successfully generated!")

        self.close()
        