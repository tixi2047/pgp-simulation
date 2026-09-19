from PyQt6.QtWidgets import (
    QApplication,
    QWidget,
    QLabel,
    QPushButton,
    QVBoxLayout
)

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

from gui.generate_keys_dialog import GenerateKeysDialog
from gui.private_ring_dialog import PrivateRingDialog
from gui.public_ring_dialog import PublicRingDialog
from gui.send_message_dialog import SendMessageDialog

from keys.private_ring import PrivateKeyRing
from keys.public_ring import PublicKeyRing
from keys.rsa_tool import RSATool
from gui.receive_message_dialog import ReceiveMessageDialog


class MainWindow(QWidget):

    def __init__(self):

        super().__init__()

        self.setWindowTitle("PGP Simulation")
        self.setGeometry(500, 100, 500, 700)

        # creating necessary objects

        self.rsa_tool = RSATool()
        self.public_ring = PublicKeyRing()
        self.private_ring = PrivateKeyRing()

        self.init_ui()

    def init_ui(self):

        layout = QVBoxLayout()

        title = QLabel("PGP Simulation")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(24)
        title_font.setBold(True)
        title.setFont(title_font)

        layout.addWidget(title)

        self.generate_button = QPushButton("Generate RSA Keys")
        self.private_ring_button = QPushButton("Private Key Ring")
        self.public_ring_button = QPushButton("Public Key Ring")
        self.send_button = QPushButton("Send Message")
        self.receive_button = QPushButton("Receive Message")

        buttons = [
            self.generate_button,
            self.private_ring_button,
            self.public_ring_button,
            self.send_button,
            self.receive_button
        ]

        for button in buttons:
            button.setMinimumHeight(45)
            layout.addWidget(button)

        self.generate_button.clicked.connect(self.open_generate_dialog)
        self.private_ring_button.clicked.connect(self.open_private_ring)
        self.public_ring_button.clicked.connect(self.open_public_ring)
        self.send_button.clicked.connect(self.open_send_message)
        self.receive_button.clicked.connect(self.open_receive_message)

        self.setStyleSheet("""

            QWidget {
                background-color: #ADD8E6;
            }

            QLabel {
                color: #003366;
                margin-bottom: 30px;

            }
            QPushButton {

                background-color: white;
                color: #003366;
                border: 2px solid #003366;
                border-radius: 8px;
                font-size: 16px;
                padding: 8px;

            }
            QPushButton:hover {

                background-color: #DFF6FF;
            }

            QPushButton:pressed {
                background-color: #87CEEB;
            }

        """)

        self.setLayout(layout)

    def open_generate_dialog(self):

        dialog = GenerateKeysDialog(
            self.rsa_tool,
            self.public_ring,
            self.private_ring
        )
        dialog.exec()

    def open_private_ring(self):
        dialog = PrivateRingDialog(
            self.private_ring,
            self.public_ring,
            self.rsa_tool
        )
        dialog.exec()

    def open_public_ring(self):
        dialog = PublicRingDialog(
            self.public_ring,
            self.private_ring,
            self.rsa_tool
        )
        dialog.exec()


    def open_send_message(self):

        dialog = SendMessageDialog(
            self.private_ring,
            self.public_ring,
            self.rsa_tool
        )

        dialog.exec()

    def open_receive_message(self):
        dialog = ReceiveMessageDialog(
            self.private_ring,
            self.public_ring,
            self.rsa_tool
        )
        dialog.exec()

if __name__ == "__main__":

    app = QApplication([])
    window = MainWindow()
    window.show()

    app.exec()