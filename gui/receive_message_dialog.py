from PyQt6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QPushButton,
    QLabel,
    QFileDialog, QMessageBox
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from pgp_receive import PGPReceive
from gui.password_dialog import PasswordDialog
from PyQt6.QtWidgets import QDialog
import os

class ReceiveMessageDialog(QDialog):

    def __init__(self, private_ring, public_ring, rsa_tool):

        super().__init__()

        self.private_ring = private_ring
        self.public_ring = public_ring
        self.rsa_tool = rsa_tool

        self.selected_file = None

        self.message_content = None
        self.password=None

        self.result={}

        # default destination
        self.destination_path = ("./extern/enc_messages")

        self.setWindowTitle("Receive Message")
        self.setGeometry(500, 200, 500, 400)

        self.init_ui()

    def init_ui(self):

        layout = QVBoxLayout()

        title = QLabel("Receive Message")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)

        # choose message button

        self.choose_message_button = QPushButton("Choose Message To Receive")
        self.choose_message_button.clicked.connect(self.choose_message)

        layout.addWidget(self.choose_message_button)

        # receive button

        self.receive_button = QPushButton("Receive")
        self.receive_button.clicked.connect(self.receive_message)
        layout.addWidget(self.receive_button)

        # save button

        self.save_button = QPushButton("Save")
        self.save_button.clicked.connect(self.save_message)

        layout.addWidget(self.save_button)

        # info label goes to the bottom

        self.info_label = QLabel("No message selected")
        self.info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.info_label.setWordWrap(True)

        layout.addWidget(self.info_label)

        self.setLayout(layout)

        self.setStyleSheet("""

            QDialog {
                background-color: #ADD8E6;
            }

            QLabel {

                color: #003366;
                font-size: 15px;

            }

            QPushButton {

                background-color: white;
                color: #003366;
                border: 2px solid #003366;
                border-radius: 8px;
                font-size: 16px;
                padding: 10px;

            }

            QPushButton:hover {

                background-color: #DFF6FF;

            }

            QPushButton:pressed {

                background-color: #87CEEB;
            }
        """)

    def choose_message(self):

        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Choose message",
            "./extern/dec_messages",
            "Text Files (*.txt)"
        )


        if filename:

            self.selected_file = filename

            with open(filename,"r",encoding="utf-8") as file:
                self.message_content = file.read()

            self.info_label.setText("Selected message:\n" + filename)

            print("Received file:")
            print(self.message_content)

    def receive_message(self):

        result={}
        if self.message_content is None:
            self.info_label.setText("No message selected!")
            return

        password_dialog = PasswordDialog()

        if password_dialog.exec() == QDialog.DialogCode.Accepted:
            password = password_dialog.password

            pgp = PGPReceive(
                private_ring= self.private_ring,
                public_ring=self.public_ring,
                rsa_tool=self.rsa_tool,
                message_content=self.message_content,
                password=password
            )

            result = pgp.receive()

            if "error" in result:
                QMessageBox.warning(self, "Receive error", result["error"])
                return

            self.result=result

            output = ""

            # signature information

            if pgp.is_signature_checked:

                if pgp.is_valid_signature:

                    output += "Signature is valid.\n\n"

                    output += (
                            "--Author--\n"
                            "Name: "
                            + str(pgp.author_name)
                            + "\n"
                              "Email: "
                            + str(pgp.author_email)
                            + "\n\n"
                    )

                else:

                    output += (
                        "Signature is invalid.\n\n"
                    )

                    output += (
                            "--Author--\n"
                            "Name: "
                            + str(pgp.author_name)
                            + "\n"
                              "Email: "
                            + str(pgp.author_email)
                            + "\n\n"
                    )


            else:

                output += (
                    "Signature was not used.\n\n"
                )


            output += (
                    "Message:\n"
                    + self.result["message"]
                    + "\n\n"
            )

            output += (
                    "Filename:\n"
                    + self.result["filename"]+".txt"
                    + "\n\n"
            )

            self.info_label.setText(output)

        else:
            return

        print("Result:")
        print(self.result)

    def save_message(self):

        if not self.result:
            QMessageBox.warning(self, "Save error", "No received message to save.")
            return

        save_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save received message",
            "./extern/enc_messages/",
            "Text Files (*.txt)"
        )

        if save_path:

            if not save_path.endswith(".txt"):
                save_path += ".txt"

            try:

                with open(save_path, "w", encoding="utf-8") as file:
                    file.write(self.result["message"])

                QMessageBox.information(self, "Save", "Message successfully saved.")


            except Exception as e:

                QMessageBox.warning(self, "Save error", str(e))
