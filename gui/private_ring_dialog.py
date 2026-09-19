from PyQt6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QPushButton,
    QHeaderView,
    QMessageBox
)
from PyQt6.QtCore import Qt
from cryptography.hazmat.primitives import serialization
from gui.password_dialog import PasswordDialog
from PyQt6.QtWidgets import QFileDialog
from keys.key_exporter import KeyExporter

class PrivateRingDialog(QDialog):

    def __init__(self, private_ring, public_ring, rsa_tool):

        super().__init__()

        self.private_ring = private_ring
        self.public_ring = public_ring
        self.rsa_tool = rsa_tool
        self.exporter = KeyExporter()

        self.setWindowTitle("Private Key Ring")
        self.setGeometry(250, 150, 1200, 600)

        self.init_ui()


    def init_ui(self):

        layout = QVBoxLayout()
        self.table = QTableWidget()

        self.table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.table.setSelectionMode(
            QTableWidget.SelectionMode.SingleSelection
        )
        self.table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.table.setFocusPolicy(Qt.FocusPolicy.NoFocus)

        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(
            [
                "Name",
                "Email",
                "Key ID",
                "Public Key",
                "Encrypted Private Key",
                "Timestamp"
            ]
        )

        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )

        self.table.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )

        self.table.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )

        self.load_keys()
        layout.addWidget(self.table)

        self.delete_button = QPushButton("Delete Key")
        self.export_button = QPushButton("Export")
        self.import_button = QPushButton("Import")

        layout.addWidget(self.delete_button)
        layout.addWidget(self.export_button)
        layout.addWidget(self.import_button)

        self.delete_button.clicked.connect(self.delete_key)
        self.export_button.clicked.connect(self.export_key)
        self.import_button.clicked.connect(self.import_key)


        self.setStyleSheet("""

            QDialog {

                background-color: #ADD8E6;

            }

            QTableWidget {

                background-color: white;
                color: #003366;
                font-size: 14px;

            }

            QTableWidget::item:selected {

                background-color: #87CEEB;
                color: #003366;

            }

            QTableWidget::item:hover {

                background-color: #DFF6FF;

            }

            QPushButton {

                background-color: white;
                color: #003366;
                border: 2px solid #003366;
                border-radius: 8px;
                padding: 8px;
                font-size: 15px;

            }

            QPushButton:hover {

                background-color: #DFF6FF;

            }

        """)

        self.setLayout(layout)

    def load_keys(self):

        keys = self.private_ring.get_all_keys()
        self.table.setRowCount(len(keys))

        for row, key in enumerate(keys):

            public_pem = key["PublicKey"].public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()

            encrypted_private = key["EncryptedPrivateKey"].hex()

            values = [

                key["Name"],
                key["Email"],
                key["KeyID"],
                public_pem,
                encrypted_private,
                key["Timestamp"]

            ]

            for column, value in enumerate(values):

                item = QTableWidgetItem(value)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.table.setItem(row, column, item)

    def delete_key(self):

        row = self.table.currentRow()

        if row == -1:
            QMessageBox.warning(self, "Error", "Select a key first!")
            return

        key_id = self.table.item(row, 2).text()
        key = self.private_ring.get_key(key_id)

        password_dialog = PasswordDialog()

        if password_dialog.exec():

            password = password_dialog.password

            decrypted_private = self.rsa_tool.decrypt_private_key(
                key["EncryptedPrivateKey"],
                key["IV"],
                password,
                key["PublicKey"]
            )

            if decrypted_private is None:
                QMessageBox.warning(self, "Error", "Wrong password!")
                return

            # delete the private key
            self.private_ring.remove_key(key_id)

            # delete the public key
            self.public_ring.remove_key(key_id)

            QMessageBox.information(self, "Success", "Key pair deleted!")
            self.load_keys()

    def export_key(self):

        row = self.table.currentRow()

        if row == -1:
            QMessageBox.warning(self, "Error", "Select key first!")
            return

        key_id = self.table.item(row, 2).text()
        key = self.private_ring.get_key(key_id)
        password_dialog = PasswordDialog()

        if password_dialog.exec():

            password = password_dialog.password

            private = self.rsa_tool.decrypt_private_key(
                key["EncryptedPrivateKey"],
                key["IV"],
                password,
                key["PublicKey"]
            )

            if private is None:
                QMessageBox.warning(self, "Error", "Wrong password!")
                return

            filename = (key["KeyID"] + "_private_pair.pem")
            self.exporter.export_private_key_pair(key, filename)
            QMessageBox.information(self, "Success", "Key pair exported!")

    def import_key(self):

        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Select private key pair",
            "./extern/private_keys",
            "PEM Files (*.pem)"
        )

        if not filename:
            return

        password_dialog = PasswordDialog()

        if password_dialog.exec():

            password = password_dialog.password
            key = self.exporter.import_private_key_pair(filename)

            decrypted = self.rsa_tool.decrypt_private_key(
                key["EncryptedPrivateKey"],
                key["IV"],
                password,
                key["PublicKey"]
            )

            if decrypted is None:
                QMessageBox.warning(self, "Error", "Wrong password!")
                return

            # add the private key
            self.private_ring.add_key(key)

            # generate the public key part

            public_key = {

                "Timestamp": key["Timestamp"],
                "KeyID": key["KeyID"],
                "Name": key["Name"],
                "Email": key["Email"],
                "Algorithm": key["Algorithm"],
                "KeySize": key["KeySize"],
                "PublicKey": key["PublicKey"]

            }

            self.public_ring.add_key(public_key)

            QMessageBox.information(self, "Success", "Key pair imported!")
            self.load_keys()
