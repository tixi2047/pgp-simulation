from PyQt6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QPushButton,
    QHeaderView,
    QMessageBox
)
import os
from PyQt6.QtCore import Qt
from cryptography.hazmat.primitives import serialization
from gui.password_dialog import PasswordDialog
from PyQt6.QtWidgets import QFileDialog

class PublicRingDialog(QDialog):

    def __init__(self, public_ring, private_ring, rsa_tool):

        super().__init__()

        self.public_ring = public_ring
        self.private_ring = private_ring
        self.rsa_tool = rsa_tool

        self.setWindowTitle("Public Key Ring")
        self.setGeometry(250, 150, 1200, 600)

        self.init_ui()

    def init_ui(self):

        layout = QVBoxLayout()

        self.table = QTableWidget()
        self.table.setColumnCount(5)

        self.table.setHorizontalHeaderLabels(
            [
                "Name",
                "Email",
                "Key ID",
                "Public Key",
                "Timestamp"
            ]
        )

        # select the entire row
        self.table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )

        # single selection
        self.table.setSelectionMode(
            QTableWidget.SelectionMode.SingleSelection
        )

        # disable text editing
        self.table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
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

        self.action_button = QPushButton("Delete Key")
        self.export_button = QPushButton("Export Public Key")
        self.import_button = QPushButton("Import Public Key")

        layout.addWidget(self.action_button)
        layout.addWidget(self.export_button)
        layout.addWidget(self.import_button)

        self.action_button.clicked.connect(self.delete_key)
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

        keys = self.public_ring.get_all_keys()

        self.table.setRowCount(len(keys))

        for row, key in enumerate(keys):

            public_pem = key["PublicKey"].public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()

            values = [
                key["Name"],
                key["Email"],
                key["KeyID"],
                public_pem,
                key["Timestamp"]
            ]

            for column, value in enumerate(values):

                item = QTableWidgetItem(value)

                # disable individual cell editing
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.table.setItem(row, column, item)

    def delete_key(self):

        row = self.table.currentRow()

        if row == -1:
            QMessageBox.warning(self, "Error", "Select a key first!")
            return

        key_id = self.table.item(row, 2).text()

        # check if the private key exists

        private_key = self.private_ring.get_key(key_id)

        if private_key is not None:
            password_dialog = PasswordDialog()

            if password_dialog.exec():
                password = password_dialog.password

                decrypted_private = self.rsa_tool.decrypt_private_key(
                    private_key["EncryptedPrivateKey"],
                    private_key["IV"],
                    password,
                    private_key["PublicKey"]
                )

                if decrypted_private is None:
                    QMessageBox.warning(self, "Error", "Wrong password!")
                    return


                self.private_ring.remove_key(key_id)
                self.public_ring.remove_key(key_id)

                QMessageBox.information(self, "Success", "Key pair deleted!")

        else:

            # public key only (foreign/external)
            self.public_ring.remove_key(key_id)

            QMessageBox.information(self, "Success", "Public key deleted!")

        self.load_keys()

    def export_key(self):

        row = self.table.currentRow()

        if row == -1:
            QMessageBox.warning(self, "Error", "Select a key first!")
            return

        key_id = self.table.item(row, 2).text()

        key = self.public_ring.get_key(key_id)

        public_pem = key["PublicKey"].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        content = f"""
            -----BEGIN PGP PUBLIC KEY-----
            
            Timestamp: {key["Timestamp"]}
            KeyID: {key["KeyID"]}
            Name: {key["Name"]}
            Email: {key["Email"]}
            Algorithm: {key["Algorithm"]}
            KeySize: {key["KeySize"]}
            
            
            {public_pem}
            
            -----END PGP PUBLIC KEY-----
            """

        # create folder if it does not exist

        path = "./extern/public_keys"
        os.makedirs(path, exist_ok=True)
        filename = (f'{path}/{key["KeyID"]}_public.pem')

        with open(filename, "w") as file:

            file.write(content)

        QMessageBox.information(self, "Success", f"Public key exported:\n{filename}")

    def extract_value(self, data, field):

        for line in data.splitlines():
            line = line.strip()
            if line.startswith(field + ":"):
                return line.split(":", 1)[1].strip()
        return ""

    def import_key(self):

        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Select Public Key",
            "./extern/public_keys",
            "PEM Files (*.pem)"
        )

        if not filename:
            return

        try:
            with open(filename,"r") as file:
                data = file.read()

            # extracting information

            timestamp = self.extract_value(data, "Timestamp")
            key_id = self.extract_value(data, "KeyID")
            name = self.extract_value(data, "Name")
            email = self.extract_value(data, "Email")
            algorithm = self.extract_value(data, "Algorithm")
            key_size = int(self.extract_value(data, "KeySize"))

            # extract the actual PEM block

            start = data.index("-----BEGIN PUBLIC KEY-----")
            end = data.index("-----END PUBLIC KEY-----") + len("-----END PUBLIC KEY-----")

            public_pem = data[start:end]

            public_key = serialization.load_pem_public_key(
                public_pem.encode()
            )

            public_key_info = {
                "Timestamp": timestamp,
                "KeyID": key_id,
                "Name": name,
                "Email": email,
                "Algorithm": algorithm,
                "KeySize": key_size,
                "PublicKey": public_key

            }

            # check if it already exists

            if self.public_ring.contains(key_id):
                QMessageBox.warning(self, "Error", "Key already exists!")
                return

            self.public_ring.add_key(public_key_info)

            QMessageBox.information(self, "Success", "Public key imported!")

            self.load_keys()

        except Exception as e:

            QMessageBox.warning(self, "Error", f"Import failed:\n{e}")
