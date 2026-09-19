from PyQt6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QPushButton,
    QHeaderView
)
from PyQt6.QtCore import Qt
from gui.password_dialog import PasswordDialog
from PyQt6.QtWidgets import QMessageBox

class PrivateKeySelectionDialog(QDialog):

    def __init__(self,private_ring,rsa_tool):

        super().__init__()

        self.private_ring = private_ring
        self.rsa_tool = rsa_tool

        self.selected_key = None
        self.decrypted_private_key = None
        self.password = None

        self.setWindowTitle("Select Private Key")
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

        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(
            [
                "Name",
                "Email",
                "Key ID",
                "Encrypted Private Key"
            ]
        )

        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self.table.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )

        self.load_keys()

        layout.addWidget(self.table)

        self.select_button = QPushButton("Select")
        self.select_button.clicked.connect(self.select_key)
        layout.addWidget(self.select_button)

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

        for row,key in enumerate(keys):

            encrypted = key["EncryptedPrivateKey"].hex()

            values = [
                key["Name"],
                key["Email"],
                key["KeyID"],
                encrypted
            ]

            for col,value in enumerate(values):

                item = QTableWidgetItem(value)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.table.setItem(row, col, item)

    def select_key(self):

        row = self.table.currentRow()

        if row == -1:
            QMessageBox.warning(self, "Error", "Select a key first!")
            return

        key_id = self.table.item(row, 2).text()

        key = self.private_ring.get_key(key_id)

        password_dialog = PasswordDialog()

        if not password_dialog.exec():
            return

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

        self.selected_key = key
        self.decrypted_private_key = decrypted_private
        self.password= password

        print("selected key: " ,self.selected_key)
        print("decrypted private key: " , self.decrypted_private_key)

        self.accept()
