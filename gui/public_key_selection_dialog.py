from PyQt6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QPushButton,
    QHeaderView
)
from PyQt6.QtCore import Qt

class PublicKeySelectionDialog(QDialog):

    def __init__(self, public_ring):

        super().__init__()

        self.public_ring = public_ring
        self.selected_key = None

        self.setWindowTitle("Select Public Key")
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

        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Name", "Email", "Key ID"])

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

        keys = self.public_ring.get_all_keys()
        self.table.setRowCount(len(keys))

        for row,key in enumerate(keys):

            values = [key["Name"], key["Email"], key["KeyID"]]

            for col,value in enumerate(values):

                item = QTableWidgetItem(value)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.table.setItem(row, col, item)

    def select_key(self):

        row = self.table.currentRow()

        if row == -1:
            return

        key_id = self.table.item(row, 2).text()
        self.selected_key = (self.public_ring.get_key(key_id))
        self.accept()
