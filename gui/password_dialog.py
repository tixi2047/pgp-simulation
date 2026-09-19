from PyQt6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton
)

class PasswordDialog(QDialog):

    def __init__(self):

        super().__init__()
        self.password = None
        self.setWindowTitle("Enter Password")

        self.init_ui()

    def init_ui(self):

        layout = QVBoxLayout()
        layout.addWidget(QLabel("Password:"))

        self.password_input = QLineEdit()

        self.password_input.setEchoMode(
            QLineEdit.EchoMode.Password
        )
        layout.addWidget(self.password_input)

        button = QPushButton("Confirm")
        button.clicked.connect(self.accept_password)
        layout.addWidget(button)
        self.setLayout(layout)

    def accept_password(self):
        if self.password_input.text():
            self.password = self.password_input.text()
            self.accept()
