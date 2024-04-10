import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QCheckBox, QPushButton, QTextEdit
import secrets
import string


class PasswordCipherApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('LockNKey')
        self.setGeometry(100, 100, 400, 300)

        layout = QVBoxLayout()

        # Password Length
        self.lengthLabel = QLabel('Password Length:')
        self.lengthInput = QLineEdit('12')
        layout.addWidget(self.lengthLabel)
        layout.addWidget(self.lengthInput)

        # Include Symbols
        self.symbolsCheck = QCheckBox('Include Symbols')
        self.symbolsCheck.setChecked(True)
        layout.addWidget(self.symbolsCheck)

        # Include Numbers
        self.numbersCheck = QCheckBox('Include Numbers')
        self.numbersCheck.setChecked(True)
        layout.addWidget(self.numbersCheck)

        # Generate Button
        self.generateBtn = QPushButton('Generate Password')
        self.generateBtn.clicked.connect(self.generate_password)
        layout.addWidget(self.generateBtn)

        # Password Display
        self.passwordDisplay = QTextEdit()
        self.passwordDisplay.setReadOnly(True)
        layout.addWidget(self.passwordDisplay)

        self.setLayout(layout)

    def generate_password(self):
        length = int(self.lengthInput.text())
        use_symbols = self.symbolsCheck.isChecked()
        use_numbers = self.numbersCheck.isChecked()

        characters = string.ascii_letters
        if use_symbols:
            characters += string.punctuation
        if use_numbers:
            characters += string.digits

        password = ''.join(secrets.choice(characters) for i in range(length))
        self.passwordDisplay.setText(password)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    ex = PasswordCipherApp()
    ex.show()
    sys.exit(app.exec_())
