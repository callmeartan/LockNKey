import sys
import secrets
import string
import os
import random

from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QLineEdit, QTextEdit, QGroupBox, \
    QRadioButton, QFileDialog, QMessageBox, QProgressBar
from PyQt5.QtGui import QClipboard
from cryptography.fernet import Fernet


class FileWorker(QThread):
    finished = pyqtSignal(str)
    error = pyqtSignal(str)
    progress = pyqtSignal(int)

    def __init__(self, path, mode, key):
        super().__init__()
        self.path = path
        self.mode = mode
        self.key = key

    def run(self):
        try:
            fernet = Fernet(self.key)
            with open(self.path, 'rb') as file:
                file_data = file.read()

            output_data = fernet.encrypt(file_data) if self.mode == 'encrypt' else fernet.decrypt(file_data)
            output_file_path = self.path + (".encrypted" if self.mode == 'encrypt' else ".decrypted")
            with open(output_file_path, 'wb') as file:
                file.write(output_data)

            self.finished.emit(f"File {self.mode}ed. Saved as: {output_file_path}")
        except Exception as e:
            self.error.emit(f"Operation failed: {str(e)}")


class PasswordCipherApp(QWidget):
    def __init__(self):
        super().__init__()
        self.ensure_key_exists()
        self.selectedFilePath = None
        self.initUI()

    def initUI(self):
        print("Initializing UI...")
        self.setWindowTitle('LockNKey')
        self.setGeometry(100, 100, 400, 300)

        self.mainLayout = QVBoxLayout()
        print("Main layout created.")

        self.passwordGeneratorGroup = QGroupBox('Password Generator')
        self.fileCipherGroup = QGroupBox('Encryption')
        print("Groups created.")

        self.setupPasswordGeneratorUI()
        self.setupFileCipherUI()
        print("UI setup functions called.")

        self.mainLayout.addWidget(self.passwordGeneratorGroup)
        self.mainLayout.addWidget(self.fileCipherGroup)
        print("Widgets added to layout.")

        self.progressBar = QProgressBar(self)
        self.mainLayout.addWidget(self.progressBar)
        print("Progress bar added.")

        self.setLayout(self.mainLayout)
        print("Layout set for the main window.")

        self.generatePasswordButton.clicked.connect(self.generate_password)
        self.copyToClipboardButton.clicked.connect(self.copy_to_clipboard)

    def setupPasswordGeneratorUI(self):
        layout = QVBoxLayout()

        self.passwordLengthLineEdit = QLineEdit()
        self.generatePasswordButton = QPushButton('Generate Password')
        self.copyToClipboardButton = QPushButton('Copy to Clipboard')  # Add copy button
        self.generatedPasswordTextEdit = QTextEdit()
        self.passwordStrengthLabel = QLabel('Password Strength: None')  # Initialize the label

        layout.addWidget(QLabel('Password Length:'))
        layout.addWidget(self.passwordLengthLineEdit)
        layout.addWidget(self.generatePasswordButton)
        layout.addWidget(QLabel('Generated Password:'))
        layout.addWidget(self.generatedPasswordTextEdit)
        layout.addWidget(self.passwordStrengthLabel)  # Add the label to the layout
        layout.addWidget(self.copyToClipboardButton)  # Add copy button

        self.passwordGeneratorGroup.setLayout(layout)
    def setupFileCipherUI(self):
        layout = QVBoxLayout()
        self.encryptRadioButton = QRadioButton("Encrypt")
        self.decryptRadioButton = QRadioButton("Decrypt")
        self.fileSelectionButton = QPushButton("Select File")
        self.encryptDecryptButton = QPushButton("Encrypt/Decrypt")
        self.encryptDecryptButton.clicked.connect(self.encrypt_decrypt_file)

        layout.addWidget(self.encryptRadioButton)
        layout.addWidget(self.decryptRadioButton)
        layout.addWidget(self.fileSelectionButton)
        layout.addWidget(self.encryptDecryptButton)

        self.fileCipherGroup.setLayout(layout)

        self.fileSelectionButton.clicked.connect(self.select_file)
        self.encryptDecryptButton.clicked.connect(self.encrypt_decrypt_file)

    def generate_password(self):
        try:
            length = int(self.passwordLengthLineEdit.text())
            if length <= 0:
                QMessageBox.warning(self, "Invalid Input", "Please enter a positive number.")
                return

            characters = string.ascii_letters + string.digits + string.punctuation
            password = ''.join(random.choices(characters, k=length))  # Using random.choices() here
            self.generatedPasswordTextEdit.setText(password)
            strength, color = self.assess_password_strength(password)
            self.passwordStrengthLabel.setText(f'Password Strength: {strength}')
            self.passwordStrengthLabel.setStyleSheet(f"color: {color};")  # Apply color based on strength

        except ValueError:
            QMessageBox.warning(self, "Invalid Input", "Please enter a valid number.")


    def copy_to_clipboard(self):
        clipboard = QApplication.clipboard()
        password = self.generatedPasswordTextEdit.toPlainText()
        clipboard.setText(password)
        QMessageBox.information(self, "Copied", "Password copied to clipboard.")

    def assess_password_strength(self, password):
        length = len(password)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in string.punctuation for c in password)

        score = sum([has_upper, has_lower, has_digit, has_special, length >= 8])

        if score == 5:
            return "Strong", "green"
        elif score >= 3:
            return "Medium", "orange"
        else:
            return "Weak", "red"

    def ensure_key_exists(self):
        """Check if the 'secret.key' file exists and create it if not."""
        if not os.path.exists("secret.key"):
            self.write_key()

    def write_key(self):
        """
        Generates a key and saves it into a file
        """
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
        print("New encryption key generated and saved to 'secret.key'.")

    def load_key(self):
        """
        Load the previously generated key
        """
        return open("secret.key", "rb").read()

    def select_file(self):
        fname, _ = QFileDialog.getOpenFileName(self, 'Select File', '', 'All Files (*)')
        if fname:
            self.selectedFilePath = fname
        else:
            self.selectedFilePath = None

    def encrypt_decrypt_file(self):
        if not self.selectedFilePath:
            QMessageBox.warning(self, "Error", "No file selected.")
            return

        key = self.load_key()
        mode = 'encrypt' if self.encryptRadioButton.isChecked() else 'decrypt'
        self.worker = FileWorker(self.selectedFilePath, mode, key)
        self.worker.finished.connect(self.on_operation_complete)
        self.worker.error.connect(self.on_operation_error)
        self.worker.progress.connect(self.progressBar.setValue)
        self.worker.start()

    def on_operation_complete(self, message):
        self.progressBar.setValue(100)  # Ensure the progress bar shows completion
        QMessageBox.information(self, "Operation Complete", message)

    def on_operation_error(self, message):
        self.progressBar.reset()  # Reset the progress bar on error
        QMessageBox.warning(self, "Operation Failed", message)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    with open("style.qss", "r") as stylefile:
        app.setStyleSheet(stylefile.read())
    ex = PasswordCipherApp()
    ex.show()
    sys.exit(app.exec_())
