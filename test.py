import sys
import secrets
import string
import os
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QLineEdit, QTextEdit, QGroupBox, QRadioButton, QFileDialog
from cryptography.fernet import Fernet

class PasswordCipherApp(QWidget):
    def __init__(self):
        super().__init__()
        # Ensure the encryption key exists
        self.ensure_key_exists()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Password Cipher App')
        self.setGeometry(100, 100, 400, 300)

        self.mainLayout = QVBoxLayout()

        self.passwordGeneratorGroup = QGroupBox('Password Generator')
        self.fileCipherGroup = QGroupBox('File Cipher')

        self.setupPasswordGeneratorUI()
        self.setupFileCipherUI()

        self.mainLayout.addWidget(self.passwordGeneratorGroup)
        self.mainLayout.addWidget(self.fileCipherGroup)

        self.setLayout(self.mainLayout)

    def setupPasswordGeneratorUI(self):
        layout = QVBoxLayout()

        self.passwordLengthLineEdit = QLineEdit()
        self.generatePasswordButton = QPushButton('Generate Password')
        self.generatedPasswordTextEdit = QTextEdit()

        layout.addWidget(QLabel('Password Length:'))
        layout.addWidget(self.passwordLengthLineEdit)
        layout.addWidget(self.generatePasswordButton)
        layout.addWidget(QLabel('Generated Password:'))
        layout.addWidget(self.generatedPasswordTextEdit)

        self.passwordGeneratorGroup.setLayout(layout)

        self.generatePasswordButton.clicked.connect(self.generate_password)

    def setupFileCipherUI(self):
        layout = QVBoxLayout()
        self.encryptRadioButton = QRadioButton("Encrypt")
        self.decryptRadioButton = QRadioButton("Decrypt")
        self.fileSelectionButton = QPushButton("Select File")
        self.encryptDecryptButton = QPushButton("Encrypt/Decrypt")

        layout.addWidget(self.encryptRadioButton)
        layout.addWidget(self.decryptRadioButton)
        layout.addWidget(self.fileSelectionButton)
        layout.addWidget(self.encryptDecryptButton)

        self.fileCipherGroup.setLayout(layout)

        self.fileSelectionButton.clicked.connect(self.select_file)
        self.encryptDecryptButton.clicked.connect(self.encrypt_decrypt_file)

    def generate_password(self):
        length = int(self.passwordLengthLineEdit.text())
        password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))
        self.generatedPasswordTextEdit.setText(password)

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
        if not hasattr(self, 'selectedFilePath') or not self.selectedFilePath:
            print("No file selected.")
            return

        key = self.load_key()
        fernet = Fernet(key)

        with open(self.selectedFilePath, 'rb') as file:
            file_data = file.read()

        if self.encryptRadioButton.isChecked():
            encrypted_data = fernet.encrypt(file_data)
            encrypted_file_path = self.selectedFilePath + ".encrypted"  # Append '.encrypted' to the original file name
            with open(encrypted_file_path, 'wb') as file:
                file.write(encrypted_data)
            print(f"File encrypted. Encrypted file saved as: {encrypted_file_path}")
        elif self.decryptRadioButton.isChecked():
            try:
                decrypted_data = fernet.decrypt(file_data)
                decrypted_file_path = self.selectedFilePath.replace(".encrypted",
                                                                    "")  # Assuming the encrypted files end with '.encrypted'
                with open(decrypted_file_path, 'wb') as file:
                    file.write(decrypted_data)
                print(f"File decrypted. Decrypted file saved as: {decrypted_file_path}")
            except Exception as e:
                print("Decryption failed. Are you sure the file is encrypted?")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    with open("style.qss", "r") as stylefile:
        app.setStyleSheet(stylefile.read())
    ex = PasswordCipherApp()
    ex.show()
    sys.exit(app.exec_())
