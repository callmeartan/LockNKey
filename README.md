
# LockNKey - Password and File Encryption Application

LockNKey is a Python application built using PyQt5 that offers users the ability to generate strong passwords and encrypt or decrypt files securely using the Fernet symmetric encryption method from the cryptography library.

## Features

- **Password Generation:** Generate strong passwords with a customizable length that includes a mixture of uppercase, lowercase, digits, and special characters.
- **File Encryption/Decryption:** Encrypt and decrypt files easily with a high level of security.
- **GUI Interface:** Simple and user-friendly graphical interface to interact with the application.

## Installation

To run LockNKey, you need to have Python installed on your machine along with PyQt5 and the cryptography library. Follow these steps to set up the environment:

1. Clone the repository:
   ```
   git clone https://github.com/your-username/locknkey.git
   ```
2. Navigate to the cloned directory:
   ```
   cd locknkey
   ```
3. Install the required packages:
   ```
   pip install PyQt5 cryptography
   ```

## Usage

To start the application, run the following command in the terminal:
```
python locknkey.py
```

### Generating a Password

1. Enter the desired length for the password in the 'Password Length' field.
2. Click 'Generate Password'.
3. The generated password will be displayed along with its strength (Weak, Medium, Strong).

### Encrypting/Decrypting Files

1. Choose whether you want to encrypt or decrypt a file.
2. Click 'Select File' and choose the file you want to encrypt or decrypt.
3. Click 'Encrypt/Decrypt' to perform the operation.
4. You will be notified once the operation is complete and the output file will be saved in the same directory as the original file.

## Contributing

Contributions to LockNKey are welcome! Here are a few ways you can help:

- Report bugs.
- Add new features.
- Improve documentation.
- Review code and suggest improvements.

If you're ready to contribute to the project, please fork the repository and use a feature branch. Pull requests are warmly welcome.

## Licensing

The code in this project is licensed under MIT license. See the [LICENSE](LICENSE) file for more information.
