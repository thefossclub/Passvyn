# Passvyn: Secured Password Manager

## Table of Contents
- [Introduction](#introduction)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [How to Run](#how-to-run)
- [Application Usage](#application-usage)
- [File Structure](#file-structure)
- [Security Mechanisms](#security-mechanisms)
- [Customization](#customization)
- [Contributing](#contributing)
- [License](#license)

## Introduction
The **Secured Password Manager** is a simple desktop application built using **PyQt6** and **Cryptography** libraries. It provides a secure way to store, encrypt, and manage your passwords. The tool allows users to add, view, and delete passwords while keeping them encrypted using a master password.

## Features
- **Secure Storage**: Passwords are encrypted using a key derived from the user's master password.
- **Password Generation**: Generate strong random passwords.
- **Master Password Protection**: The application is protected by a master password, which is hashed and stored securely.
- **Password Encryption**: Passwords are stored in an encrypted file using the **Fernet** encryption scheme.
- **User-Friendly GUI**: The interface is simple, intuitive, and styled with a modern dark theme.
- **Cross-Platform**: It runs on any platform supported by Python, including Windows, Linux, and macOS.

## Prerequisites
To run the **Secured Password Manager**, you need to have the following installed on your system:
- **Python 3.7+**
- **pip** (Python's package manager)
- **PyQt6** for the GUI
- **Cryptography** for encryption

## Installation

1. **Clone or Download the Repository**:
   ```bash
   git clone https://github.com/your-username/secured-password-manager.git
   cd secured-password-manager
   ```

2. **Install Required Python Packages**:
   Run the following command to install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

   **Required dependencies**:
   - `PyQt6`
   - `cryptography`

3. **Configuration Files**:
   When you first run the application, it will automatically create the necessary configuration and password files.

## How to Run

1. **Running the Application**:
   After installing the dependencies, you can run the application using:
   ```bash
   python main.py
   ```

2. **Setting Up Master Password**:
   - On the first run, you'll be prompted to enter a master password. This password will be hashed and stored in the configuration file. Make sure to remember this password as it will be required for all future access.
   
3. **Login**:
   - Upon starting the application, you'll be prompted to input your master password to unlock and decrypt your stored passwords.

## Application Usage

### Main Features:

1. **Add Password**:
   - Navigate to the "Add Password" tab.
   - Enter the website, username, and password (or generate a new password using the "Generate Password" button).
   - Click on "Add Password" to store it securely.

2. **View Passwords**:
   - Navigate to the "View Passwords" tab.
   - Select an entry from the list and click "View Password" to see the stored password details.

3. **Delete Password**:
   - In the "View Passwords" tab, select a password entry and click "Delete Password" to remove it from the list.

### GUI Elements:

- **QTabWidget**: The application uses a tab-based interface, allowing users to switch between adding passwords and viewing stored passwords.
- **QTreeWidget**: Password entries are displayed in a tree structure, with each entry showing the website and username.
- **ModernStyle**: The custom dark-themed style is applied to the entire application for a consistent and sleek look.

## File Structure

The main files of the project include:

- **`main.py`**: The primary Python script containing the application logic and GUI.
- **`config.json`**: A configuration file where the master password hash and salt are stored.
- **`passwords.enc`**: A file that stores the encrypted passwords.
- **`requirements.txt`**: Contains the list of required Python packages.

## Security Mechanisms

- **Master Password**: The master password is hashed using SHA-256 and stored in a configuration file. The hash is used to verify the password on future logins.
- **Encryption Key Derivation**: The encryption key is derived from the master password using PBKDF2 (Password-Based Key Derivation Function) with SHA-256, a secure cryptographic algorithm. A unique salt is used to prevent dictionary attacks.
- **Fernet Encryption**: Passwords are encrypted and decrypted using the **Fernet** symmetric encryption from the `cryptography` library.
- **Encrypted File**: Passwords are stored in the `passwords.enc` file, which is encrypted using the Fernet encryption algorithm.

## Introduction
The **Secured Password Manager** is a desktop application built using **PyQt6** and **Cryptography** li>
## Customization

- **Styling**: The look and feel of the application can be customized by modifying the `ModernStyle.set_style()` method. You can adjust the colors, borders, and styles of various widgets.
- **Password Generation**: The password generation logic uses Python’s `secrets.token_urlsafe()` method, which can be customized for different password lengths or character sets.

## Contributing

If you'd like to contribute to the project, please follow these steps:

1. Fork the repository.
2. Create a new branch: `git checkout -b feature-branch-name`.
3. Make your changes and commit them: `git commit -m 'Add some feature'`.
4. Push to the branch: `git push origin feature-branch-name`.
5. Open a pull request.

Please ensure your code follows Python best practices and is properly formatted with docstrings and comments where necessary.

## License

This project is licensed under the GPLv2 License.
