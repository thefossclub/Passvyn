import sys
import os
import json
import hashlib
import secrets
from PyQt6.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, QTreeWidget, 
                             QTreeWidgetItem, QMessageBox, QInputDialog, QStyleFactory)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPalette, QColor
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

class ModernStyle:
    @staticmethod
    def set_style(app):
        app.setStyle(QStyleFactory.create("Fusion"))
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))
        palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.Base, QColor(25, 25, 25))
        palette.setColor(QPalette.ColorRole.AlternateBase, QColor(53, 53, 53))
        palette.setColor(QPalette.ColorRole.ToolTipBase, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.ToolTipText, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
        palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
        palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
        palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
        palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.black)
        app.setPalette(palette)
        
        app.setStyleSheet("""
            QWidget {
                border-radius: 5px;
            }
            QPushButton {
                background-color: #2a82da;
                color: white;
                border: none;
                padding: 5px 15px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #3a92ea;
            }
            QLineEdit {
                padding: 5px;
                border: 1px solid #555;
                border-radius: 5px;
            }
            QTabWidget::pane {
                border: 1px solid #555;
                border-radius: 5px;
            }
            QTabBar::tab {
                background-color: #2a2a2a;
                color: white;
                padding: 8px 20px;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
            }
            QTabBar::tab:selected {
                background-color: #3a3a3a;
            }
            QTreeWidget {
                border: 1px solid #555;
                border-radius: 5px;
            }
        """)

class SecuredPasswordManager:
    def __init__(self):
        self.passwords = []
        self.master_password_hash = None
        self.encryption_key = None
        self.salt = None
        self.config_file = "config.json"
        self.passwords_file = "passwords.enc"

    def load_config(self):
        if os.path.exists(self.config_file):
            with open(self.config_file, "r") as file:
                config = json.load(file)
                self.master_password_hash = config.get("master_password_hash")
                self.salt = base64.b64decode(config.get("salt", ""))
        else:
            self.salt = os.urandom(16)

    def save_config(self):
        config = {
            "master_password_hash": self.master_password_hash,
            "salt": base64.b64encode(self.salt).decode()
        }
        with open(self.config_file, "w") as file:
            json.dump(config, file)

    def derive_key(self, master_password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

    def encrypt_passwords(self):
        f = Fernet(self.encryption_key)
        encrypted_data = f.encrypt(json.dumps(self.passwords).encode())
        with open(self.passwords_file, "wb") as file:
            file.write(encrypted_data)

    def decrypt_passwords(self):
        if not os.path.exists(self.passwords_file):
            return
        with open(self.passwords_file, "rb") as file:
            encrypted_data = file.read()
        f = Fernet(self.encryption_key)
        decrypted_data = f.decrypt(encrypted_data)
        self.passwords = json.loads(decrypted_data.decode())

    def verify_master_password(self, master_password):
        if not self.master_password_hash:
            self.master_password_hash = hashlib.sha256(master_password.encode()).hexdigest()
            self.encryption_key = self.derive_key(master_password)
            self.save_config()
            return True
        else:
            input_hash = hashlib.sha256(master_password.encode()).hexdigest()
            if input_hash == self.master_password_hash:
                self.encryption_key = self.derive_key(master_password)
                return True
        return False

    def add_password(self, website, username, password):
        self.passwords.append({"website": website, "username": username, "password": password})
        self.encrypt_passwords()

    def get_password(self, index):
        return self.passwords[index]

    def delete_password(self, index):
        del self.passwords[index]
        self.encrypt_passwords()

    def get_all_passwords(self):
        return self.passwords

class PasswordManagerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.password_manager = SecuredPasswordManager()
        self.password_manager.load_config()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Secured Password Manager")
        self.setGeometry(100, 100, 600, 400)

        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout()
        main_widget.setLayout(main_layout)

        tabs = QTabWidget()
        main_layout.addWidget(tabs)

        add_tab = QWidget()
        add_layout = QVBoxLayout()
        add_tab.setLayout(add_layout)

        add_layout.addWidget(QLabel("Website:"))
        self.website_entry = QLineEdit()
        add_layout.addWidget(self.website_entry)

        add_layout.addWidget(QLabel("Username:"))
        self.username_entry = QLineEdit()
        add_layout.addWidget(self.username_entry)

        add_layout.addWidget(QLabel("Password:"))
        self.password_entry = QLineEdit()
        self.password_entry.setEchoMode(QLineEdit.EchoMode.Password)
        add_layout.addWidget(self.password_entry)

        button_layout = QHBoxLayout()
        generate_button = QPushButton("Generate Password")
        generate_button.clicked.connect(self.generate_password)
        button_layout.addWidget(generate_button)

        add_button = QPushButton("Add Password")
        add_button.clicked.connect(self.add_password)
        button_layout.addWidget(add_button)

        add_layout.addLayout(button_layout)

        tabs.addTab(add_tab, "Add Password")

        view_tab = QWidget()
        view_layout = QVBoxLayout()
        view_tab.setLayout(view_layout)

        self.password_tree = QTreeWidget()
        self.password_tree.setHeaderLabels(["Website", "Username"])
        view_layout.addWidget(self.password_tree)

        view_button_layout = QHBoxLayout()
        view_button = QPushButton("View Password")
        view_button.clicked.connect(self.view_password)
        view_button_layout.addWidget(view_button)

        delete_button = QPushButton("Delete Password")
        delete_button.clicked.connect(self.delete_password)
        view_button_layout.addWidget(delete_button)

        view_layout.addLayout(view_button_layout)

        tabs.addTab(view_tab, "View Passwords")

    def generate_password(self):
        password = secrets.token_urlsafe(16)
        self.password_entry.setText(password)

    def add_password(self):
        website = self.website_entry.text()
        username = self.username_entry.text()
        password = self.password_entry.text()

        if website and username and password:
            self.password_manager.add_password(website, username, password)
            QMessageBox.information(self, "Success", "Password added successfully!")
            self.website_entry.clear()
            self.username_entry.clear()
            self.password_entry.clear()
            self.refresh_password_list()
        else:
            QMessageBox.warning(self, "Error", "Please fill in all fields!")

    def view_password(self):
        selected_items = self.password_tree.selectedItems()
        if selected_items:
            item = selected_items[0]
            index = self.password_tree.indexOfTopLevelItem(item)
            password_entry = self.password_manager.get_password(index)
            QMessageBox.information(self, "Password Details",
                                    f"Website: {password_entry['website']}\n"
                                    f"Username: {password_entry['username']}\n"
                                    f"Password: {password_entry['password']}")
        else:
            QMessageBox.warning(self, "Error", "Please select a password entry!")

    def delete_password(self):
        selected_items = self.password_tree.selectedItems()
        if selected_items:
            item = selected_items[0]
            index = self.password_tree.indexOfTopLevelItem(item)
            self.password_manager.delete_password(index)
            self.refresh_password_list()
            QMessageBox.information(self, "Success", "Password deleted successfully!")
        else:
            QMessageBox.warning(self, "Error", "Please select a password entry!")

    def refresh_password_list(self):
        self.password_tree.clear()
        for password in self.password_manager.get_all_passwords():
            item = QTreeWidgetItem([password["website"], password["username"]])
            self.password_tree.addTopLevelItem(item)

    def run(self):
        master_password, ok = QInputDialog.getText(self, "Master Password", "Enter your master password:", QLineEdit.EchoMode.Password)
        if ok and master_password:
            if self.password_manager.verify_master_password(master_password):
                self.password_manager.decrypt_passwords()
                self.refresh_password_list()
                self.show()
            else:
                QMessageBox.critical(self, "Error", "Incorrect master password!")
                sys.exit()
        else:
            sys.exit()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    ModernStyle.set_style(app)
    password_manager_gui = PasswordManagerGUI()
    password_manager_gui.run()
    sys.exit(app.exec())
