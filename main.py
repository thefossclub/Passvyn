import sys
import os
os.environ['QT_QPA_PLATFORM'] = 'xcb'
import json
import hashlib
import secrets
from PyQt6.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, QTreeWidget, 
                             QTreeWidgetItem, QMessageBox, QInputDialog, QStyleFactory,
                             QListWidget, QListWidgetItem, QGroupBox, QGridLayout, 
                             QStackedWidget, QSpacerItem, QSizePolicy)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QPalette, QColor
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import pyotp
import time
import cv2
from pyzbar import pyzbar
import urllib.parse

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
        self.totp_accounts = []
        self.master_password_hash = None
        self.encryption_key = None
        self.salt = None
        self.config_file = "config.json"
        self.data_file = "data.enc"

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

    def encrypt_data(self):
        if not self.encryption_key:
            print("Error: Encryption key not available.")
            return
        data_to_encrypt = {
            "passwords": self.passwords,
            "totp_accounts": self.totp_accounts
        }
        f = Fernet(self.encryption_key)
        encrypted_data = f.encrypt(json.dumps(data_to_encrypt).encode())
        with open(self.data_file, "wb") as file:
            file.write(encrypted_data)

    def decrypt_data(self):
        if not self.encryption_key:
            print("Error: Decryption key not available.")
            return False
        if not os.path.exists(self.data_file):
            self.passwords = []
            self.totp_accounts = []
            return True
        try:
            with open(self.data_file, "rb") as file:
                encrypted_data = file.read()
            f = Fernet(self.encryption_key)
            decrypted_data = f.decrypt(encrypted_data)
            loaded_data = json.loads(decrypted_data.decode())
            self.passwords = loaded_data.get("passwords", [])
            self.totp_accounts = loaded_data.get("totp_accounts", [])
            return True
        except Exception as e:
            print(f"Error decrypting data: {e}")
            QMessageBox.critical(None, "Decryption Error", f"Failed to decrypt data. The master password might be incorrect or the data file ('{self.data_file}') might be corrupted.")
            return False

    def verify_master_password(self, master_password):
        if not self.master_password_hash:
            self.master_password_hash = hashlib.sha256(master_password.encode()).hexdigest()
            self.encryption_key = self.derive_key(master_password)
            self.save_config()
            self.encrypt_data()
            return True
        else:
            input_hash = hashlib.sha256(master_password.encode()).hexdigest()
            if input_hash == self.master_password_hash:
                self.encryption_key = self.derive_key(master_password)
                return self.decrypt_data()
        QMessageBox.critical(None, "Error", "Incorrect master password!")
        return False

    def add_password(self, website, username, password):
        entry = {"website": website, "username": username, "password": password}
        self.passwords.append(entry)
        self.encrypt_data()

    def get_password(self, index):
        return self.passwords[index]

    def delete_password(self, index):
        del self.passwords[index]
        self.encrypt_data()

    def get_all_passwords(self):
        return self.passwords

    def add_totp_account(self, name, secret):
        if not name or not secret:
             raise ValueError("Account name and secret cannot be empty.")
        # Validate secret by attempting to create a TOTP object
        cleaned_secret = secret.replace(" ", "").upper()
        try:
            # Attempt to initialize TOTP - this implicitly validates Base32
            pyotp.TOTP(cleaned_secret)
        except Exception as e:
            # Catch potential exceptions during init (like base64 errors)
            print(f"Secret validation failed: {e}") # Optional logging
            raise ValueError("Invalid Base32 secret format.")
            
        # Check for duplicate names (optional but good practice)
        if any(acc["name"].lower() == name.lower() for acc in self.totp_accounts):
             raise ValueError(f"An account named '{name}' already exists.")
             
        entry = {"name": name, "secret": cleaned_secret}
        self.totp_accounts.append(entry)
        self.encrypt_data() # Encrypt combined data
        
    def get_totp_account(self, index):
        return self.totp_accounts[index]
         
    def delete_totp_account(self, index):
        del self.totp_accounts[index]
        self.encrypt_data()
         
    def get_all_totp_accounts(self):
        return self.totp_accounts

    def generate_totp_code(self, index):
        account = self.get_totp_account(index)
        secret = account.get("secret")
        if secret:
            try:
                totp = pyotp.TOTP(secret)
                return totp.now()
            except Exception as e:
                print(f"Error generating TOTP for account {account.get('name')}: {e}")
                return "Error"
        return None

class PasswordManagerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.password_manager = SecuredPasswordManager()
        self.password_manager.load_config()
        self.totp_timer = QTimer(self)
        self.totp_timer.timeout.connect(self.update_authenticator_display)
        self.currently_selected_totp_index = -1
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Secured Password Manager")
        self.setGeometry(100, 100, 700, 450)

        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout()
        main_widget.setLayout(main_layout)

        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

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

        add_button = QPushButton("Add Entry")
        add_button.clicked.connect(self.add_entry)
        button_layout.addWidget(add_button)

        add_layout.addLayout(button_layout)
        add_layout.addStretch()
        self.tabs.addTab(add_tab, "Add Entry")

        view_tab = QWidget()
        view_layout = QVBoxLayout()
        view_tab.setLayout(view_layout)

        self.password_tree = QTreeWidget()
        self.password_tree.setHeaderLabels(["Website", "Username"])
        self.password_tree.itemSelectionChanged.connect(self.display_entry_details)
        view_layout.addWidget(self.password_tree)
        
        self.details_group = QGroupBox("Selected Entry Details")
        details_layout = QGridLayout()
        self.details_group.setLayout(details_layout)

        details_layout.addWidget(QLabel("Website:"), 0, 0)
        self.details_website_label = QLabel("-")
        details_layout.addWidget(self.details_website_label, 0, 1)

        details_layout.addWidget(QLabel("Username:"), 1, 0)
        self.details_username_label = QLabel("-")
        details_layout.addWidget(self.details_username_label, 1, 1)

        details_layout.addWidget(QLabel("Password:"), 2, 0)
        self.details_password_label = QLabel("-")
        self.details_password_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        details_layout.addWidget(self.details_password_label, 2, 1)
        
        details_layout.addWidget(QLabel("TOTP Code:"), 3, 0)
        self.details_totp_code_label = QLabel("-")
        self.details_totp_code_label.setStyleSheet("font-size: 18pt; font-weight: bold;")
        self.details_totp_code_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        details_layout.addWidget(self.details_totp_code_label, 3, 1)

        self.details_totp_progressbar = QLabel("")
        details_layout.addWidget(self.details_totp_progressbar, 4, 0, 1, 2)

        view_layout.addWidget(self.details_group)

        view_button_layout = QHBoxLayout()
        view_password_button = QPushButton("Show/Hide Password")
        view_password_button.clicked.connect(self.toggle_view_password)
        view_button_layout.addWidget(view_password_button)

        delete_button = QPushButton("Delete Selected Entry")
        delete_button.clicked.connect(self.delete_selected_entry)
        view_button_layout.addWidget(delete_button)

        view_layout.addLayout(view_button_layout)

        self.tabs.addTab(view_tab, "View Entries")

        auth_tab = QWidget()
        auth_tab_layout = QVBoxLayout()
        auth_tab.setLayout(auth_tab_layout)

        self.authenticator_stack = QStackedWidget()
        auth_tab_layout.addWidget(self.authenticator_stack)

        view_codes_widget = QWidget()
        view_codes_layout = QHBoxLayout()
        view_codes_widget.setLayout(view_codes_layout)

        view_codes_left_pane = QVBoxLayout()
        view_codes_left_pane.addWidget(QLabel("Authenticator Accounts:"))
        self.totp_account_list = QListWidget()
        self.totp_account_list.itemSelectionChanged.connect(self.display_totp_details)
        view_codes_left_pane.addWidget(self.totp_account_list)

        add_new_account_button = QPushButton("Add New Account + ")
        add_new_account_button.clicked.connect(lambda: self.authenticator_stack.setCurrentIndex(1))
        view_codes_left_pane.addWidget(add_new_account_button)

        view_codes_right_pane = QVBoxLayout()
        self.totp_details_group = QGroupBox("Current Code")
        totp_details_layout = QVBoxLayout()
        self.totp_details_group.setLayout(totp_details_layout)
        
        self.totp_details_name_label = QLabel("<i>Select an account</i>")
        self.totp_details_name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.totp_details_name_label.setStyleSheet("margin-top: 10px;")
        totp_details_layout.addWidget(self.totp_details_name_label)
        
        self.totp_details_code_label = QLabel("-")
        self.totp_details_code_label.setStyleSheet("font-size: 28pt; font-weight: bold; margin: 10px;")
        self.totp_details_code_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.totp_details_code_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        totp_details_layout.addWidget(self.totp_details_code_label)

        self.totp_details_progressbar = QLabel("") 
        self.totp_details_progressbar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        totp_details_layout.addWidget(self.totp_details_progressbar)

        totp_details_layout.addStretch(1)
        delete_totp_button = QPushButton("Delete Selected Account")
        delete_totp_button.clicked.connect(self.delete_selected_totp_account)
        totp_details_layout.addWidget(delete_totp_button)
        
        view_codes_right_pane.addWidget(self.totp_details_group)
        view_codes_right_pane.addStretch()

        view_codes_layout.addLayout(view_codes_left_pane, 2)
        view_codes_layout.addLayout(view_codes_right_pane, 1)
        
        self.authenticator_stack.addWidget(view_codes_widget)

        add_account_widget = QWidget()
        add_account_layout = QVBoxLayout()
        add_account_widget.setLayout(add_account_layout)

        add_auth_group = QGroupBox("Add New Authenticator Account")
        add_auth_form_layout = QGridLayout()
        add_auth_group.setLayout(add_auth_form_layout)
        
        scan_qr_button = QPushButton("Scan QR Code (Recommended)") 
        scan_qr_button.setStyleSheet("padding: 10px;")
        scan_qr_button.clicked.connect(self.scan_totp_qr_code)
        add_auth_form_layout.addWidget(scan_qr_button, 0, 0, 1, 2)

        add_auth_form_layout.addItem(QSpacerItem(20, 10, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding), 1, 0, 1, 2)
        add_auth_form_layout.addWidget(QLabel("<i>Or enter manually:</i>"), 2, 0, 1, 2, alignment=Qt.AlignmentFlag.AlignCenter)

        add_auth_form_layout.addWidget(QLabel("Account Name:"), 3, 0)
        self.totp_account_name_entry = QLineEdit()
        self.totp_account_name_entry.setPlaceholderText("e.g., Google (myemail@...) / GitHub")
        add_auth_form_layout.addWidget(self.totp_account_name_entry, 3, 1)

        add_auth_form_layout.addWidget(QLabel("Secret Key (Base32):"), 4, 0)
        self.totp_secret_key_entry = QLineEdit()
        self.totp_secret_key_entry.setPlaceholderText("Paste Base32 secret here")
        add_auth_form_layout.addWidget(self.totp_secret_key_entry, 4, 1)

        manual_add_button = QPushButton("Add Account Manually")
        manual_add_button.clicked.connect(self.add_totp_account_gui)
        add_auth_form_layout.addWidget(manual_add_button, 5, 0, 1, 2)

        add_account_layout.addWidget(add_auth_group)
        add_account_layout.addStretch(1)
        
        cancel_add_button = QPushButton("Cancel")
        cancel_add_button.clicked.connect(lambda: self.authenticator_stack.setCurrentIndex(0))
        add_account_layout.addWidget(cancel_add_button, alignment=Qt.AlignmentFlag.AlignRight)

        self.authenticator_stack.addWidget(add_account_widget)

        self.authenticator_stack.setCurrentIndex(0)

        self.tabs.addTab(auth_tab, "Authenticator")

    def generate_password(self):
        password = secrets.token_urlsafe(16)
        self.password_entry.setText(password)

    def add_entry(self):
        website = self.website_entry.text()
        username = self.username_entry.text()
        password = self.password_entry.text()

        if website and username and password:
            try:
                self.password_manager.add_password(website, username, password)
                QMessageBox.information(self, "Success", "Entry added successfully!")
                self.website_entry.clear()
                self.username_entry.clear()
                self.password_entry.clear()
                self.refresh_password_list()
            except ValueError as e:
                QMessageBox.critical(self, "Error", f"Failed to add entry: {e}")
            except Exception as e:
                 QMessageBox.critical(self, "Error", f"An unexpected error occurred: {e}")
        else:
            QMessageBox.warning(self, "Error", "Please fill in Website, Username, and Password fields!")

    def display_entry_details(self):
        self.totp_timer.stop()
        selected_items = self.password_tree.selectedItems()
        if selected_items:
            item = selected_items[0]
            self.currently_selected_index = self.password_tree.indexOfTopLevelItem(item)
            entry = self.password_manager.get_password(self.currently_selected_index)
            
            self.details_website_label.setText(entry.get('website', '-'))
            self.details_username_label.setText(entry.get('username', '-'))
            self.details_password_label.setText("********")
            self.details_password_label.setProperty("password_hidden", True)
            self.details_password_label.setProperty("actual_password", entry.get('password', ''))
            
            if entry.get("totp_secret"):
                self.update_selected_totp_display()
                self.totp_timer.start(1000)
            else:
                self.details_totp_code_label.setText("-")
                self.details_totp_progressbar.setText("")
        else:
            self.currently_selected_index = -1
            self.details_website_label.setText("-")
            self.details_username_label.setText("-")
            self.details_password_label.setText("-")
            self.details_password_label.setProperty("password_hidden", True)
            self.details_password_label.setProperty("actual_password", "")
            self.details_totp_code_label.setText("-")
            self.details_totp_progressbar.setText("")

    def update_selected_totp_display(self):
         if self.currently_selected_index != -1:
             code = self.password_manager.generate_totp_code(self.currently_selected_index)
             if code:
                self.details_totp_code_label.setText(code)
                try:
                    secret = self.password_manager.get_password(self.currently_selected_index).get("totp_secret")
                    totp = pyotp.TOTP(secret)
                    remaining = totp.interval - (time.time() % totp.interval)
                    progress = int((remaining / totp.interval) * 10)
                    self.details_totp_progressbar.setText(f"[{'#' * progress}{'.' * (10 - progress)}] {int(remaining)}s")
                except Exception:
                     self.details_totp_progressbar.setText("[----------]")
             else:
                 self.details_totp_code_label.setText("-")
                 self.details_totp_progressbar.setText("")
         else:
             self.totp_timer.stop()

    def toggle_view_password(self):
        if self.currently_selected_index != -1:
            is_hidden = self.details_password_label.property("password_hidden")
            actual_password = self.details_password_label.property("actual_password")
            if is_hidden:
                self.details_password_label.setText(actual_password)
                self.details_password_label.setProperty("password_hidden", False)
            else:
                self.details_password_label.setText("********")
                self.details_password_label.setProperty("password_hidden", True)
        else:
             QMessageBox.warning(self, "Error", "Please select an entry first!")

    def delete_selected_entry(self):
        if self.currently_selected_index != -1:
            reply = QMessageBox.question(self, 'Confirm Delete', 
                                       f"Are you sure you want to delete the entry for '{self.details_website_label.text()}'?",
                                       QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, 
                                       QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                self.password_manager.delete_password(self.currently_selected_index)
                self.refresh_password_list()
                self.display_entry_details()
                QMessageBox.information(self, "Success", "Entry deleted successfully!")
        else:
            QMessageBox.warning(self, "Error", "Please select an entry to delete!")

    def refresh_password_list(self):
        self.password_tree.clear()
        for password in self.password_manager.get_all_passwords():
            item = QTreeWidgetItem([password["website"], password["username"]])
            self.password_tree.addTopLevelItem(item)

    def add_totp_account_gui(self):
        name = self.totp_account_name_entry.text().strip()
        secret = self.totp_secret_key_entry.text().strip()
        
        if not name or not secret:
             QMessageBox.warning(self, "Input Error", "Please enter both an account name and the secret key.")
             return
             
        try:
             self.password_manager.add_totp_account(name, secret)
             QMessageBox.information(self, "Success", f"Authenticator account '{name}' added successfully!")
             self.totp_account_name_entry.clear()
             self.totp_secret_key_entry.clear()
             self.refresh_totp_list()
             self.authenticator_stack.setCurrentIndex(0)
        except ValueError as e:
             QMessageBox.critical(self, "Error", f"Failed to add account: {e}")
        except Exception as e:
             QMessageBox.critical(self, "Error", f"An unexpected error occurred: {e}")
             
    def refresh_totp_list(self):
         selected_row = self.totp_account_list.currentRow()
         self.totp_account_list.clear()
         accounts = self.password_manager.get_all_totp_accounts()
         for account in accounts:
              self.totp_account_list.addItem(QListWidgetItem(account["name"]))
         if 0 <= selected_row < self.totp_account_list.count():
             self.totp_account_list.setCurrentRow(selected_row)
         else:
              self.display_totp_details()
              
    def display_totp_details(self):
         self.totp_timer.stop()
         selected_items = self.totp_account_list.selectedItems()
         if selected_items:
              self.currently_selected_totp_index = self.totp_account_list.currentRow()
              account = self.password_manager.get_totp_account(self.currently_selected_totp_index)
              self.totp_details_name_label.setText(f"<b>{account.get('name', '-')}</b>")
              self.update_authenticator_display()
              self.totp_timer.start(1000)
         else:
              self.currently_selected_totp_index = -1
              self.totp_details_name_label.setText("<i>Select an account</i>")
              self.totp_details_code_label.setText("-")
              self.totp_details_progressbar.setText("")
              
    def update_authenticator_display(self):
         if self.currently_selected_totp_index != -1:
             code = self.password_manager.generate_totp_code(self.currently_selected_totp_index)
             if code:
                 self.totp_details_code_label.setText(code)
                 try:
                     secret = self.password_manager.get_totp_account(self.currently_selected_totp_index).get("secret")
                     totp = pyotp.TOTP(secret)
                     remaining = totp.interval - (time.time() % totp.interval)
                     progress = int((remaining / totp.interval) * 10)
                     self.totp_details_progressbar.setText(f"[{'#' * progress}{'.' * (10 - progress)}] {int(remaining)}s")
                 except Exception:
                     self.totp_details_progressbar.setText("[----------]")
             else:
                 self.totp_details_code_label.setText("Error")
                 self.totp_details_progressbar.setText("")
         else:
             self.totp_timer.stop()
             self.display_totp_details()

    def delete_selected_totp_account(self):
         if self.currently_selected_totp_index != -1:
             account = self.password_manager.get_totp_account(self.currently_selected_totp_index)
             reply = QMessageBox.question(self, 'Confirm Delete', 
                                        f"Are you sure you want to delete the authenticator account for '{account.get('name')}'?",
                                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, 
                                        QMessageBox.StandardButton.No)
             if reply == QMessageBox.StandardButton.Yes:
                 self.password_manager.delete_totp_account(self.currently_selected_totp_index)
                 self.refresh_totp_list()
                 QMessageBox.information(self, "Success", "Authenticator account deleted successfully!")
         else:
             QMessageBox.warning(self, "Error", "Please select an authenticator account to delete!")

    def scan_totp_qr_code(self):
        cap = cv2.VideoCapture(0)
        
        if not cap.isOpened():
            QMessageBox.critical(self, "Camera Error", "Could not open webcam.")
            return

        scanned_data = None
        scan_window_name = "Scan TOTP QR Code - Press 'Q' to Quit"

        while True:
            ret, frame = cap.read()
            if not ret:
                QMessageBox.warning(self, "Camera Error", "Failed to capture frame from webcam.")
                break

            qrcodes = pyzbar.decode(frame)
            found = False
            for qr in qrcodes:
                qr_data = qr.data.decode('utf-8')
                
                if qr_data.startswith('otpauth://totp/'):
                    scanned_data = qr_data
                    found = True
                    (x, y, w, h) = qr.rect
                    cv2.rectangle(frame, (x, y), (x + w, y + h), (0, 255, 0), 2)
                    cv2.putText(frame, "OTP QR Found! Press Q", (x, y - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 0), 2)
                    break
            
            cv2.imshow(scan_window_name, frame)

            key = cv2.waitKey(1) & 0xFF
            if key == ord('q') or found:
                break
                
        cap.release()
        cv2.destroyWindow(scan_window_name)
        cv2.waitKey(1)
        cv2.waitKey(1)
        cv2.waitKey(1)
        cv2.waitKey(1)

        if scanned_data:
            self.parse_otpauth_uri(scanned_data)
        else:
            QMessageBox.information(self, "Scan Cancelled", "QR code scanning cancelled or no valid code found.")
            
    def parse_otpauth_uri(self, uri):
        try:
            parsed_uri = urllib.parse.urlparse(uri)
            params = urllib.parse.parse_qs(parsed_uri.query)
            
            secret = params.get('secret', [None])[0]
            if not secret:
                raise ValueError("Secret parameter not found in URI")

            path_parts = parsed_uri.path.strip('/').split(':', 1)
            account_label = urllib.parse.unquote(path_parts[-1]) # Decode URL encoding
            issuer = params.get('issuer', [None])[0]
            if issuer:
                 issuer = urllib.parse.unquote(issuer) # Decode issuer
            
            suggested_name = account_label
            if issuer and issuer.lower() not in account_label.lower(): # Case-insensitive check
                 suggested_name = f"{issuer} ({account_label})"
                 
            # --- Auto-add the account --- 
            try:
                 self.password_manager.add_totp_account(suggested_name, secret)
                 QMessageBox.information(self, "Scan Successful", f"Account '{suggested_name}' added successfully!")
                 self.refresh_totp_list()
                 # Switch back to the code view after successful add
                 self.authenticator_stack.setCurrentIndex(0) 
                 # Clear fields for next time (optional, but good practice)
                 self.totp_account_name_entry.clear()
                 self.totp_secret_key_entry.clear()
            except ValueError as e:
                 # Handle errors during add (e.g., duplicate name)
                 QMessageBox.critical(self, "Add Account Error", f"Could not add scanned account: {e}")
                 # Keep fields populated to allow user to fix name and add manually
                 self.totp_account_name_entry.setText(suggested_name)
                 self.totp_secret_key_entry.setText(secret)
            except Exception as e:
                 QMessageBox.critical(self, "Add Account Error", f"An unexpected error occurred while adding the account: {e}")
                 self.totp_account_name_entry.clear()
                 self.totp_secret_key_entry.clear()
            # --- End Auto-add ---
            
        except Exception as e:
            QMessageBox.critical(self, "URI Parse Error", f"Could not parse the scanned QR code URI: {e}\nURI: {uri}")
            # Clear fields on parse error
            self.totp_secret_key_entry.setText("")
            self.totp_account_name_entry.setText("")

    def run(self):
        master_password, ok = QInputDialog.getText(self, "Master Password", "Enter your master password:", QLineEdit.EchoMode.Password)
        if ok and master_password:
            if self.password_manager.verify_master_password(master_password):
                 self.refresh_password_list()
                 self.refresh_totp_list()
                 self.show()
            else:
                 sys.exit()
        else:
             QMessageBox.warning(self, "Cancelled", "Master password entry cancelled.")
             sys.exit()

if __name__ == "__main__":
    # Environment variable is set before QApplication is created
    app = QApplication(sys.argv)
    ModernStyle.set_style(app)
    password_manager_gui = PasswordManagerGUI()
    password_manager_gui.run()
    sys.exit(app.exec())
