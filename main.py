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
                             QStackedWidget, QSpacerItem, QSizePolicy, 
                             QProgressBar, QMenu, 
                             QDialog, QDialogButtonBox, QFileDialog)
from PyQt6.QtCore import Qt, QTimer, QSettings, QSize, QPoint
from PyQt6.QtGui import QPalette, QColor, QAction, QIcon
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
import pyperclip
import shutil

# App details for QSettings
ORG_NAME = "V8V88V8V88"
APP_NAME = "Passvyn: PasswordManager"

# Define icon paths (relative to main.py)
ICON_DIR = "icons"
ICON_ADD = os.path.join(ICON_DIR, "plus-circle.svg")
ICON_DELETE = os.path.join(ICON_DIR, "trash-2.svg")
ICON_COPY = os.path.join(ICON_DIR, "copy.svg")
ICON_SHOW = os.path.join(ICON_DIR, "eye.svg")
ICON_HIDE = os.path.join(ICON_DIR, "eye-off.svg")
ICON_SCAN = os.path.join(ICON_DIR, "camera.svg")
ICON_GENERATE = os.path.join(ICON_DIR, "refresh-cw.svg")
ICON_OK = os.path.join(ICON_DIR, "check.svg")
ICON_CANCEL = os.path.join(ICON_DIR, "x.svg")
ICON_TAB_ADD = os.path.join(ICON_DIR, "file-plus.svg")
ICON_TAB_VIEW = os.path.join(ICON_DIR, "list.svg")
ICON_TAB_AUTH = os.path.join(ICON_DIR, "shield.svg")
ICON_LOCK = os.path.join(ICON_DIR, "lock.svg")
# New Menu Icons
ICON_MENU = os.path.join(ICON_DIR, "menu.svg")
ICON_ABOUT = os.path.join(ICON_DIR, "info.svg")
ICON_BACKUP = os.path.join(ICON_DIR, "download.svg")
ICON_RESTORE = os.path.join(ICON_DIR, "upload.svg")
ICON_SETTINGS = os.path.join(ICON_DIR, "settings.svg")

class ModernStyle:
    # Define colors as class attributes
    COLOR_WINDOW_BG = QColor("#1e1e1e")      
    COLOR_BASE_BG = QColor("#2a2a2a")        
    COLOR_ALT_BASE_BG = QColor("#333333")  
    COLOR_BUTTON_BG = QColor("#3a3a3a")      
    COLOR_HIGHLIGHT = QColor("#0A84FF")      
    COLOR_HIGHLIGHT_TEXT = Qt.GlobalColor.white # This one is an enum, used differently
    COLOR_TEXT = QColor("#e0e0e0")           
    COLOR_TEXT_DIM = QColor("#a0a0a0")       
    COLOR_BORDER = QColor("#484848")         
    
    @staticmethod
    def set_style(app):
        app.setStyle(QStyleFactory.create("Fusion"))
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, ModernStyle.COLOR_WINDOW_BG)
        palette.setColor(QPalette.ColorRole.WindowText, ModernStyle.COLOR_TEXT)
        palette.setColor(QPalette.ColorRole.Base, ModernStyle.COLOR_BASE_BG)
        palette.setColor(QPalette.ColorRole.AlternateBase, ModernStyle.COLOR_ALT_BASE_BG)
        palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(255, 255, 220))
        palette.setColor(QPalette.ColorRole.ToolTipText, QColor(0, 0, 0))
        palette.setColor(QPalette.ColorRole.Text, ModernStyle.COLOR_TEXT)
        palette.setColor(QPalette.ColorRole.Button, ModernStyle.COLOR_BUTTON_BG)
        palette.setColor(QPalette.ColorRole.ButtonText, ModernStyle.COLOR_TEXT)
        palette.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
        palette.setColor(QPalette.ColorRole.Link, ModernStyle.COLOR_HIGHLIGHT)
        palette.setColor(QPalette.ColorRole.Highlight, ModernStyle.COLOR_HIGHLIGHT)
        # Use the enum directly for HighlightedText
        palette.setColor(QPalette.ColorRole.HighlightedText, ModernStyle.COLOR_HIGHLIGHT_TEXT)
        app.setPalette(palette)
        
        # Enhanced Stylesheet - Use class attributes directly
        app.setStyleSheet(f"""
            QWidget {{ 
                /* font-size: 10pt; */ 
                color: {ModernStyle.COLOR_TEXT.name()};
            }}
            QMainWindow, QDialog {{ 
                 background-color: {ModernStyle.COLOR_WINDOW_BG.name()}; 
            }}
            QTabWidget::pane {{ 
                border: 1px solid {ModernStyle.COLOR_BORDER.name()}; 
                border-top: none; 
                border-radius: 0px; 
                border-bottom-left-radius: 6px;
                border-bottom-right-radius: 6px;
                padding: 18px;
                background-color: {ModernStyle.COLOR_BASE_BG.name()}; 
            }}
            QTabBar::tab {{
                background-color: {ModernStyle.COLOR_BUTTON_BG.name()};
                color: {ModernStyle.COLOR_TEXT_DIM.name()}; 
                padding: 10px 25px;
                border-top-left-radius: 6px; 
                border-top-right-radius: 6px;
                border: 1px solid {ModernStyle.COLOR_BORDER.name()};
                border-bottom: none; 
                margin-right: 1px;
            }}
            QTabBar::tab:selected {{
                background-color: {ModernStyle.COLOR_BASE_BG.name()}; 
                color: {ModernStyle.COLOR_TEXT.name()};
                font-weight: bold;
                margin-bottom: -1px; 
            }}
            QTabBar::tab:hover {{
                background-color: {ModernStyle.COLOR_ALT_BASE_BG.name()};
                color: white;
            }}
            QPushButton#PrimaryButton, QPushButton[primary="true"] {{
                background-color: {ModernStyle.COLOR_HIGHLIGHT.name()};
                color: white;
                font-weight: bold;
            }}
            QPushButton#PrimaryButton:hover, QPushButton[primary="true"]:hover {{
                background-color: {ModernStyle.COLOR_HIGHLIGHT.lighter(120).name()};
            }}
            QPushButton#PrimaryButton:pressed, QPushButton[primary="true"]:pressed {{
                background-color: {ModernStyle.COLOR_HIGHLIGHT.darker(120).name()};
            }}
            QPushButton {{
                background-color: {ModernStyle.COLOR_BUTTON_BG.name()};
                color: {ModernStyle.COLOR_TEXT.name()};
                border: 1px solid {ModernStyle.COLOR_BORDER.name()};
                padding: 8px 15px; 
                border-radius: 5px;
                min-height: 20px;
            }}
            QPushButton:hover {{
                background-color: {ModernStyle.COLOR_ALT_BASE_BG.name()};
                border-color: {ModernStyle.COLOR_TEXT_DIM.name()};
            }}
            QPushButton:pressed {{
                background-color: {ModernStyle.COLOR_BASE_BG.name()};
            }}
            QPushButton#DeleteButton {{
                 background-color: {ModernStyle.COLOR_BUTTON_BG.name()};
                 color: #f77; 
                 border: 1px solid #733;
            }}
            QPushButton#DeleteButton:hover {{ background-color: #533; border-color: #944; }}
            QPushButton#DeleteButton:pressed {{ background-color: #422; }}
             QPushButton#ScanButton {{
                 background-color: #28a745; 
                 color: white;
                 border: none;
                 font-weight: bold;
            }}
            QPushButton#ScanButton:hover {{ background-color: #2fbf50; }}
            QPushButton#ScanButton:pressed {{ background-color: #1e8735; }}
             QPushButton[icon-button="true"] {{
                 background-color: transparent;
                 border: none;
                 padding: 4px;
                 border-radius: 4px;
                 min-width: 28px; 
                 max-width: 28px;
                 min-height: 28px;
                 max-height: 28px;
             }}
             QPushButton[icon-button="true"]:hover {{
                 background-color: {ModernStyle.COLOR_ALT_BASE_BG.name()};
             }}
             QPushButton[icon-button="true"]:pressed {{
                 background-color: {ModernStyle.COLOR_BASE_BG.name()};
             }}
            QLineEdit {{
                padding: 9px;
                border: 1px solid {ModernStyle.COLOR_BORDER.name()};
                border-radius: 5px;
                background-color: {ModernStyle.COLOR_WINDOW_BG.name()}; 
                color: {ModernStyle.COLOR_TEXT.name()};
            }}
            QGroupBox {{
                 background-color: {ModernStyle.COLOR_ALT_BASE_BG.name()};
                 border: 1px solid {ModernStyle.COLOR_BORDER.name()};
                 border-radius: 6px;
                 margin-top: 1ex;
                 padding: 18px;
                 padding-top: 25px;
            }}
            QGroupBox::title {{
                 subcontrol-origin: margin;
                 subcontrol-position: top left; 
                 padding: 4px 10px;
                 left: 15px; 
                 color: {ModernStyle.COLOR_TEXT.name()};
                 background-color: transparent; 
                 font-weight: bold;
                 border: none;
            }}
            QTreeWidget, QListWidget {{
                border: 1px solid {ModernStyle.COLOR_BORDER.name()};
                border-radius: 5px;
                background-color: {ModernStyle.COLOR_BASE_BG.name()};
                padding: 5px;
                alternate-background-color: {ModernStyle.COLOR_ALT_BASE_BG.darker(110).name()}; 
            }}
            QTreeWidget::item, QListWidget::item {{
                 padding: 6px; 
                 border-radius: 4px; 
                 color: {ModernStyle.COLOR_TEXT_DIM.name()};
            }}
            QTreeWidget::item:selected, QListWidget::item:selected {{
                 background-color: {ModernStyle.COLOR_HIGHLIGHT.name()}; 
                 color: white; 
            }}
            QLabel {{
                 background-color: transparent; 
                 padding: 2px; 
                 color: {ModernStyle.COLOR_TEXT_DIM.name()}; 
            }}
            QLabel#CodeLabel {{
                 color: {ModernStyle.COLOR_TEXT.name()}; 
                 font-size: 30pt; 
                 font-weight: bold; 
                 margin-right: 5px; 
            }}
            QLabel#CodeLabel[expiring="true"] {{ 
                 color: #f39c12; 
            }}
            QProgressBar {{
                 border: none; 
                 border-radius: 5px;
                 text-align: center;
                 background-color: {ModernStyle.COLOR_BASE_BG.name()};
                 height: 6px; 
            }}
            QProgressBar::chunk {{
                 background-color: {ModernStyle.COLOR_HIGHLIGHT.name()}; 
                 border-radius: 3px;
            }}
            QStatusBar {{ 
                background-color: {ModernStyle.COLOR_WINDOW_BG.name()};
                border-top: 1px solid {ModernStyle.COLOR_BORDER.name()};
                color: {ModernStyle.COLOR_TEXT_DIM.name()};
                font-size: 9pt;
             }}
            QStatusBar::item {{ border: none; }}
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

# --- Custom Master Password Dialog ---
class MasterPasswordDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Master Password Required")
        self.setWindowIcon(QIcon(ICON_LOCK)) # Use the lock icon
        self.setMinimumWidth(350)

        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        self.label = QLabel("Enter your master password:")
        layout.addWidget(self.label)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.password_input)

        # Standard buttons with custom icons
        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        ok_button = button_box.button(QDialogButtonBox.StandardButton.Ok)
        cancel_button = button_box.button(QDialogButtonBox.StandardButton.Cancel)
        
        if ok_button: # Check if button exists
             ok_button.setIcon(QIcon(ICON_OK))
             ok_button.setText(" Unlock") # Add space for icon
        if cancel_button:
             cancel_button.setIcon(QIcon(ICON_CANCEL))
             cancel_button.setText(" Cancel")
             
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
        # Focus the input field initially
        self.password_input.setFocus()

    def getPassword(self):
        # Return entered text if dialog was accepted
        return self.password_input.text()

# --- Add TOTP Account Dialog ---
class AddTotpAccountDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Authenticator Account")
        self.setMinimumWidth(450)
        self.new_account_details = None
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        scan_group = QGroupBox("Scan QR Code")
        scan_layout = QVBoxLayout(scan_group)
        scan_qr_button = QPushButton(QIcon(ICON_SCAN), " Scan QR Code Now") 
        scan_qr_button.setObjectName("ScanButton") 
        scan_qr_button.setStyleSheet("padding: 12px;") 
        scan_qr_button.setToolTip("Open camera to scan the TOTP QR code")
        scan_qr_button.clicked.connect(self.scan_qr_code_internal)
        scan_layout.addWidget(scan_qr_button)
        layout.addWidget(scan_group)
        manual_group = QGroupBox("Or Enter Manually")
        manual_layout = QGridLayout(manual_group)
        manual_layout.setSpacing(10)
        manual_layout.addWidget(QLabel("Account Name:"), 0, 0)
        self.account_name_entry = QLineEdit()
        self.account_name_entry.setPlaceholderText("e.g., Google (myemail@...)")
        manual_layout.addWidget(self.account_name_entry, 0, 1)
        manual_layout.addWidget(QLabel("Secret Key (Base32):"), 1, 0)
        self.secret_key_entry = QLineEdit()
        self.secret_key_entry.setPlaceholderText("Paste Base32 secret")
        manual_layout.addWidget(self.secret_key_entry, 1, 1)
        layout.addWidget(manual_group)
        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.button(QDialogButtonBox.StandardButton.Ok).setIcon(QIcon(ICON_OK))
        button_box.button(QDialogButtonBox.StandardButton.Cancel).setIcon(QIcon(ICON_CANCEL))
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def scan_qr_code_internal(self):
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            QMessageBox.critical(self, "Camera Error", "Could not open webcam.")
            return
        scanned_data = None
        scan_window_name = "Scan TOTP QR Code - Press 'Q' to Quit"
        while True:
            ret, frame = cap.read()
            if not ret: break
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
            if key == ord('q') or found: break
        cap.release()
        cv2.destroyWindow(scan_window_name)
        cv2.waitKey(1); cv2.waitKey(1); cv2.waitKey(1); cv2.waitKey(1)

        if scanned_data:
            self.parse_otpauth_uri_internal(scanned_data)
        # No message if cancelled, user just returns to dialog
            
    def parse_otpauth_uri_internal(self, uri):
        try:
            parsed_uri = urllib.parse.urlparse(uri)
            params = urllib.parse.parse_qs(parsed_uri.query)
            secret = params.get('secret', [None])[0]
            if not secret: raise ValueError("Secret parameter not found")
            path_parts = parsed_uri.path.strip('/').split(':', 1)
            account_label = urllib.parse.unquote(path_parts[-1])
            issuer = params.get('issuer', [None])[0]
            if issuer: issuer = urllib.parse.unquote(issuer)
            suggested_name = account_label
            if issuer and issuer.lower() not in account_label.lower():
                 suggested_name = f"{issuer} ({account_label})"
            self.account_name_entry.setText(suggested_name)
            self.secret_key_entry.setText(secret)
            QMessageBox.information(self, "Scan Successful", "Account details populated. Verify and click OK.")
        except Exception as e:
            QMessageBox.critical(self, "URI Parse Error", f"Could not parse QR code: {e}")
            self.secret_key_entry.clear()
            self.account_name_entry.clear()

    # Override accept to store data before closing
    def accept(self):
        name = self.account_name_entry.text().strip()
        secret = self.secret_key_entry.text().strip()
        if not name or not secret:
            QMessageBox.warning(self, "Input Error", "Account name and secret key are required.")
            return # Don't close dialog
        
        # Store details for the main window to retrieve
        self.new_account_details = {"name": name, "secret": secret}
        super().accept() # Close dialog with Accepted state

    def get_new_account_details(self):
        return self.new_account_details

class PasswordManagerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowIcon(QIcon(ICON_LOCK))
        self.password_manager = SecuredPasswordManager()
        self.password_manager.load_config()
        self.totp_timer = QTimer(self)
        self.totp_timer.timeout.connect(self.update_authenticator_display)
        self.currently_selected_totp_index = -1
        self.currently_selected_index = -1
        self.init_ui()
        self.load_settings()

    def init_ui(self):
        self.setWindowTitle("Passvyn - Secured Password Manager")
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready") 

        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_v_layout = QVBoxLayout(main_widget)
        main_v_layout.setContentsMargins(10, 10, 10, 10) # Add margins back to main layout
        main_v_layout.setSpacing(10)

        # --- Tab Widget --- 
        self.tabs = QTabWidget()
        main_v_layout.addWidget(self.tabs)

        # --- Create and Add Menu Button to Tab Bar Corner --- 
        self.menu_button = QPushButton(QIcon(ICON_MENU), "")
        self.menu_button.setProperty("icon-button", True) # Use icon-button style
        self.menu_button.setToolTip("Menu")
        # Make button flat/transparent background to blend with tab bar corner
        self.menu_button.setFlat(True) 
        self.menu_button.setStyleSheet("QPushButton { border: none; padding: 5px; } QPushButton:hover { background-color: #555; }") # Minimal style
        self.menu_button.clicked.connect(self.show_main_menu)
        # Add button to the corner, aligned right
        self.tabs.setCornerWidget(self.menu_button, Qt.Corner.TopRightCorner)
        
        # --- Add Entry Tab --- 
        add_tab = QWidget()
        add_layout = QVBoxLayout(add_tab)
        add_layout.setSpacing(15)

        add_form_layout = QGridLayout()
        add_form_layout.setSpacing(12)
        add_form_layout.addWidget(QLabel("Website:"), 0, 0)
        self.website_entry = QLineEdit()
        add_form_layout.addWidget(self.website_entry, 0, 1)

        add_form_layout.addWidget(QLabel("Username:"), 1, 0)
        self.username_entry = QLineEdit()
        add_form_layout.addWidget(self.username_entry, 1, 1)

        add_form_layout.addWidget(QLabel("Password:"), 2, 0)
        self.password_entry = QLineEdit()
        self.password_entry.setEchoMode(QLineEdit.EchoMode.Password)
        add_form_layout.addWidget(self.password_entry, 2, 1)
        add_layout.addLayout(add_form_layout)

        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)
        button_layout.addStretch(1)
        generate_button = QPushButton(QIcon(ICON_GENERATE), " Generate Password")
        generate_button.setToolTip("Generate a strong random password")
        generate_button.clicked.connect(self.generate_password)
        button_layout.addWidget(generate_button)
        add_button = QPushButton(QIcon(ICON_ADD), " Add Entry")
        add_button.setProperty("primary", True)
        add_button.setToolTip("Save this password entry")
        add_button.clicked.connect(self.add_entry)
        button_layout.addWidget(add_button)
        add_layout.addLayout(button_layout)
        add_layout.addStretch(1)
        self.tabs.addTab(add_tab, QIcon(ICON_TAB_ADD), "Add Entry")

        # --- View Entries Tab --- 
        view_tab = QWidget()
        view_layout = QVBoxLayout(view_tab)
        view_layout.setSpacing(15)

        self.password_tree = QTreeWidget()
        self.password_tree.setHeaderLabels(["Website", "Username"])
        self.password_tree.itemSelectionChanged.connect(self.display_entry_details)
        self.password_tree.setAlternatingRowColors(True)
        view_layout.addWidget(self.password_tree, 1)
        
        self.details_group = QGroupBox("Selected Entry Details")
        details_layout = QGridLayout(self.details_group)
        details_layout.setSpacing(10)

        details_layout.addWidget(QLabel("Website:"), 0, 0)
        self.details_website_label = QLabel("-")
        details_layout.addWidget(self.details_website_label, 0, 1, 1, 2)

        details_layout.addWidget(QLabel("Username:"), 1, 0)
        self.details_username_label = QLabel("-")
        self.details_username_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        details_layout.addWidget(self.details_username_label, 1, 1)
        self.copy_username_button = QPushButton(QIcon(ICON_COPY), "")
        self.copy_username_button.setProperty("icon-button", True)
        self.copy_username_button.setToolTip("Copy Username")
        self.copy_username_button.clicked.connect(lambda: self.copy_to_clipboard(self.details_username_label.text()))
        details_layout.addWidget(self.copy_username_button, 1, 2)

        details_layout.addWidget(QLabel("Password:"), 2, 0)
        password_layout = QHBoxLayout()
        password_layout.setSpacing(5)
        self.details_password_label = QLineEdit("********")
        self.details_password_label.setReadOnly(True)
        self.details_password_label.setEchoMode(QLineEdit.EchoMode.Password)
        self.details_password_label.setStyleSheet("background-color: transparent; border: none; padding: 0px;")
        self.details_password_label.setProperty("password_hidden", True)
        self.details_password_label.setProperty("actual_password", "")
        password_layout.addWidget(self.details_password_label, 1)
        self.toggle_pass_button = QPushButton(QIcon(ICON_SHOW), "")
        self.toggle_pass_button.setProperty("icon-button", True)
        self.toggle_pass_button.setToolTip("Show Password")
        self.toggle_pass_button.setCheckable(True)
        self.toggle_pass_button.toggled.connect(self.toggle_view_password)
        password_layout.addWidget(self.toggle_pass_button)
        self.copy_password_button = QPushButton(QIcon(ICON_COPY), "")
        self.copy_password_button.setProperty("icon-button", True)
        self.copy_password_button.setToolTip("Copy Password")
        self.copy_password_button.clicked.connect(lambda: self.copy_to_clipboard(self.details_password_label.property("actual_password")))
        self.copy_password_button.setEnabled(False)
        password_layout.addWidget(self.copy_password_button)
        details_layout.addLayout(password_layout, 2, 1, 1, 2)

        view_layout.addWidget(self.details_group)
        view_layout.setStretchFactor(self.password_tree, 3)
        view_layout.setStretchFactor(self.details_group, 1)

        view_button_layout = QHBoxLayout()
        view_button_layout.addStretch(1)
        delete_button = QPushButton(QIcon(ICON_DELETE), " Delete Entry")
        delete_button.setObjectName("DeleteButton")
        delete_button.setToolTip("Delete the selected password entry")
        delete_button.clicked.connect(self.delete_selected_entry)
        view_button_layout.addWidget(delete_button)
        view_layout.addLayout(view_button_layout)

        self.tabs.addTab(view_tab, QIcon(ICON_TAB_VIEW), "View Entries")

        # --- Authenticator Tab --- 
        auth_tab = QWidget()
        auth_tab_layout = QHBoxLayout(auth_tab)
        auth_tab_layout.setSpacing(15)

        view_codes_left_pane = QVBoxLayout()
        view_codes_left_pane.setSpacing(10)
        view_codes_left_pane.addWidget(QLabel("Authenticator Accounts:"))
        self.totp_account_list = QListWidget()
        self.totp_account_list.itemSelectionChanged.connect(self.display_totp_details)
        self.totp_account_list.setAlternatingRowColors(True)
        view_codes_left_pane.addWidget(self.totp_account_list, 1)

        add_new_account_button = QPushButton(QIcon(ICON_ADD), " Add Account...")
        add_new_account_button.setToolTip("Add a new account for TOTP code generation")
        add_new_account_button.clicked.connect(self.open_add_totp_dialog)
        view_codes_left_pane.addWidget(add_new_account_button)

        view_codes_right_pane = QVBoxLayout()
        self.totp_details_group = QGroupBox("Current Code")
        totp_details_layout = QVBoxLayout(self.totp_details_group)
        totp_details_layout.setSpacing(10)
        self.totp_details_name_label = QLabel("<i>Select an account</i>")
        self.totp_details_name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        totp_details_layout.addWidget(self.totp_details_name_label)
        code_layout = QHBoxLayout()
        code_layout.addStretch(1)
        self.totp_details_code_label = QLabel("-")
        self.totp_details_code_label.setObjectName("CodeLabel")
        self.totp_details_code_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.totp_details_code_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.TextBrowserInteraction)
        self.totp_details_code_label.mousePressEvent = self.copy_current_totp_code
        self.totp_details_code_label.setToolTip("Click code to copy")
        code_layout.addWidget(self.totp_details_code_label)
        copy_totp_button = QPushButton(QIcon(ICON_COPY), "")
        copy_totp_button.setProperty("icon-button", True)
        copy_totp_button.setToolTip("Copy Code")
        copy_totp_button.clicked.connect(self.copy_current_totp_code)
        code_layout.addWidget(copy_totp_button)
        code_layout.addStretch(1)
        totp_details_layout.addLayout(code_layout)
        self.totp_progressbar = QProgressBar()
        self.totp_progressbar.setRange(0, 300)
        self.totp_progressbar.setValue(0)
        self.totp_progressbar.setTextVisible(False)
        self.totp_progressbar.setFixedHeight(6)
        totp_details_layout.addWidget(self.totp_progressbar)
        self.totp_seconds_label = QLabel("")
        self.totp_seconds_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.totp_seconds_label.setStyleSheet("font-size: 9pt; color: #a0a0a0;")
        totp_details_layout.addWidget(self.totp_seconds_label)
        totp_details_layout.addStretch(1)
        delete_totp_button = QPushButton(QIcon(ICON_DELETE), " Delete Account")
        delete_totp_button.setObjectName("DeleteButton")
        delete_totp_button.setToolTip("Delete the selected authenticator account")
        delete_totp_button.clicked.connect(self.delete_selected_totp_account)
        totp_details_layout.addWidget(delete_totp_button)
        view_codes_right_pane.addWidget(self.totp_details_group)
        view_codes_right_pane.addStretch()
        
        auth_tab_layout.addLayout(view_codes_left_pane, 1) 
        auth_tab_layout.addLayout(view_codes_right_pane, 1)

        self.tabs.addTab(auth_tab, QIcon(ICON_TAB_AUTH), "Authenticator")

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
        selected_items = self.password_tree.selectedItems()
        if selected_items:
            item = selected_items[0]
            try:
                 index = self.password_tree.indexOfTopLevelItem(item)
                 if index < 0 or index >= len(self.password_manager.passwords):
                     self.clear_entry_details()
                     return
                 self.currently_selected_index = index
                 entry = self.password_manager.get_password(self.currently_selected_index)
                 
                 self.details_website_label.setText(entry.get('website', '-'))
                 self.details_username_label.setText(entry.get('username', '-'))
                 self.details_password_label.setText("********")
                 self.details_password_label.setProperty("password_hidden", True)
                 self.details_password_label.setProperty("actual_password", entry.get('password', ''))
                 self.toggle_pass_button.setChecked(False)
                 self.copy_password_button.setEnabled(False)
                 self.copy_username_button.setEnabled(bool(entry.get('username')))
            except Exception as e:
                 print(f"Error displaying entry details: {e}")
                 self.clear_entry_details()
        else:
            self.clear_entry_details()

    def clear_entry_details(self):
        self.currently_selected_index = -1
        self.details_website_label.setText("-")
        self.details_username_label.setText("-")
        self.details_password_label.setText("-")
        self.details_password_label.setProperty("password_hidden", True)
        self.details_password_label.setProperty("actual_password", "")
        self.toggle_pass_button.setChecked(False)
        self.copy_password_button.setEnabled(False)
        self.copy_username_button.setEnabled(False)

    def toggle_view_password(self, checked):
        if self.currently_selected_index != -1:
            actual_password = self.details_password_label.property("actual_password")
            if checked:
                self.details_password_label.setEchoMode(QLineEdit.EchoMode.Normal)
                self.details_password_label.setText(actual_password)
                self.toggle_pass_button.setIcon(QIcon(ICON_HIDE))
                self.toggle_pass_button.setToolTip("Hide Password")
                self.copy_password_button.setEnabled(bool(actual_password))
            else:
                self.details_password_label.setEchoMode(QLineEdit.EchoMode.Password)
                self.details_password_label.setText("********")
                self.toggle_pass_button.setIcon(QIcon(ICON_SHOW))
                self.toggle_pass_button.setToolTip("Show Password")
                self.copy_password_button.setEnabled(False)
        else:
            self.toggle_pass_button.setChecked(False)
            self.toggle_pass_button.setIcon(QIcon(ICON_SHOW))
            self.copy_password_button.setEnabled(False)

    def delete_selected_entry(self):
        if self.currently_selected_index != -1:
            if self.currently_selected_index < len(self.password_manager.passwords):
                 entry_name = self.password_manager.get_password(self.currently_selected_index).get('website', 'this entry')
                 reply = QMessageBox.question(self, 'Confirm Delete', 
                                            f"Are you sure you want to delete the password entry for '{entry_name}'?",
                                            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, 
                                            QMessageBox.StandardButton.No)
                 if reply == QMessageBox.StandardButton.Yes:
                     try:
                         self.password_manager.delete_password(self.currently_selected_index)
                         self.refresh_password_list()
                         self.clear_entry_details()
                         QMessageBox.information(self, "Success", "Entry deleted successfully!")
                     except IndexError:
                          QMessageBox.warning(self, "Error", "Could not delete entry. Index out of range.")
                     except Exception as e:
                          QMessageBox.critical(self, "Error", f"Could not delete entry: {e}")
            else:
                 QMessageBox.warning(self, "Error", "Selection is invalid. Please re-select.")
                 self.clear_entry_details()
        else:
            QMessageBox.warning(self, "Error", "Please select an entry to delete!")

    def refresh_password_list(self):
        self.password_tree.clear()
        for password in self.password_manager.get_all_passwords():
            item = QTreeWidgetItem([password["website"], password["username"]])
            self.password_tree.addTopLevelItem(item)

    def open_add_totp_dialog(self):
        dialog = AddTotpAccountDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
             details = dialog.get_new_account_details()
             if details:
                  try:
                       self.password_manager.add_totp_account(details["name"], details["secret"])
                       QMessageBox.information(self, "Success", f"Authenticator account '{details['name']}' added successfully!")
                       self.refresh_totp_list()
                  except ValueError as e:
                       QMessageBox.critical(self, "Error", f"Failed to add account: {e}")
                  except Exception as e:
                       QMessageBox.critical(self, "Error", f"An unexpected error occurred: {e}")
        # No action needed if dialog is cancelled (Rejected)

    def display_totp_details(self):
         self.totp_timer.stop()
         selected_items = self.totp_account_list.selectedItems()
         if selected_items:
              try:
                  self.currently_selected_totp_index = self.totp_account_list.currentRow()
                  if self.currently_selected_totp_index < 0 or self.currently_selected_totp_index >= len(self.password_manager.totp_accounts):
                      self.clear_totp_details()
                      return
                      
                  account = self.password_manager.get_totp_account(self.currently_selected_totp_index)
                  self.totp_details_name_label.setText(f"<b>{account.get('name', '-')}</b>")
                  self.update_authenticator_display()
                  self.totp_timer.start(500)
              except Exception as e:
                   print(f"Error displaying TOTP details: {e}")
                   self.clear_totp_details()
         else:
             self.clear_totp_details()

    def clear_totp_details(self):
        self.currently_selected_totp_index = -1
        self.totp_details_name_label.setText("<i>Select an account</i>")
        self.totp_details_code_label.setText("-")
        self.totp_progressbar.setValue(0)
        self.totp_seconds_label.setText("")
        self.totp_timer.stop()
              
    def update_authenticator_display(self):
         if self.currently_selected_totp_index != -1:
             try:
                 if self.currently_selected_totp_index >= len(self.password_manager.totp_accounts):
                      self.clear_totp_details()
                      return
                 code = self.password_manager.generate_totp_code(self.currently_selected_totp_index)
                 if code and code != "Error":
                     self.totp_details_code_label.setText(code)
                     secret = self.password_manager.get_totp_account(self.currently_selected_totp_index).get("secret")
                     if not secret:
                          raise ValueError("Secret not found for TOTP update")
                     totp = pyotp.TOTP(secret)
                     remaining_float = totp.interval - (time.time() % totp.interval)
                     remaining_int = int(remaining_float)
                     progress_value = int(remaining_float * 10)
                     self.totp_progressbar.setValue(progress_value) 
                     self.totp_seconds_label.setText(f"{remaining_int}s remaining")
                     is_expiring = remaining_int < 5
                     self.totp_details_code_label.setProperty("expiring", is_expiring)
                     self.totp_details_code_label.style().unpolish(self.totp_details_code_label)
                     self.totp_details_code_label.style().polish(self.totp_details_code_label)
                 elif code == "Error":
                     self.totp_details_code_label.setText("Error") 
                     self.totp_progressbar.setValue(0)
                     self.totp_seconds_label.setText("Error generating code")
                 else:
                      self.clear_totp_details()
             except IndexError:
                  print("IndexError during TOTP update, clearing details.")
                  self.clear_totp_details()
             except Exception as e:
                  print(f"Error in update_authenticator_display: {e}")
                  self.totp_details_code_label.setText("Error") 
                  self.totp_progressbar.setValue(0)
                  self.totp_seconds_label.setText("Update Error")
                  self.totp_timer.stop()
         else:
             self.clear_totp_details()

    def copy_current_totp_code(self, event=None):
        code = self.totp_details_code_label.text()
        if code and code != "-" and code != "Error":
             self.copy_to_clipboard(code)

    def delete_selected_totp_account(self):
        if self.currently_selected_totp_index != -1:
            if self.currently_selected_totp_index < len(self.password_manager.totp_accounts):
                account = self.password_manager.get_totp_account(self.currently_selected_totp_index)
                reply = QMessageBox.question(self, 'Confirm Delete', 
                                           f"Are you sure you want to delete the authenticator account for '{account.get('name')}'?",
                                           QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, 
                                           QMessageBox.StandardButton.No)
                if reply == QMessageBox.StandardButton.Yes:
                    try:
                        self.password_manager.delete_totp_account(self.currently_selected_totp_index)
                        self.refresh_totp_list()
                        QMessageBox.information(self, "Success", "Authenticator account deleted successfully!")
                    except IndexError:
                         QMessageBox.warning(self, "Error", "Could not delete account. Index out of range.")
                    except Exception as e:
                         QMessageBox.critical(self, "Error", f"Could not delete account: {e}")
            else:
                 QMessageBox.warning(self, "Error", "Selection is invalid. Please re-select.")
                 self.clear_totp_details()
        else:
            QMessageBox.warning(self, "Error", "Please select an authenticator account to delete!")

    def copy_to_clipboard(self, text):
        if not text:
            return
        try:
            pyperclip.copy(text)
            self.status_bar.showMessage("Copied to clipboard!", 1500) 
        except Exception as e:
            print(f"Clipboard error: {e}")
            QMessageBox.warning(self, "Clipboard Error", f"Could not copy to clipboard: {e}")
            self.status_bar.showMessage("Clipboard error.", 1500)

    def load_settings(self):
        settings = QSettings(ORG_NAME, APP_NAME)
        geometry = settings.value("geometry")
        if geometry:
            self.restoreGeometry(geometry)
        else:
            self.resize(800, 600) 
            screen_geometry = QApplication.primaryScreen().availableGeometry()
            self.move(screen_geometry.center() - self.frameGeometry().center())

    def save_settings(self):
        settings = QSettings(ORG_NAME, APP_NAME)
        settings.setValue("geometry", self.saveGeometry())

    def closeEvent(self, event):
        self.save_settings()
        super().closeEvent(event)

    def run(self):
        self.statusBar().showMessage("Ready")
        
        # Use custom dialog instead of QInputDialog
        dialog = MasterPasswordDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
             master_password = dialog.getPassword()
             if master_password: # Check if something was entered
                  if self.password_manager.verify_master_password(master_password):
                       self.refresh_password_list()
                       self.refresh_totp_list()
                       self.show()
                  else:
                       # Error message shown by verify_master_password
                       sys.exit()
             else:
                  # Handle empty password entry after clicking OK
                  QMessageBox.warning(self, "Input Error", "Master password cannot be empty.")
                  sys.exit()
        else:
             # Dialog was cancelled
             QMessageBox.warning(self, "Cancelled", "Master password entry cancelled.")
             sys.exit()

    def refresh_totp_list(self):
        current_row = self.totp_account_list.currentRow()
        self.totp_account_list.clear()
        accounts = self.password_manager.get_all_totp_accounts()
        for account in accounts:
            self.totp_account_list.addItem(QListWidgetItem(account["name"]))
        # Try to restore selection if valid
        if 0 <= current_row < self.totp_account_list.count():
            self.totp_account_list.setCurrentRow(current_row)
        else:
             # If selection lost or invalid, clear details
             self.clear_totp_details()
    
    def show_main_menu(self):
        menu = QMenu(self)
        # Apply stylesheet to menu for consistency (optional)
        # menu.setStyleSheet(self.styleSheet()) # Inherit main style

        about_action = QAction(QIcon(ICON_ABOUT), "About Passvyn", self)
        about_action.triggered.connect(self.show_about_dialog)
        menu.addAction(about_action)

        menu.addSeparator()

        backup_action = QAction(QIcon(ICON_BACKUP), "Backup Data...", self)
        backup_action.triggered.connect(self.backup_data)
        menu.addAction(backup_action)

        restore_action = QAction(QIcon(ICON_RESTORE), "Restore Data...", self)
        restore_action.triggered.connect(self.restore_data)
        menu.addAction(restore_action)

        menu.addSeparator()

        settings_action = QAction(QIcon(ICON_SETTINGS), "Settings", self)
        settings_action.triggered.connect(self.show_settings)
        menu.addAction(settings_action)

        # Position menu below button (adjust slightly for corner widget)
        button_global_pos = self.menu_button.mapToGlobal(QPoint(0, self.menu_button.height()))
        menu.exec(button_global_pos)

    # --- Menu Action Handlers --- 
    def show_about_dialog(self):
        # Simple About Box
        QMessageBox.about(self, 
            "About Passvyn",
            "<b>Passvyn: Password Manager</b><br><br>" 
            "Version: 1.0 (Conceptual)<br>" 
            "A secure place for your passwords and codes.<br><br>" 
            "Developed by Vaibhav Pratap Singh"
        )

    def backup_data(self):
        data_file = self.password_manager.data_file
        if not os.path.exists(data_file):
            QMessageBox.warning(self, "Backup Error", "No data file found to backup.")
            return

        # Suggest a filename for the backup
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        suggested_filename = f"passvyn_backup_{timestamp}.enc"

        # Open file dialog to choose save location
        fileName, _ = QFileDialog.getSaveFileName(self, 
            "Backup Data File", 
            suggested_filename, 
            "Encrypted Data Files (*.enc);;All Files (*)")

        if fileName:
            try:
                shutil.copy2(data_file, fileName) # copy2 preserves metadata
                self.status_bar.showMessage(f"Backup successful: {fileName}", 5000)
                QMessageBox.information(self, "Backup Successful", f"Data successfully backed up to:<br>{fileName}")
            except Exception as e:
                QMessageBox.critical(self, "Backup Failed", f"Could not backup data file: {e}")
                self.status_bar.showMessage("Backup failed.", 3000)

    def restore_data(self):
        reply = QMessageBox.warning(self, "Confirm Restore",
            "Restoring data will <b>overwrite your current passwords and accounts</b>.<br><br>" 
            "Ensure the backup file was created with the <b>same master password</b> you are currently using.<br><br>" 
            "Are you sure you want to proceed?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel)

        if reply != QMessageBox.StandardButton.Yes:
            self.status_bar.showMessage("Restore cancelled.", 3000)
            return

        # Prompt for current master password to confirm identity
        confirm_dialog = MasterPasswordDialog(self)
        confirm_dialog.label.setText("Enter your CURRENT master password to confirm restore:")
        if confirm_dialog.exec() != QDialog.DialogCode.Accepted:
            self.status_bar.showMessage("Restore cancelled.", 3000)
            return
        
        current_password = confirm_dialog.getPassword()
        # Verify password without trying to decrypt (just check hash)
        current_hash = hashlib.sha256(current_password.encode()).hexdigest()
        if not self.password_manager.master_password_hash or current_hash != self.password_manager.master_password_hash:
             QMessageBox.critical(self, "Restore Failed", "Incorrect master password entered. Restore cancelled.")
             self.status_bar.showMessage("Restore failed: Incorrect password.", 3000)
             return

        # Proceed to select backup file
        fileName, _ = QFileDialog.getOpenFileName(self, 
            "Restore Data File", 
            "", 
            "Encrypted Data Files (*.enc);;All Files (*)")

        if fileName:
            data_file = self.password_manager.data_file
            try:
                # Perform the copy
                shutil.copy2(fileName, data_file)
                
                # Attempt to reload data with current key derived from confirmed password
                # We already derived the key when checking the hash if needed
                if not self.password_manager.encryption_key:
                     self.password_manager.encryption_key = self.password_manager.derive_key(current_password)
                     
                if self.password_manager.decrypt_data():
                     # Decryption successful, reload UI
                     self.refresh_password_list()
                     self.refresh_totp_list()
                     # Clear details panels
                     self.clear_entry_details()
                     self.clear_totp_details()
                     self.status_bar.showMessage("Restore successful! Data reloaded.", 5000)
                     QMessageBox.information(self, "Restore Successful", "Data successfully restored and reloaded.")
                else:
                     # Decryption failed - the backup might be corrupt or from a different master password
                     # We might want to restore the original file if possible, or warn user intensely.
                     # For now, just warn.
                     QMessageBox.critical(self, "Restore Warning", "Data file was replaced, but failed to decrypt with the current master password. The backup might be corrupt or require a different master password.")
                     self.status_bar.showMessage("Restore completed, but decryption failed.", 5000)
                     # Clear lists as data is unusable
                     self.password_manager.passwords = []
                     self.password_manager.totp_accounts = []
                     self.refresh_password_list()
                     self.refresh_totp_list()

            except Exception as e:
                QMessageBox.critical(self, "Restore Failed", f"Could not restore data file: {e}")
                self.status_bar.showMessage("Restore failed.", 3000)

    def show_settings(self):
        # Placeholder for settings functionality
        QMessageBox.information(self, "Settings", "Settings are not yet implemented.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    ModernStyle.set_style(app)
    password_manager_gui = PasswordManagerGUI()
    password_manager_gui.run()
    sys.exit(app.exec())
