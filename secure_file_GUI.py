import os
import sys
import json
import time
import hashlib
import hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from PyQt5 import QtWidgets, QtCore, QtGui

# ----------- Utility Functions -----------

def compute_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def compute_hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

# ----------- Encryption / Decryption -----------

def encrypt_file(input_path, output_path, password):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(input_path, "rb") as f:
        data = f.read()

    metadata = {
        "filename": os.path.basename(input_path),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "hash": compute_hash(data)
    }

    package = json.dumps(metadata).encode() + b"\nMETA_END\n" + data
    encrypted = encryptor.update(package) + encryptor.finalize()
    tag = compute_hmac(key, encrypted)

    with open(output_path, "wb") as f:
        f.write(salt + iv + encrypted + tag)

def decrypt_file(input_path, output_path, password):
    with open(input_path, "rb") as f:
        file_data = f.read()

    salt, iv = file_data[:16], file_data[16:32]
    encrypted, tag = file_data[32:-32], file_data[-32:]
    key = derive_key(password, salt)

    calc_tag = compute_hmac(key, encrypted)
    if not hmac.compare_digest(tag, calc_tag):
        raise ValueError("❌ Integrity check failed (HMAC mismatch). File tampered or wrong password.")

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    package = decryptor.update(encrypted) + decryptor.finalize()

    metadata_bytes, file_bytes = package.split(b"\nMETA_END\n", 1)
    metadata = json.loads(metadata_bytes.decode())

    extracted_hash = compute_hash(file_bytes)
    if extracted_hash != metadata["hash"]:
        raise ValueError("❌ Integrity check failed (SHA256 mismatch). File corrupted.")

    if output_path.endswith(".dec"):
        output_path = output_path.replace(".dec", "_" + metadata["filename"])

    with open(output_path, "wb") as f:
        f.write(file_bytes)

    return metadata

# ----------- GUI with Animations -----------

class EncryptDecryptApp(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.applyAnimations()

    def initUI(self):
        self.setWindowTitle("🔒 Secure File Encryptor (with HMAC)")
        self.setStyleSheet("""
            QWidget {
                background-color: #1E1E2F;
                color: #EAEAEA;
                font-family: Arial;
                font-size: 14px;
            }
            QLineEdit, QTextEdit {
                background-color: #2E2E3E;
                border: 2px solid #5A5A7A;
                border-radius: 10px;
                padding: 5px;
                color: white;
            }
            QPushButton {
                background-color: #4A90E2;
                color: white;
                border-radius: 12px;
                padding: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #357ABD;
            }
            QTextEdit {
                min-height: 120px;
            }
        """)

        layout = QtWidgets.QVBoxLayout()

        self.file_input = QtWidgets.QLineEdit(self)
        self.file_input.setPlaceholderText("Select file...")
        layout.addWidget(self.file_input)

        browse_btn = QtWidgets.QPushButton("📂 Browse")
        browse_btn.clicked.connect(self.browse_file)
        layout.addWidget(browse_btn)

        self.password_input = QtWidgets.QLineEdit(self)
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter password")
        layout.addWidget(self.password_input)

        encrypt_btn = QtWidgets.QPushButton("🔐 Encrypt")
        encrypt_btn.clicked.connect(self.encrypt_file)
        layout.addWidget(encrypt_btn)

        decrypt_btn = QtWidgets.QPushButton("🔓 Decrypt")
        decrypt_btn.clicked.connect(self.decrypt_file)
        layout.addWidget(decrypt_btn)

        self.status = QtWidgets.QTextEdit(self)
        self.status.setReadOnly(True)
        layout.addWidget(self.status)

        self.setLayout(layout)

        # Drop shadow effect
        for widget in [browse_btn, encrypt_btn, decrypt_btn]:
            effect = QtWidgets.QGraphicsDropShadowEffect()
            effect.setBlurRadius(20)
            effect.setOffset(3, 3)
            widget.setGraphicsEffect(effect)

    def applyAnimations(self):
        # Fade-in animation
        self.fade_anim = QtCore.QPropertyAnimation(self, b"windowOpacity")
        self.fade_anim.setDuration(1200)
        self.fade_anim.setStartValue(0)
        self.fade_anim.setEndValue(1)
        self.fade_anim.start()

    def browse_file(self):
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.file_input.setText(file_path)

    def animate_status(self, message):
        self.status.append(message)
        # Slide effect
        self.anim = QtCore.QPropertyAnimation(self.status, b"geometry")
        self.anim.setDuration(500)
        self.anim.setStartValue(self.status.geometry())
        self.anim.setEndValue(self.status.geometry())
        self.anim.start()

    def encrypt_file(self):
        file_path = self.file_input.text()
        password = self.password_input.text()
        if not file_path or not password:
            self.animate_status("⚠️ Select file and enter password!")
            return

        out_path = file_path + ".enc"
        try:
            encrypt_file(file_path, out_path, password)
            self.animate_status(f"✅ File encrypted successfully: {out_path}")
        except Exception as e:
            self.animate_status(f"❌ Error: {str(e)}")

    def decrypt_file(self):
        file_path = self.file_input.text()
        password = self.password_input.text()
        if not file_path or not password:
            self.animate_status("⚠️ Select file and enter password!")
            return

        out_path = file_path + ".dec"
        try:
            metadata = decrypt_file(file_path, out_path, password)
            self.animate_status(f"✅ File decrypted successfully: {out_path}")
            self.animate_status(f"📄 Original filename: {metadata['filename']}")
            self.animate_status(f"🕒 Encrypted on: {metadata['timestamp']}")
            self.animate_status("🔑 Integrity Verified (SHA256 + HMAC OK)")
        except Exception as e:
            self.animate_status(f"❌ Error: {str(e)}")

# ----------- Run -----------

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = EncryptDecryptApp()
    window.resize(550, 420)
    window.show()
    sys.exit(app.exec_())
