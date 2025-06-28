import wmi
import time
import logging
from cryptography.fernet import Fernet
from datetime import datetime
import os
import hashlib

# === CONFIGURATION ===

LOG_FILE = "usb_log.enc"
TEMP_LOG_FILE = "usb_log.txt"
KEY_FILE = "secret.key"
WHITELIST_FILE = "whitelist.txt"

# Change this to your own hashed password (hash of "admin123" shown here)
ADMIN_PASSWORD_HASH = hashlib.sha256(b"admin123").hexdigest()

def load_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key

def load_whitelist():
    if os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, "r") as f:
            return set(line.strip() for line in f if line.strip())
    return set()

def save_whitelist(whitelist):
    with open(WHITELIST_FILE, "w") as f:
        for device_id in sorted(whitelist):
            f.write(f"{device_id}\n")

def check_admin_password():
    password = input("🔐 Enter admin password (leave blank to run as user): ").strip()
    hashed = hashlib.sha256(password.encode()).hexdigest()
    return hashed == ADMIN_PASSWORD_HASH

# Load encryption key and whitelist
KEY = load_key()
cipher = Fernet(KEY)
WHITELIST = load_whitelist()

# Logging setup
logging.basicConfig(filename=TEMP_LOG_FILE,
                    level=logging.INFO,
                    format='%(asctime)s - %(message)s')

class USBDetector:
    def __init__(self, is_admin=False):
        self.wmi = wmi.WMI()
        self.known_devices = set()
        self.is_admin = is_admin
        self.already_prompted = set()  # Track already handled device IDs

    def get_connected_usb_devices(self):
        usb_devices = set()
        for usb in self.wmi.Win32_USBControllerDevice():
            try:
                device = usb.Dependent
                usb_devices.add(device.DeviceID)
            except:
                continue
        return usb_devices

    def check_new_devices(self):
        global WHITELIST
        current_devices = self.get_connected_usb_devices()
        new_devices = current_devices - self.known_devices
        removed_devices = self.known_devices - current_devices

        for dev in new_devices:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if self.is_whitelisted(dev):
                logging.info(f"Approved USB connected: {dev}")
                print(f"[{timestamp}] ✅ Approved USB connected: {dev}")
            else:
                if dev not in self.already_prompted:
                    self.already_prompted.add(dev)
                    logging.warning(f"ALERT! Unauthorized USB detected: {dev}")
                    print(f"[{timestamp}] 🚨 Unauthorized USB detected: {dev}")

                    if self.is_admin:
                        choice = input(f"➕ Admin: Whitelist this device? (y/n): ").strip().lower()
                        if choice == 'y':
                            WHITELIST.add(dev)
                            save_whitelist(WHITELIST)
                            logging.info(f"Device added to whitelist by admin: {dev}")
                            print(f"[{timestamp}] ✅ Device added to whitelist.")
                    else:
                        print("⚠️ Access denied: Only admin can whitelist devices.")

        for dev in removed_devices:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            logging.info(f"USB disconnected: {dev}")
            print(f"[{timestamp}] ❌ USB disconnected: {dev}")

        self.known_devices = current_devices

    def is_whitelisted(self, device_id):
        return any(device_id.startswith(allowed) for allowed in WHITELIST)

    def run(self, poll_interval=2):
        print("🔌 USB Detection started. Plug in or remove a USB device...")
        self.known_devices = self.get_connected_usb_devices()
        try:
            while True:
                self.check_new_devices()
                time.sleep(poll_interval)
        except KeyboardInterrupt:
            print("\n🛑 Stopping USB Detector...")
            for handler in logging.root.handlers[:]:
                handler.close()
            logging.root.removeHandler(handler)
            self.encrypt_log()

    def encrypt_log(self):
        try:
            if os.path.exists(TEMP_LOG_FILE):
                with open(TEMP_LOG_FILE, "rb") as f:
                    data = f.read()
                if data.strip():
                    encrypted_data = cipher.encrypt(data)
                    with open(LOG_FILE, "wb") as f:
                        f.write(encrypted_data)
                    print(f"🔐 Encrypted log saved to {LOG_FILE}")
                else:
                    print("⚠️ Log file is empty. No data encrypted.")
                os.remove(TEMP_LOG_FILE)
        except Exception as e:
            print(f"❌ Failed to encrypt log: {e}")

# === Main Program ===
if __name__ == "__main__":
    is_admin = check_admin_password()
    if is_admin:
        print("🛡️ Admin access granted.")
    else:
        print("👤 Running in user mode (no whitelist permissions).")

    detector = USBDetector(is_admin=is_admin)
    detector.run()
