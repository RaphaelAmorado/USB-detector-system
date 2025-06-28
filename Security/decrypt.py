from cryptography.fernet import Fernet

# Load the secret key
with open("secret.key", "rb") as key_file:
    key = key_file.read()

cipher = Fernet(key)

# Load the encrypted log
with open("usb_log.enc", "rb") as enc_file:
    encrypted_data = enc_file.read()

# Decrypt it
decrypted_data = cipher.decrypt(encrypted_data)

# Print the original log
print(decrypted_data.decode())
