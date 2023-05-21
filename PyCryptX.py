from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
import os

# Encrypt stuff with public key, sign with private key (soon)
	# Open the recipient public key
def encrypt(file_path):
	recipient_ed25519_pk = input("Enter the recipient's X25519 public key: ")
	with open(file_path, "rb") as file:
		file_data = file.read()

	# Open keys as bytes (uses generated private key automatically)
	f = open(recipient_ed25519_pk, 'rb')
	recipient_ed25519_pk = f.read()
	f.close
	f = open('x25519_private_key.pem', 'rb')
	my_x25519_sk = f.read()
	f.close

	# Open keys as keys
	loaded_recipient_ed25519_pk = load_pem_public_key(recipient_ed25519_pk)
	loaded_my_x25519_sk = load_pem_private_key(my_x25519_sk, None)
	pk_x25519 = loaded_recipient_ed25519_pk.public_bytes_raw()
	sk_x25519 = loaded_my_x25519_sk.private_bytes_raw()

	# Make sure both keys are X25519 (bug can make them show as Ed25519 instead if you don't declare this explicity)
	pk_x25519 = x25519.X25519PublicKey.from_public_bytes(pk_x25519)
	sk_x25519 = x25519.X25519PrivateKey.from_private_bytes(sk_x25519)

	# Key exchange
	shared_secret = sk_x25519.exchange(pk_x25519)

	# Don't drink and derive
	derived_key = HKDF(
	algorithm=hashes.SHA512(),
	length=32,
	salt=None,
	info=b'',
	).derive(shared_secret)

	# Encrypt it
	nonce = os.urandom(16)
	algorithm = algorithms.ChaCha20(shared_secret, nonce)
	cipher = Cipher(algorithm, mode=None)
	encryptor = cipher.encryptor()
	encrypted_data = encryptor.update(file_data) + encryptor.finalize()

	# Write encrypted file
	output_file_path = file_path + ".sec"
	with open(output_file_path, "wb") as output_file:
		output_file.write(nonce)
		output_file.write(encrypted_data)

	# Print success
	print("File encrypted successfully.")

# Decrypt stuff with private key, verify signature with public key (soon)
	# Open with your private key
def decrypt(file_path):
	recipient_ed25519_sk = input("Enter your X25519 private key: ")
	if not file_path.endswith(".sec"):
		print("Not en encrypted file. Make sure it has the .sec extension.")
		return
	with open(file_path, "rb") as file:
		nonce = file.read(16)
		encrypted_data = file.read()

	# Open keys
	f = open(recipient_ed25519_sk, 'rb')
	recipient_ed25519_sk = f.read()
	f.close
	f = open('x25519_public_key.pem', 'rb')
	my_x25519_pk = f.read()
	f.close

	# Load keys as keys
	loaded_recipient_ed25519_sk = load_pem_private_key(recipient_ed25519_sk, None)
	loaded_my_x25519_pk = load_pem_public_key(my_x25519_pk)
	sk_x25519 = loaded_recipient_ed25519_sk.private_bytes_raw()
	pk_x25519 = loaded_my_x25519_pk.public_bytes_raw()

	# Make sure both keys are X25519 (bug can make them show as Ed25519 instead if you don't declare this explicity)
	pk_x25519 = x25519.X25519PublicKey.from_public_bytes(pk_x25519)
	sk_x25519 = x25519.X25519PrivateKey.from_private_bytes(sk_x25519)

	# Key exchange
	shared_secret = sk_x25519.exchange(pk_x25519)

	# Don't drink and derive 
	derived_key = HKDF(
	algorithm=hashes.SHA512(),
	length=32,
	salt=None,
	info=b'',
	).derive(shared_secret)

	# Encrypt it
	algorithm = algorithms.ChaCha20(shared_secret, nonce)
	cipher = Cipher(algorithm, mode=None)
	decryptor = cipher.decryptor()
	decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

	# Remove the ".sec" extension
	output_file_path = file_path[:-4]

	# Write decrypted file
	with open(output_file_path, "wb") as output_file:
		output_file.write(decrypted_data)

	# Print success
	print("File decrypted successfully.")

def main():
    # Welcome message
	print("Welcome to PyCryptX v0.0.1. This is only a hobby project. It has not been audited. Don't trust it with important shit.")
	print("Report any bugs to the GitHub or submit a PR if you're a dev: https://github.com/xannythepleb/PyCryptX")
	print("This project is something I started to learn more about encryption so help is appreciated.")
	
	# Prompt for encrypt or decrypt
	action = input("Do you want to encrypt or decrypt a file? (e/d): ")

    # Prompt for the file name or path
	file_path = input("Enter the file path, or just file name if in current directory: ")

	if action.lower() == "e":
		encrypt(file_path)
	elif action.lower() == "d":
		decrypt(file_path)
	else:
		print("Invalid action. Please type either 'e' for encrypt or 'd' for decrypt.")

# Run main function
if __name__ == "__main__":
    main()
