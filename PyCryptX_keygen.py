from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization

# Generate X25519 keypair for key exchange
private_key_exchange = x25519.X25519PrivateKey.generate()
public_key_exchange = private_key_exchange.public_key()

# Generate Ed25519 keypair for digital signatures
private_key_signature = ed25519.Ed25519PrivateKey.generate()
public_key_signature = private_key_signature.public_key()

# Convert private keys to PEM
sk_ed25519 = private_key_exchange.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
sk_x25519 = private_key_signature.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Convert public keys to PEM
pk_ed25519 = public_key_exchange.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
pk_x25519 = public_key_signature.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Write the x25519 private key to file
with open('x25519_private_key.pem', 'wb') as file:
	file.write(sk_x25519)
	file.close()
# Write the ed25519 private key to file
with open('ed25519_private_key.pem', 'wb') as file:
	file.write(sk_ed25519)
	file.close()

# Write the x25519 private key to file
with open('x25519_public_key.pem', 'wb') as file:
	file.write(pk_x25519)
	file.close()
# Write the ed25519 private key to file
with open('ed25519_public_key.pem', 'wb') as file:
	file.write(pk_ed25519)
	file.close()

print("Keys generated and stored successfully.")

# Print public keys
print("Below are your public keys. The first is allows others to send you encrypted messages. The second allows others to verify your messages came from you.\n")

f = open('x25519_public_key.pem', 'r')
file_contents = f.read()
print(file_contents)
f.close

f = open('ed25519_public_key.pem', 'r')
file_contents = f.read()
print(file_contents)
f.close
