from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def rsa_encrypt(message, public_key):
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    decrypted = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

if __name__ == "__main__":
    # User input for plaintext message
    plaintext = input("Enter the plaintext message: ")

    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # Encrypt
    ciphertext = rsa_encrypt(plaintext, public_key)
    print("\nEncryption Results:")
    print("Plaintext:", plaintext)
    print("Encrypted (ciphertext):", ciphertext)

    # Decrypt
    decrypted_text = rsa_decrypt(ciphertext, private_key)
    print("\nDecryption Results:")
    print("Decrypted:", decrypted_text)
