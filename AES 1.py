from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def aes_encrypt(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return ciphertext, cipher.nonce, tag

def aes_decrypt(ciphertext, nonce, tag, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted.decode()

# Example usage
if __name__ == "__main__":
    # User input for plaintext message
    plaintext = input("Enter the plaintext message: ")

    # User input for key size
    while True:
        try:
            key_size = int(input("Enter the key size (16 for AES-128, 24 for AES-192, 32 for AES-256): "))
            if key_size in [16, 24, 32]:
                break
            else:
                print("Invalid key size. Please enter 16, 24, or 32.")
        except ValueError:
            print("Invalid input. Please enter an integer.")

    # Generate a random AES key of the specified size
    key = get_random_bytes(key_size)

    # Encrypt
    ciphertext, nonce, tag = aes_encrypt(plaintext, key)
    print("\nEncryption Results:")
    print("Plaintext:", plaintext)
    print("Encrypted (ciphertext):", ciphertext)
    print("Nonce:", nonce)
    print("Tag:", tag)

    # Decrypt
    decrypted_text = aes_decrypt(ciphertext, nonce, tag, key)
    print("\nDecryption Results:")
    print("Decrypted:", decrypted_text)
