from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes

def pad(text):
    # Pads the text to be a multiple of 8 bytes
    while len(text) % 8 != 0:
        text += ' '
    return text

def des_encrypt(message, key):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_message = pad(message)
    ciphertext = cipher.encrypt(padded_message.encode())
    return ciphertext

def des_decrypt(ciphertext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    return decrypted.decode().strip()

if __name__ == "__main__":
    # User input for plaintext message
    plaintext = input("Enter the plaintext message: ")

    # Generate a random DES key (8 bytes)
    key = get_random_bytes(8)

    # Encrypt
    ciphertext = des_encrypt(plaintext, key)
    print("\nEncryption Results:")
    print("Plaintext:", plaintext)
    print("Encrypted (ciphertext):", ciphertext)
    print("Key:", key)

    # Decrypt
    decrypted_text = des_decrypt(ciphertext, key)
    print("\nDecryption Results:")
    print("Decrypted:", decrypted_text)
