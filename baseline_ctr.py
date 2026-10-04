from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

#given command
PLAINTEXT = b'{"action":"READ","path":"notes.txt"}'

#encrypt function
def encrypt_ctr(key,iv,plaintext):
    cipher = Cipher(algorithms.AES(key),modes.CTR(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext)+encryptor.finalize()

    return ciphertext

#decrypt function
def decrypt_ctr(key,iv,ciphertext):
    cipher = Cipher(algorithms.AES(key),modes.CTR(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext)+decryptor.finalize()

    return plaintext

def receiver(key,iv,ciphertext):
    plaintext = decrypt_ctr(key,iv, ciphertext)

    #change bytes into a string
    print(plaintext.decode())

def relay_modify(ciphertext):
    #create the bytes to change
    original = b"READ"
    modified = b"EDIT"

    offset = PLAINTEXT.index(original)

    altered_text = bytearray(ciphertext)
    print()
    print("XOR difference:")
    print()
    for i in range(len(original)):
        xor_delta = original[i] ^ modified[i]
        print("The XOR delta for ",chr(original[i])," and ", chr(modified[i]), " is ", hex(xor_delta))
        altered_text[offset + i] =altered_text[offset + i] ^ xor_delta

    return bytes(altered_text)

def main():
    
    key = os.urandom(32)
    iv = os.urandom(16)
    ciphertext = encrypt_ctr(key,iv,PLAINTEXT)

    print("Original plaintext:" + PLAINTEXT.decode())
    print()
    print("Ciphertext:"  + ciphertext.hex())
    print()

    print("Normal Receiver behavior")
    receiver(key, iv, ciphertext)

    tampered_ciphertext = relay_modify(ciphertext)

    print()
    print("Modified receiver behavior")
    receiver(key, iv, tampered_ciphertext)

    print()
    print("Replay attack")

    print("First process:")
    receiver(key, iv, ciphertext)
    print()
    print("Second process:")
    receiver(key, iv, ciphertext)


if __name__ == "__main__":
    main()
