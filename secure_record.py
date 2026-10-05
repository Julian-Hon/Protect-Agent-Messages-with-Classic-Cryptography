from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature
import os

GATEWAY_TO_NODE = 0
NODE_TO_GATEWAY = 1
VERSION =1

def create_header(version,direction,sequence, message_type, ciphertext_length):
    return version.to_bytes(1, "big") + direction.to_bytes(1, "big") + sequence.to_bytes(8,"big") + message_type.to_bytes(1, "big") + ciphertext_length.to_bytes(4,"big")

def create_iv(session_id, sequence):
    return session_id + sequence.to_bytes(8,"big")

def encrypt_ctr(key, iv, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

def decrypt_ctr(key,iv,ciphertext):
    cipher = Cipher(algorithms.AES(key),modes.CTR(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def create_tag(mac_key, info):
    x = hmac.HMAC(mac_key, hashes.SHA256())
    x.update(info)
    return x.finalize()

def verify_tag(mac_key, info, tag):
    x = hmac.HMAC(mac_key, hashes.SHA256())
    x.update(info)
    x.verify(tag)

def seal(encryption_key, mac_key, session_id,sequence, direction, message_type, plaintext):
    iv = create_iv(session_id, sequence)
    ciphertext = encrypt_ctr(encryption_key, iv, plaintext)
    header = create_header(VERSION,direction, sequence, message_type, len(ciphertext))
    tag = create_tag(mac_key, header + iv + ciphertext)
    return header + iv + ciphertext + tag


def open_record(encryption_key, mac_key,session_id, record, expected_sequence, expected_direction ):
    if len(record) < 63:
        raise ValueError("Record is invalid, too short")
    header = record[:15]
    version = header[0]
    direction = header[1]
    sequence = int.from_bytes(header[2:10],"big")
    message_type = header[10]
    ciphertext_length = int.from_bytes(header[11:15],"big")
    iv = record[15:31]
    ciphertext = record[31:31 + ciphertext_length]
    tag = record[31 + ciphertext_length: 31 + ciphertext_length + 32]

    expected_iv = create_iv(session_id,sequence)

    #validation
    
    if version != VERSION:
        raise ValueError("Version mismatch")
    if sequence != expected_sequence:
        raise ValueError("Wrong sequence")
    if direction != expected_direction:
        raise ValueError("wrong Direction")
    if iv !=expected_iv:
        raise ValueError("incorrect IV")
    verify_tag(mac_key, header+ iv + ciphertext, tag)

    plaintext = decrypt_ctr(encryption_key, iv, ciphertext)
    return plaintext
    
def main():
    enc_key = os.urandom(32)
    mac_key = os.urandom(32)
    session_id = os.urandom(8)

    plaintext = b'{"action":"READ","path":"notes.txt"}'

    record = seal(
        enc_key,
        mac_key,
        session_id,
        sequence=0,
        direction=GATEWAY_TO_NODE,
        message_type=1,
        plaintext=plaintext
    )

    print("Record:")
    print(record.hex())

    opened = open_record(
        enc_key,
        mac_key,
        session_id,
        record,
        expected_sequence=0,
        expected_direction=GATEWAY_TO_NODE
    )

    print()
    print("Recovered plaintext:")
    print(opened.decode())

if __name__ == "__main__":
    main()

