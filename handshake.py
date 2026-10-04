from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
import os

#RSA signing key

def generate_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)

def generate_dh_parameters(): 
    with open("ffdhe3072.pem", "rb") as file:
        data = file.read()

    parameters = serialization.load_pem_parameters(data)
    return parameters

def encode_transcript(field):
    length_bytes = len(field).to_bytes(4,"big")
    return length_bytes + field

def sign_transcript(private_key, identity, transcript_hash):
    message = identity + transcript_hash

    signiature = private_key.sign(message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()) 
    return signiature

def verify_signature(public_key,identity,transcript_hash, signature):

    message = identity + transcript_hash
    public_key.verify(signature, message,padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

def derive_key(k_master, identity, transcript_hash):
    x = hmac.HMAC(k_master, hashes.SHA256())
    x.update(identity + transcript_hash)
    return x.finalize()

def main():
    #rsa key for each party
    gateway_rsa = generate_rsa_key()
    node_rsa = generate_rsa_key()
    session_dh = generate_dh_parameters()

    gateway_dh = session_dh.generate_private_key()
    node_dh = session_dh.generate_private_key()

    #16byte nonce
    gatewaynonce = os.urandom(16)
    nodenonce = os.urandom(16)

    #public values
    gateway_public = gateway_dh.public_key()
    node_public = node_dh.public_key()
    gateway_public_bytes = gateway_public.public_numbers().y.to_bytes(384, "big")
    node_public_bytes = node_public.public_numbers().y.to_bytes(384,"big")

    protocol_label = b"CSCE465-HS-v2"
    group_identifier = b"ffdhe3072"
    gateway_identity = b"gateway"
    node_identity = b"node"
    #protocol label CSCE465-HS-v2, group identifier ffdhe3072, and both party identities both ephemeral Diffie–Hellman public values and both random nonces.
    canonical_transcript = (
        encode_transcript(protocol_label) + encode_transcript(group_identifier) + encode_transcript(gateway_identity) + encode_transcript(node_identity) +
        encode_transcript(gateway_public_bytes) + encode_transcript(node_public_bytes) +encode_transcript(gatewaynonce) + encode_transcript(nodenonce)
    )



    digest = hashes.Hash(hashes.SHA256())
    digest.update(canonical_transcript)
    transcript_hash = digest.finalize()

  

    gateway_signature = sign_transcript(gateway_rsa, gateway_identity, transcript_hash)
    node_signature = sign_transcript(node_rsa,node_identity, transcript_hash)

    gateway_rsa_public = gateway_rsa.public_key()
    node_rsa_public = node_rsa.public_key()
    gateway_public_key = gateway_dh.public_key()
    node_public_key = node_dh.public_key()

    gateway_z = gateway_dh.exchange(node_public_key)
    node_z = node_dh.exchange(gateway_public_key)

    print(gateway_z == node_z)
    verify_signature(node_rsa_public,node_identity, transcript_hash, node_signature)
    verify_signature(gateway_rsa_public,gateway_identity, transcript_hash, gateway_signature)

    #k_master
    digest = hashes.Hash(hashes.SHA256())
    digest.update(b"CSCE465-KDF-v1")
    digest.update(gateway_z)
    digest.update(transcript_hash)
    k_master = digest.finalize()


    k_g2n_enc = derive_key(k_master, b"gateway-to-node encryption", transcript_hash)
    k_g2n_mac = derive_key(k_master, b"gateway-to-node MAC", transcript_hash)
    k_n2g_enc = derive_key(k_master, b"node-to-gateway encryption", transcript_hash)
    k_n2g_mac = derive_key(k_master, b"node-to-gateway MAC", transcript_hash)
    session_id = derive_key(k_master,b"session identifier", transcript_hash)[:8]

    print("Gateway nonce:", gatewaynonce.hex())
    print("Node nonce:", nodenonce.hex())
    print(canonical_transcript)
    print("Transcript hash: ", transcript_hash.hex())
    print("Master key", k_master.hex())
    print("Session ID:", session_id.hex())
if __name__ == "__main__":
    main()

    