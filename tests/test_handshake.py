import pytest
from cryptography.exceptions import InvalidSignature
from handshake import generate_rsa_key,sign_transcript,verify_signature


def test_valid_handshake():
    gateway_rsa = generate_rsa_key()
    transcript_hash = b"T" *32
    signature = sign_transcript(gateway_rsa, b"gateway", transcript_hash)
    gateway_public_key = gateway_rsa.public_key()
    verify_signature(gateway_public_key, b"gateway", transcript_hash,signature)

def test_incorrect_rsa_public_key():
    gateway_rsa = generate_rsa_key()
    transcript_hash = b"T" * 32
    signature = sign_transcript(gateway_rsa, b"gateway", transcript_hash)
    incorrect_gateway_public_key = generate_rsa_key().public_key()
    with pytest.raises(InvalidSignature):
        verify_signature(incorrect_gateway_public_key,b"gateway", transcript_hash,signature)

def test_invalid_transcript():
    gateway_rsa =generate_rsa_key()
    transcript_hash = b"T"*32
    incorrect_transcript_hash = b"A" *32
    signature = sign_transcript(gateway_rsa, b"gateway", transcript_hash)
    gateway_public_key = gateway_rsa.public_key()
    with pytest.raises(InvalidSignature):
        verify_signature(gateway_public_key,b"gateway",incorrect_transcript_hash, signature)
def test_reflected_handshake_message():
    gateway_rsa =generate_rsa_key()
    transcript_hash = b"T"*32
    signature = sign_transcript(gateway_rsa, b"gateway", transcript_hash)
    gateway_public_key = gateway_rsa.public_key()
    with pytest.raises(InvalidSignature):
        verify_signature(gateway_public_key,b"node",transcript_hash, signature)