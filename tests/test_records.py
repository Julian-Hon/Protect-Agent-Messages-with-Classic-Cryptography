import pytest
from cryptography.exceptions import InvalidSignature
from secure_record import seal, open_record, GATEWAY_TO_NODE, NODE_TO_GATEWAY
import os

def test_bidirectional_messages():
    gateway_enc = os.urandom(32)
    gateway_mac = os.urandom(32)
    node_enc = os.urandom(32)
    node_mac = os.urandom(32)
    session_id = os.urandom(8)
    gatewaymessage = b"message to node"
    nodemessage = b"message to gateway"
    gateway_record = seal(gateway_enc, gateway_mac, session_id, 0, GATEWAY_TO_NODE, 1, gatewaymessage)
    node_record = seal(node_enc,node_mac, session_id, 0, NODE_TO_GATEWAY, 1, nodemessage)

    open_gateway = open_record(gateway_enc, gateway_mac, session_id,gateway_record, 0, GATEWAY_TO_NODE )
    open_node = open_record(node_enc,node_mac, session_id, node_record,0, NODE_TO_GATEWAY)
    assert open_gateway == gatewaymessage
    assert open_node == nodemessage
#2
def test_modified_ciphertext():
    enc_key = os.urandom(32)
    mac_key = os.urandom(32)
    session_id = os.urandom(8)
    plaintext = b'{"action":"READ","path":"notes.txt"}'
    record = seal(enc_key,mac_key,session_id,0, GATEWAY_TO_NODE, 1, plaintext)

    altered_record = bytearray(record)
    altered_record[31] = altered_record[31] ^ 1
    altered_record = bytes(altered_record)
    with pytest.raises(InvalidSignature):
        open_record(enc_key,mac_key,session_id,altered_record, 0,GATEWAY_TO_NODE)
#3
def test_modified_header():
    enc_key = os.urandom(32)
    mac_key = os.urandom(32)
    session_id = os.urandom(8)
    plaintext = b'{"action":"READ","path":"notes.txt"}'

    record = seal(enc_key,mac_key,session_id,0, GATEWAY_TO_NODE, 1, plaintext)

    altered_record = bytearray(record)
    altered_record[10] = altered_record[10] ^ 1
    altered_record = bytes(altered_record)
    with pytest.raises(InvalidSignature):
        open_record(enc_key,mac_key,session_id,altered_record, 0,GATEWAY_TO_NODE)
#4
def test_replayed_record():
    enc_key = os.urandom(32)
    mac_key = os.urandom(32)
    session_id = os.urandom(8)
    plaintext = b'{"action":"READ","path":"notes.txt"}'

    record = seal(enc_key,mac_key,session_id,0, GATEWAY_TO_NODE, 1, plaintext)
    result = open_record(enc_key,mac_key,session_id,record,0,GATEWAY_TO_NODE)
    assert result == plaintext
    with pytest.raises(ValueError):
        open_record(enc_key,mac_key,session_id,record,1,GATEWAY_TO_NODE)
#5
def test_reflected_record():
    enc_key = os.urandom(32)
    mac_key = os.urandom(32)
    session_id = os.urandom(8)
    plaintext = b'{"action":"READ","path":"notes.txt"}'
    record = seal(enc_key,mac_key,session_id,0, GATEWAY_TO_NODE, 1, plaintext)
    with pytest.raises(ValueError):
        open_record(enc_key,mac_key, session_id, record,0, NODE_TO_GATEWAY)