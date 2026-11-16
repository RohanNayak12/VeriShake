import socket
import json
import os
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Load Keys
with open("server_private.pem", "rb") as f:
    skS = serialization.load_pem_private_key(f.read(), password=None)
with open("client_public.pem", "rb") as f:
    pkC = serialization.load_pem_public_key(f.read())

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 5005))
print("Server V2 (ECDH + AES-GCM) listening...\n")

while True:
    # Step 1: Receive [Client_ID, Nonce_C, Client_Eph_Pub]
    data, addr = sock.recvfrom(2048)
    msg1 = json.loads(data.decode())
    client_id = msg1['client_id']
    nonce_c = base64.b64decode(msg1['nonce_c'])
    client_eph_pub = base64.b64decode(msg1['client_eph_pub'])
    print(f"[Step 1] Received connection & Ephemeral Key from {client_id}")

    # Generate Server Ephemeral Key & Derive AES Session Key
    server_eph_key = ec.generate_private_key(ec.SECP256R1())
    server_eph_pub = server_eph_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    peer_pub = serialization.load_pem_public_key(client_eph_pub)
    shared_secret = server_eph_key.exchange(ec.ECDH(), peer_pub)
    aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data').derive(shared_secret)
    aesgcm = AESGCM(aes_key)

    # Step 2: Sign parameters and send Server Ephemeral Key
    nonce_s = os.urandom(16)
    signature_s = skS.sign(nonce_c + nonce_s + client_eph_pub + server_eph_pub, ec.ECDSA(hashes.SHA256()))
    
    msg2 = {
        'nonce_s': base64.b64encode(nonce_s).decode(),
        'server_eph_pub': base64.b64encode(server_eph_pub).decode(),
        'signature_s': base64.b64encode(signature_s).decode()
    }
    sock.sendto(json.dumps(msg2).encode(), addr)
    print("[Step 2] Sent Nonce_S, Ephemeral Key, and Signature")

    # Step 3: Receive Encrypted Payload containing Client Signature and Secret Data
    data, addr = sock.recvfrom(2048)
    msg3 = json.loads(data.decode())
    iv = base64.b64decode(msg3['iv'])
    ciphertext = base64.b64decode(msg3['ciphertext'])

    try:
        # Decrypt payload using AES-GCM
        plaintext = aesgcm.decrypt(iv, ciphertext, None)
        decrypted_payload = json.loads(plaintext.decode())
        
        signature_c = base64.b64decode(decrypted_payload['signature_c'])
        secret_sensor_data = decrypted_payload['sensor_data']

        # Verify Client Signature
        pkC.verify(signature_c, nonce_s + nonce_c + server_eph_pub + client_eph_pub, ec.ECDSA(hashes.SHA256()))
        print(f"[Step 3] Mutual Auth Complete! Decrypted Secret Data: {secret_sensor_data}\n")
    except Exception as e:
        print(f"[!] Authentication/Decryption failed: {e}\n")
