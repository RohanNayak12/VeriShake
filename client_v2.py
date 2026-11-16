import socket
import json
import os
import base64
from hsm import VirtualHSM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Initialize HSM (Protects Private Key & ECDH Math)
hsm = VirtualHSM("client_private.pem")

# Load Server Public Key for Validation
with open("server_public.pem", "rb") as f:
    pkS = serialization.load_pem_public_key(f.read())

server_addr = ("127.0.0.1", 5005)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Step 1: Send [Client_ID, Nonce_C, Ephemeral Public Key]
nonce_c = os.urandom(16)
client_eph_pub = hsm.get_ephemeral_public_bytes()

msg1 = {
    'client_id': 'IoT_Device_01',
    'nonce_c': base64.b64encode(nonce_c).decode(),
    'client_eph_pub': base64.b64encode(client_eph_pub).decode()
}
sock.sendto(json.dumps(msg1).encode(), server_addr)
print("[Step 1] Sent Identity, Nonce_C, and Ephemeral Public Key")

# Step 2: Receive and verify Server parameters
data, _ = sock.recvfrom(2048)
msg2 = json.loads(data.decode())
nonce_s = base64.b64decode(msg2['nonce_s'])
server_eph_pub = base64.b64decode(msg2['server_eph_pub'])
signature_s = base64.b64decode(msg2['signature_s'])

try:
    pkS.verify(signature_s, nonce_c + nonce_s + client_eph_pub + server_eph_pub, ec.ECDSA(hashes.SHA256()))
    print("[Step 2] Server Identity Verified.")
except Exception as e:
    print(f"[!] Server Auth failed: {e}")
    exit(1)

# Step 3: Derive AES Key, Sign, and Encrypt Payload
aes_key = hsm.derive_session_key(server_eph_pub)
aesgcm = AESGCM(aes_key)

# The HSM securely signs the cryptographic binding
signature_c = hsm.sign_data(nonce_s + nonce_c + server_eph_pub + client_eph_pub)

# Prepare secret payload
payload = {
    'signature_c': base64.b64encode(signature_c).decode(),
    'sensor_data': 'TOP_SECRET_FIRMWARE_METRIC_99'
}

# Encrypt the payload using AES-GCM
iv = os.urandom(12)
ciphertext = aesgcm.encrypt(iv, json.dumps(payload).encode(), None)

msg3 = {
    'iv': base64.b64encode(iv).decode(),
    'ciphertext': base64.b64encode(ciphertext).decode()
}
sock.sendto(json.dumps(msg3).encode(), server_addr)
print("[Step 3] Sent Encrypted Signature and Payload. Session Secure.")
