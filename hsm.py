import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class VirtualHSM:
    def __init__(self, key_path):
        # 1. Load Long-Term Identity Key (in a real HSM, this is burned into silicon)
        with open(key_path, "rb") as f:
            self._identity_key = serialization.load_pem_private_key(f.read(), password=None)
        
        # 2. Generate Ephemeral Key for Perfect Forward Secrecy
        self._ephemeral_key = ec.generate_private_key(ec.SECP256R1())
        self.aes_key = None

    def get_ephemeral_public_bytes(self):
        return self._ephemeral_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def sign_data(self, data):
        # Application asks HSM to sign, but cannot see the private key
        return self._identity_key.sign(data, ec.ECDSA(hashes.SHA256()))

    def derive_session_key(self, peer_ephemeral_pub_bytes):
        # Application passes in the Server's ephemeral key to derive AES-GCM
        peer_pub = serialization.load_pem_public_key(peer_ephemeral_pub_bytes)
        shared_secret = self._ephemeral_key.exchange(ec.ECDH(), peer_pub)
        
        # Use HKDF to convert the shared secret into a strong 256-bit AES key
        self.aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_secret)
        return self.aes_key
