from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def generate_keys(prefix):
    private_key = ec.generate_private_key(ec.SECP256R1())
    
    # Save Private Key
    with open(f"{prefix}_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
        
    # Save Public Key
    with open(f"{prefix}_public.pem", "wb") as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

generate_keys("server")
generate_keys("client")
print("Keypairs generated successfully.")
