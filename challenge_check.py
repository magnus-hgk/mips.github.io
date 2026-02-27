import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization

def challenge_check(pub_pem, priv_pem):
    challenge = os.urandom(32) 
    print(f"Server Challenge: {challenge.hex()}")

    # client signs the challenge using their Private Key
    # PEM string back to  key object
    signing_key = serialization.load_pem_private_key(priv_pem.encode(), password=None)
    signature = signing_key.sign(
        challenge,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )


    # Server verifies
    verifying_key = serialization.load_pem_public_key(pub_pem.encode())

    try:
        verifying_key.verify(
            signature,
            challenge,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        print("\n RSA Verification Failed: Invalid Signature.")

        return False 
    
