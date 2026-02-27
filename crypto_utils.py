import base64
import secrets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Statisk salt til projektet (for at sikre konsistens i vores test)
PROJECT_SALT = b'mips_semester_2_aau'

class ECDHUser:
    def __init__(self):
        # Generer privat nøgle
        self.__private_key = ec.generate_private_key(ec.SECP256R1())
        # Generer offentlig nøgle
        self.public_key = self.__private_key.public_key()

    def get_public_key_b64(self):
        """Konverterer nøglen til en Base64-streng, der kan gemmes i db.Text."""
        key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        return base64.b64encode(key_bytes).decode('utf-8')

    def compute_aes_key(self, remote_public_key_b64):
        """Modtager Base64 fra databasen og beregner AES-nøglen."""
        # Dekod Base64 tilbage til bytes og objekt
        remote_bytes = base64.b64decode(remote_public_key_b64)
        remote_pub_key_obj = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), remote_bytes
        )
        
        # Beregn shared secret
        shared_secret = self.__private_key.exchange(ec.ECDH(), remote_pub_key_obj)
        
        # Deriver den endelige AES-nøgle
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=PROJECT_SALT,
            info=b'mips ecdhe key exchange',
        )
        return hkdf.derive(shared_secret)
