from Cryptodome.Cipher import AES, ChaCha20_Poly1305
from Cryptodome.Random import get_random_bytes
from obsidian.crypto.interfaces import ICryptoEngine

class AesGcmEngine(ICryptoEngine):
    """
    Implementation of AES-256 in GCM (Galois/Counter Mode).
    Features:
    - Confidentiality (Encryption)
    - Authenticity (Integrity Check via Tag)
    - 256-bit Key Strength
    """
    
    @property
    def algorithm_name(self) -> str:
        return "AES-256-GCM"

    def encrypt(self, data: bytes, key: bytes) -> bytes:
        # 1. Validate Key Size (Must be 32 bytes for AES-256)
        if len(key) != 32:
            raise ValueError("AES-256 requires a 32-byte key.")

        # 2. Create Cipher Object

        nonce = get_random_bytes(12)  # 96-bit nonce is recommended for GCM
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        # 3. Encrypt and Sign (Digest)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        # 4. Return bundled data: Nonce + Tag + Ciphertext

        return nonce + tag + ciphertext

    def decrypt(self, encrypted_data: bytes, key: bytes) -> bytes:
        if len(key) != 32:
            raise ValueError("AES-256 requires a 32-byte key.")
        
        # Unpack the bundle
        # GCM Nonce = 12 bytes
        # GCM Tag = 16 bytes
        if len(encrypted_data) < 28:
            raise ValueError("Data too short to be AES-GCM encrypted.")

        nonce = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]

        # Create Cipher for Decryption
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        # Decrypt and Verify
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext
        except ValueError:
            # This error means either the key is wrong or the file has been tampered with.
            raise ValueError("Decryption failed: Integrity check error or wrong key.")


class ChaCha20Poly1305Engine(ICryptoEngine):
    """
    Implementation of ChaCha20-Poly1305.
    Features:
    - High speed stream cipher (ARX design).
    - Immunized against timing attacks.
    - Full Authenticated Encryption (AEAD).
    """

    @property
    def algorithm_name(self) -> str:
        return "ChaCha20-Poly1305"

    def encrypt(self, data: bytes, key: bytes) -> bytes:
        if len(key) != 32:
            raise ValueError("ChaCha20 requires a 32-byte key.")

        # ChaCha20 Nonce is usually 12 bytes (96 bits) or 8 bytes.
        # PyCryptodome default is 8, but 12 is allowed and standard in RFC 8439.
        nonce = get_random_bytes(12)
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)

        ciphertext, tag = cipher.encrypt_and_digest(data)

        # Structure: Nonce (12) + Tag (16) + Ciphertext
        return nonce + tag + ciphertext

    def decrypt(self, encrypted_data: bytes, key: bytes) -> bytes:
        if len(key) != 32:
            raise ValueError("ChaCha20 requires a 32-byte key.")

        if len(encrypted_data) < 28: # 12 + 16
            raise ValueError("Data too short.")

        nonce = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]

        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)

        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext
        except ValueError:
            raise ValueError("ChaCha20 Decryption failed: Integrity check error.")