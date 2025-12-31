import os
from dataclasses import dataclass
from typing import Tuple
import argon2
from argon2 import Type
from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.Hash import SHA512

from obsidian.core.memory import SecureBuffer

@dataclass
class DerivedKeys:
    """
    Secure storage of derived keys.
    Each key will be exactly 32 bytes (256 bits).
    """
    key_serpent: bytes
    key_twofish: bytes
    key_aes: bytes
    key_hmac: bytes

class KeyDerivationManager:
    """
    Responsible for converting a plaintext password into a set of encryption keys.
    Uses a combination of Argon2id (for difficulty) and HKDF (for differentiation).
    """
    
    # 1GB RAM cost, 4 parallel threads, 4 iterations
    ARGON_MEMORY_COST = 1024 * 1024
    ARGON_TIME_COST = 4
    ARGON_PARALLELISM = 4
    ARGON_HASH_LEN = 64

    @staticmethod
    def generate_salt() -> bytes:
        """Generates a random 16-byte salt."""
        return os.urandom(16)

    @classmethod
    def derive_keys(cls, password: SecureBuffer, salt: bytes) -> DerivedKeys:
        """
        The Core Logic:
        Password + Salt -> Argon2id -> MainSecret -> HKDF -> [Key1, Key2, Key3, KeyHMAC]
        """
        
        # 1. Argon2id
        # output is Raw Bytes
        main_secret = argon2.low_level.hash_secret_raw(
            secret=password.value,
            salt=salt,
            time_cost=cls.ARGON_TIME_COST,
            memory_cost=cls.ARGON_MEMORY_COST,
            parallelism=cls.ARGON_PARALLELISM,
            hash_len=cls.ARGON_HASH_LEN,
            type=Type.ID
        )

        # 2. HKDF : transform Main Secret to multiple keys
        # We use SHA512 as the internal hash function.

        # Define 'info' for each key (Context Binding)
        # This ensures even if Main Secret is the same, outputs are completely different

        # First key: for the Serpent layer
        k_serpent = HKDF(
            master=main_secret,
            key_len=32,
            salt=salt,
            hashmod=SHA512,
            context=b"obsidian-v1-serpent"
        )
        
        # Second key: for the Twofish layer
        k_twofish = HKDF(
            master=main_secret,
            key_len=32,
            salt=salt,
            hashmod=SHA512,
            context=b"obsidian-v1-twofish"
        )

        # Third key: for the AES layer
        k_aes = HKDF(
            master=main_secret,
            key_len=32,
            salt=salt,
            hashmod=SHA512,
            context=b"obsidian-v1-aes"
        )
        
        # Fourth key: To sign the manifesto
        k_hmac = HKDF(
            master=main_secret,
            key_len=32,
            salt=salt,
            hashmod=SHA512,
            context=b"obsidian-v1-manifest-hmac"
        )

        # Clearing Main Secret from Python memory (as much as possible)
        # Note: Since the output of argon2 is of type bytes (immutable), we cannot zero_out
        # But because it is in function scope, it is freed sooner.
        # DO: (In future versions we can make this even more secure with C-Extension)
        del main_secret

        return DerivedKeys(
            key_serpent=k_serpent,
            key_twofish=k_twofish,
            key_aes=k_aes,
            key_hmac=k_hmac
        )