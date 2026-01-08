from abc import ABC, abstractmethod

class ICryptoEngine(ABC):
    """
    Interface (Contract) for all encryption algorithms.
    Any new algorithm (AES, Serpent, Post-Quantum) MUST follow this template.
    This ensures the main program doesn't care 'which' algorithm is running.
    """

    @property
    @abstractmethod
    def algorithm_name(self) -> str:
        """Returns the name of the algorithm (e.g., 'AES-256-GCM')."""
        pass

    @abstractmethod
    def encrypt(self, data: bytes, key: bytes) -> bytes:
        """
        Encrypts the data.
        :param data: Raw plaintext bytes.
        :param key: 32-byte secure key.
        :return: Encrypted bytes (Ciphertext + Nonce/IV + Tag).
        """
        pass

    @abstractmethod
    def decrypt(self, encrypted_data: bytes, key: bytes) -> bytes:
        """
        Decrypts the data.
        :param encrypted_data: Ciphertext bytes.
        :param key: 32-byte secure key.
        :return: Raw plaintext bytes.
        :raises: ValueError if decryption/authentication fails.
        """
        pass