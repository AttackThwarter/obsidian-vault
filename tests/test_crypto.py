from obsidian.core.memory import SecureBuffer
from obsidian.crypto.kdf import KeyDerivationManager

def test_kdf_generation():
    print("\n[TEST] Starting Key Derivation Test...")
    print("[TEST] This might take a few seconds due to Argon2 hardness...")
    
    password = "MyStrongPassword123"
    
    with SecureBuffer(password) as sec_pass:
        salt = KeyDerivationManager.generate_salt()
        print(f"[TEST] Generated Salt: {salt.hex()}")
        
        keys = KeyDerivationManager.derive_keys(sec_pass, salt)
        
        print(f"[TEST] Key Serpent: {keys.key_serpent.hex()[:10]}... (Len: {len(keys.key_serpent)})")
        print(f"[TEST] Key AES:     {keys.key_aes.hex()[:10]}... (Len: {len(keys.key_aes)})")
        
        assert len(keys.key_serpent) == 32
        assert len(keys.key_twofish) == 32
        assert len(keys.key_aes) == 32
        assert len(keys.key_hmac) == 32
        
        assert keys.key_serpent != keys.key_aes
        
        print("[SUCCESS] All keys generated correctly and are distinct.")

# if __name__ == "__main__":
#     test_kdf_generation()


from obsidian.crypto.engines import AesGcmEngine, ChaCha20Poly1305Engine

def test_crypto_engines():
    print("\n[TEST] Starting Crypto Engines Test...")
    
    plaintext = b"This is a ultra secret message for testing engines."
    dummy_key = b"A" * 32 
    
    engines = [AesGcmEngine(), ChaCha20Poly1305Engine()]
    
    for engine in engines:
        print(f"--- Testing {engine.algorithm_name} ---")
        
        encrypted = engine.encrypt(plaintext, dummy_key)
        print(f"[*] Encrypted size: {len(encrypted)} bytes")
        
        assert encrypted != plaintext
        assert plaintext not in encrypted
        
        decrypted = engine.decrypt(encrypted, dummy_key)
        print(f"[*] Decrypted successfully.")
        
        assert decrypted == plaintext
        
        tampered_data = encrypted[:-1] + b'\x00'
        try:
            engine.decrypt(tampered_data, dummy_key)
            print("[FAIL] Engine accepted tampered data!")
            assert False
        except ValueError:
            print("[PASS] Engine detected tampering correctly.")

    print("[SUCCESS] All engines passed security checks.")

if __name__ == "__main__":
    test_kdf_generation() 
    test_crypto_engines()