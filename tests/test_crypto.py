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

if __name__ == "__main__":
    test_kdf_generation()