import ctypes
from obsidian.core.memory import SecureBuffer

def test_secure_buffer_lifecycle():
    secret = "TopSecretPassword"
    

    with SecureBuffer(secret) as buf:

        assert buf.value == b"TopSecretPassword"
        
        address = buf._address
        
        data_in_memory = ctypes.string_at(address, len(secret))
        print(f"\n[TEST] Data inside lock: {data_in_memory}")
        assert data_in_memory == b"TopSecretPassword"

    data_after_exit = ctypes.string_at(address, len(secret))
    print(f"[TEST] Data after exit: {data_after_exit}")
    
    assert data_after_exit == b'\x00' * len(secret)
    print("[SUCCESS] Memory was successfully zeroed out!")

if __name__ == "__main__":
    test_secure_buffer_lifecycle()