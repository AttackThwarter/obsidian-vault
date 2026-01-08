import os
import shutil
import hashlib
from obsidian.core.memory import SecureBuffer
from obsidian.core.processor import ObsidianProcessor

def calculate_file_hash(filepath):
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

def test_full_cycle_backup_restore():
    print("\n[TEST] Starting Full Encrypt/Decrypt Cycle...")
    
    test_dir = "temp_test_cycle"
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)
    os.makedirs(test_dir)

    src_file = os.path.join(test_dir, "top_secret.pdf") 
    original_content = b"Super Secret Data " * 5000 
    with open(src_file, "wb") as f:
        f.write(original_content)
    
    original_hash = calculate_file_hash(src_file)
    print(f"[INFO] Original File Hash: {original_hash}")

    backup_dir = os.path.join(test_dir, "backup_vault")
    restore_dir = os.path.join(test_dir, "restored_data")
    os.makedirs(restore_dir)

    password = SecureBuffer("CorrectBatteryHorseStaple")
    processor = ObsidianProcessor()

    print("\n--- PHASE 1: ENCRYPTION ---")
    processor.encrypt_file(src_file, password, backup_dir)

    print("\n--- PHASE 2: DECRYPTION ---")
    processor.decrypt_file(backup_dir, password, restore_dir)

    restored_file = os.path.join(restore_dir, "top_secret.pdf")
    assert os.path.exists(restored_file)
    
    restored_hash = calculate_file_hash(restored_file)
    print(f"[INFO] Restored File Hash: {restored_hash}")

    if original_hash == restored_hash:
        print("\n[SUCCESS] INTEGRITY CONFIRMED! The restored file is identical to the original.")
    else:
        print("\n[FAIL] DATA CORRUPTION! Hashes do not match.")
        assert False



if __name__ == "__main__":
    test_full_cycle_backup_restore()