import os
import shutil
import json
from obsidian.core.memory import SecureBuffer
from obsidian.core.processor import ObsidianProcessor

def test_full_encryption_flow():
    print("\n[TEST] Starting Full File Processing Test...")
    
    test_dir = "temp_test_data"
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)
    os.makedirs(test_dir)

    src_file = os.path.join(test_dir, "secret_doc.txt")
    with open(src_file, "w") as f:
        f.write("This is a super secret document that needs double encryption!" * 100)
    
    output_dir = os.path.join(test_dir, "encrypted_backup")
    
    password = SecureBuffer("MyStrongPass")
    processor = ObsidianProcessor()
    
    processor.encrypt_file(src_file, password, output_dir)
    
    manifest_path = os.path.join(output_dir, "manifest.json")
    
    assert os.path.exists(manifest_path)
    
    with open(manifest_path, 'r') as f:
        data = json.load(f)
        print(f"[CHECK] Manifest Salt: {data['kdf_salt_hex']}")
        assert 'kdf_salt_hex' in data
        assert len(data['kdf_salt_hex']) == 32
        
        chunks = data['chunks']
        assert len(chunks) > 0
        first_chunk_name = chunks[0]['filename']
        assert os.path.exists(os.path.join(output_dir, first_chunk_name))
        
    print("[SUCCESS] File processed, encrypted, and manifest created correctly.")
    

if __name__ == "__main__":
    test_full_encryption_flow()