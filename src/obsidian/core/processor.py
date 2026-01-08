import os
import json
import time
import hashlib
from typing import List, Dict
from dataclasses import dataclass, asdict

from obsidian.core.memory import SecureBuffer
from obsidian.crypto.kdf import KeyDerivationManager
from obsidian.crypto.engines import AesGcmEngine, ChaCha20Poly1305Engine
from obsidian.utils.io_streams import FileStreamer

@dataclass
class EncryptedChunkMeta:
    index: int
    filename: str       
    original_size: int
    encrypted_size: int
    hash_sha256: str    

@dataclass
class Manifest:
    version: str = "1.0"
    timestamp: float = 0.0
    original_filename: str = ""
    kdf_salt_hex: str = ""      
    kdf_params: Dict[str, int] = None 
    encryption_pipeline: List[str] = None
    chunks: List[EncryptedChunkMeta] = None

class ObsidianProcessor:
    def __init__(self):
        self.engines = [
            ChaCha20Poly1305Engine(), 
            AesGcmEngine()
        ]

    # =========================================================
    #  encrypt_file
    # =========================================================
    def encrypt_file(self, file_path: str, password: SecureBuffer, output_dir: str):

        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        print("[*] Generating Salt and Deriving Keys...")
        salt = KeyDerivationManager.generate_salt()
        keys = KeyDerivationManager.derive_keys(password, salt)
        
        engine_keys = [keys.key_twofish, keys.key_aes] 

        manifest_data = Manifest(
            timestamp=time.time(),
            original_filename=os.path.basename(file_path),
            kdf_salt_hex=salt.hex(),
            kdf_params={
                "time": KeyDerivationManager.ARGON_TIME_COST,
                "memory": KeyDerivationManager.ARGON_MEMORY_COST,
                "threads": KeyDerivationManager.ARGON_PARALLELISM
            },
            encryption_pipeline=[e.algorithm_name for e in self.engines],
            chunks=[]
        )

        print(f"[*] Starting encryption pipeline for: {file_path}")
        chunk_gen = FileStreamer.file_chunk_generator(file_path)
        
        chunk_index = 0
        for raw_chunk in chunk_gen:
            chunk_index += 1
            current_data = raw_chunk
            original_len = len(raw_chunk)

            for engine, key in zip(self.engines, engine_keys):
                current_data = engine.encrypt(current_data, key)
            
            out_filename = f"chunk_{chunk_index:04d}.obs"
            out_path = os.path.join(output_dir, out_filename)

            with open(out_path, 'wb') as f_out:
                f_out.write(current_data)

            file_hash = hashlib.sha256(current_data).hexdigest()

            meta = EncryptedChunkMeta(
                index=chunk_index,
                filename=out_filename,
                original_size=original_len,
                encrypted_size=len(current_data),
                hash_sha256=file_hash
            )
            manifest_data.chunks.append(meta)
            
            print(f"   -> Encrypted Chunk #{chunk_index} | Size: {len(current_data)/1024/1024:.2f} MB")

        manifest_path = os.path.join(output_dir, "manifest.json")
        with open(manifest_path, 'w') as f_man:
            json.dump(asdict(manifest_data), f_man, indent=4)
        
        print(f"[*] Encryption Complete. Manifest saved at: {manifest_path}")

    # =========================================================
    #  decrypt_file
    # =========================================================
    def decrypt_file(self, backup_dir: str, password: SecureBuffer, output_path: str):

        manifest_path = os.path.join(backup_dir, "manifest.json")
        if not os.path.exists(manifest_path):
            raise FileNotFoundError("Manifest file not found. Cannot restore backup.")

        print(f"[*] Loading Manifest from: {manifest_path}")
        with open(manifest_path, 'r') as f:
            manifest_dict = json.load(f)
        
        salt_hex = manifest_dict['kdf_salt_hex']
        salt = bytes.fromhex(salt_hex)

        keys = KeyDerivationManager.derive_keys(password, salt)
        engine_keys = [keys.key_twofish, keys.key_aes]
        
        if os.path.isdir(output_path):
            final_out_path = os.path.join(output_path, manifest_dict['original_filename'])
        else:
            final_out_path = output_path

        print(f"[*] Restoring to: {final_out_path}")
        
        with open(final_out_path, 'wb') as f_out:
            chunks = sorted(manifest_dict['chunks'], key=lambda x: x['index'])
            
            for chunk_meta in chunks:
                chunk_path = os.path.join(backup_dir, chunk_meta['filename'])
                
                with open(chunk_path, 'rb') as f_in:
                    encrypted_data = f_in.read()

                current_hash = hashlib.sha256(encrypted_data).hexdigest()
                if current_hash != chunk_meta['hash_sha256']:
                    raise ValueError(f"CORRUPTION DETECTED in chunk {chunk_meta['index']}! Hash mismatch.")

                current_data = encrypted_data
                for engine, key in zip(reversed(self.engines), reversed(engine_keys)):
                    current_data = engine.decrypt(current_data, key)
                
                f_out.write(current_data)
                print(f"   -> Restored Chunk #{chunk_meta['index']}")

        print("[SUCCESS] File restored successfully.")