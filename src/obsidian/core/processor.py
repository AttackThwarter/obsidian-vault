import os
import json
import time
import hashlib
from typing import List, Dict, Any
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
    # ---------------------------
    encryption_pipeline: List[str] = None
    chunks: List[EncryptedChunkMeta] = None

class ObsidianProcessor:
    def __init__(self):
        self.engines = [
            ChaCha20Poly1305Engine(), 
            AesGcmEngine()
        ]

    def encrypt_file(self, file_path: str, password: SecureBuffer, output_dir: str):
        """
        Main orchestration function:
        1. Generate Keys (Password + Salt)
        2. Chunk File
        3. Encrypt Chunk (Cascade)
        4. Write to Disk
        5. Create Manifest
        """
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
            # DO: change to UUID
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
            
            print(f"   -> Processed Chunk #{chunk_index} | Size: {len(current_data)/1024/1024:.2f} MB")

        manifest_path = os.path.join(output_dir, "manifest.json")
        with open(manifest_path, 'w') as f_man:
            json.dump(asdict(manifest_data), f_man, indent=4)
        
        print(f"[*] Encryption Complete. Manifest saved at: {manifest_path}")
        print(f"[*] SALT SAVED: {salt.hex()}") 