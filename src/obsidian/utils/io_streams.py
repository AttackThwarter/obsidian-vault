import os
from typing import Generator, BinaryIO

class FileStreamer:
    """
    Handles reading large files in memory-efficient chunks.
    This prevents RAM from filling up when processing huge backups.
    """
    
    DEFAULT_CHUNK_SIZE = 64 * 1024 * 1024 

    @staticmethod
    def file_chunk_generator(file_path: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> Generator[bytes, None, None]:
        """
        A generator that yields chunks of the file.
        Using 'yield' ensures we only hold one chunk in RAM at a time.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        total_size = os.path.getsize(file_path)
        read_bytes = 0

        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                
                yield chunk
                read_bytes += len(chunk)