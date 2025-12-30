import sys
import ctypes
import atexit
from typing import List, Optional 


_os_type = sys.platform

if _os_type == "win32":
    _kernel32 = ctypes.windll.kernel32
    _VirtualLock = _kernel32.VirtualLock
    _VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    _VirtualLock.restype = ctypes.c_int
    _VirtualUnlock = _kernel32.VirtualUnlock
    _VirtualUnlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    _VirtualUnlock.restype = ctypes.c_int
    _GetLastError = _kernel32.GetLastError
elif _os_type.startswith("linux") or _os_type == "darwin":
    _libc = ctypes.CDLL("libc.so.6")
    _mlock = _libc.mlock
    _mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    _mlock.restype = ctypes.c_int
    _munlock = _libc.munlock
    _munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    _munlock.restype = ctypes.c_int
else:
    raise RuntimeError(f"Unsupported Operating System: {_os_type}")

# -----------------------------------------------------------------------------
# Global Registry for Emergency Cleanup
# -----------------------------------------------------------------------------

_active_buffers: List['SecureBuffer'] = []

def _emergency_cleanup():
    """
    Cleans up all active SecureBuffers on program exit.

    """
    for buf in _active_buffers:
        try:
            buf.zero_out()
        except:
            pass


atexit.register(_emergency_cleanup)


class SecureBuffer:
    def __init__(self, sensitive_data: bytes | str):
        if isinstance(sensitive_data, str):
            sensitive_data = sensitive_data.encode("utf-8")
        
        self._size = len(sensitive_data)

        self._buffer = ctypes.create_string_buffer(sensitive_data, self._size)
        self._address = ctypes.addressof(self._buffer)
        self._locked = False
        

        self._lock_memory()
        

        _active_buffers.append(self)

    def _lock_memory(self):
        success = False
        if _os_type == "win32":
            if _VirtualLock(self._address, self._size) != 0:
                success = True
            else:
                # error handling -> working set
                # DO: handle in final version
                pass 
        else:
            if _mlock(self._address, self._size) == 0:
                success = True
        self._locked = success

    def _unlock_memory(self):
        if not self._locked:
            return
        if _os_type == "win32":
            _VirtualUnlock(self._address, self._size)
        else:
            _munlock(self._address, self._size)
        self._locked = False

    def zero_out(self):
        """Overwrites memory with zeros."""
        if self._size > 0:
            ctypes.memset(self._address, 0, self._size)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.zero_out()
        self._unlock_memory()
        if self in _active_buffers:
            _active_buffers.remove(self)
        return False

    @property
    def value(self) -> bytes:
        return self._buffer.raw

    def __del__(self):
        self.zero_out()
        self._unlock_memory()
        if self in _active_buffers:
            _active_buffers.remove(self)