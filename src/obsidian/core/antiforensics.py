import sys
import ctypes
import platform

# -----------------------------------------------------------------------------
# Anti-Forensics Module
# Prevents memory dumps and suppresses error logs during crashes.
# -----------------------------------------------------------------------------

def _disable_core_dumps_linux():
    """
    Disables core dumps on Linux using prctl syscall.
    Prevents RAM contents from being written to disk on crash.
    """
    try:
        # PR_SET_DUMPABLE = 4 (Option)
        # SUID_DUMP_DISABLE = 0 (Arg2)
        libc = ctypes.CDLL("libc.so.6")
        
        # prctl(PR_SET_DUMPABLE, SUID_DUMP_DISABLE, 0, 0, 0)
        result = libc.prctl(4, 0, 0, 0, 0)
        
        if result != 0:
            # DO: keep for debugging if needed
            pass 
    except Exception:
        # silence if exception (Fail-Safe)
        pass

def _disable_error_reporting_windows():
    """
    Disables Windows Error Reporting (WER) dialogs.
    Prevents 'MiniDumpWriteDump' from saving memory to disk.
    """
    try:
        kernel32 = ctypes.windll.kernel32
        # SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX
        kernel32.SetErrorMode(0x0001 | 0x0002)
    except Exception:
        pass

def _secure_exception_hook(exc_type, exc_value, exc_traceback):
    """
    Replaces the default Python exception handler.
    Suppresses traceback printing to avoid leaking variable values in logs.
    """
    print("\n[CRITICAL SECURITY ALERT] An unhandled exception occurred.")
    print(f"Error Type: {exc_type.__name__}")
    print("Full traceback suppressed for security.")
    

    sys.exit(1)

def activate_shield():
    """
    Activates all anti-forensics mechanisms based on the OS.
    Should be called at the very start of the program.
    """
    sys.excepthook = _secure_exception_hook
    
    current_os = platform.system()
    
    if current_os == "Linux":
        _disable_core_dumps_linux()
    elif current_os == "Windows":
        _disable_error_reporting_windows()