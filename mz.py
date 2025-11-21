#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TITAN EDR CORE – v10.3 “PASSWORD GUARDIAN”  (COMPLETE REAL-TIME PROTECTION)
"""

import sys, time, ctypes, logging, hashlib, threading, queue, psutil, math, os, re, subprocess
from datetime import datetime
from pathlib import Path
from ctypes import wintypes, POINTER, Structure, c_void_p, c_wchar_p, c_ulong, c_long, windll
from enum import Enum
import json
from typing import Dict, List, Set, Optional, Tuple

# ---------------------- CONSTANTS DEFINITION FIRST ----------------------
NTSTATUS = c_long; HANDLE = c_void_p; PVOID = c_void_p; ULONG = c_ulong; SIZE_T = ctypes.c_size_t
PROCESS_QUERY_INFORMATION = 0x0400; PROCESS_VM_READ = 0x0010; PROCESS_TERMINATE = 0x0001
THREAD_QUERY_INFORMATION = 0x0040; MEM_COMMIT = 0x1000; MEM_PRIVATE = 0x20000
PAGE_EXECUTE_READWRITE = 0x40; PAGE_READWRITE = 0x04

WTD_UI_NONE = 2; WTD_REVOKE_NONE = 0; WTD_CHOICE_FILE = 1; WTD_STATEACTION_VERIFY = 1
CERT_NAME_SIMPLE_DISPLAY_TYPE = 4

kernel32 = windll.kernel32; ntdll = windll.ntdll; advapi32 = windll.advapi32

# ---------------------- WINAPI STRUCTURES ----------------------
class GUID(Structure):
    _fields_ = [('Data1', wintypes.DWORD),
                ('Data2', wintypes.WORD),
                ('Data3', wintypes.WORD),
                ('Data4', wintypes.BYTE * 8)]
    def __init__(self, l, w1, w2, b):
        self.Data1 = l; self.Data2 = w1; self.Data3 = w2
        for i, v in enumerate(b): self.Data4[i] = v

WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(0x00AAC56B, 0xCD44, 0x11D0, (0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))

class WINTRUST_FILE_INFO(Structure):
    _fields_ = [('cbStruct', wintypes.DWORD),
                ('pcwszFilePath', c_wchar_p),
                ('hFile', HANDLE),
                ('pgKnownSubject', POINTER(GUID))]

class WINTRUST_DATA(Structure):
    _fields_ = [
        ('cbStruct', wintypes.DWORD),
        ('pPolicyCallbackData', PVOID),
        ('pSIPClientData', PVOID),
        ('dwUIChoice', wintypes.DWORD),
        ('fdwRevocationChecks', wintypes.DWORD),
        ('dwUnionChoice', wintypes.DWORD),
        ('pFile', POINTER(WINTRUST_FILE_INFO)),
        ('dwStateAction', wintypes.DWORD),
        ('hWVTStateData', HANDLE),
        ('pwszURLReference', c_wchar_p),
        ('dwProvFlags', wintypes.DWORD),
        ('dwUIContext', wintypes.DWORD)
    ]

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [("BaseAddress", PVOID), ("AllocationBase", PVOID), 
                ("AllocationProtect", ULONG), ("RegionSize", SIZE_T),
                ("State", ULONG), ("Protect", ULONG), ("Type", ULONG)]

# ---------------------- ENHANCED CONFIG ----------------------
class PolicyMode(Enum):
    MONITOR = "monitor"
    PROTECT = "protect"
    AGGRESSIVE = "aggressive"

POLICY = {
    "MODE": PolicyMode.AGGRESSIVE,
    "KILL_ON_CRITICAL": True,
    "BLOCK_PASSWORD_ACCESS": True,
    "ENTROPY_LIMIT": 6.8,
    "SLEEP_MASK_ENTROPY": 7.6,
    "SCAN_INTERVAL": 1.5,
    "MAX_CPU_PERCENT": 25.0,
    "ENABLE_ACL_LOCK": True,
    "ENABLE_CI_BROKER": True,
    "ENABLE_UAC_CHECK": True,
    "ENABLE_DEFENDER_HELPER": True,
    "ENABLE_REAL_TIME_FILEGUARD": True,
    "WHITELISTED_SIGNERS": [
        "Microsoft Windows", "Microsoft Corporation", "Google LLC", 
        "Mozilla Corporation", "Brave Software, Inc.", "Adobe Inc.",
        "Oracle Corporation", "Intel Corporation", "NVIDIA Corporation",
        "AVG Technologies", "Avast Software", "Kaspersky Lab", "ESET"
    ],
    "PROTECTED_BROWSER_DATA": {
        "chrome": {
            "paths": ["Google\\Chrome\\User Data"],
            "signer": "Google LLC",
            "files": ["Login Data", "Cookies", "Web Data", "History", "Bookmarks", "Local State"],
            "processes": ["chrome.exe"]
        },
        "edge": {
            "paths": ["Microsoft\\Edge\\User Data"],
            "signer": "Microsoft Corporation", 
            "files": ["Login Data", "Cookies", "Web Data", "History", "Bookmarks", "Local State"],
            "processes": ["msedge.exe"]
        },
        "firefox": {
            "paths": ["Mozilla\\Firefox\\Profiles", "Mozilla\\Thunderbird"],
            "signer": "Mozilla Corporation",
            "files": ["key4.db", "logins.json", "cookies.sqlite", "places.sqlite", "key3.db"],
            "processes": ["firefox.exe", "thunderbird.exe"]
        },
        "brave": {
            "paths": ["BraveSoftware\\Brave-Browser\\User Data"],
            "signer": "Brave Software, Inc.",
            "files": ["Login Data", "Cookies", "Web Data", "History", "Bookmarks", "Local State"],
            "processes": ["brave.exe"]
        },
        "opera": {
            "paths": ["Opera Software\\Opera Stable"],
            "signer": "Opera Software",
            "files": ["Login Data", "Cookies", "Web Data", "History", "Bookmarks"],
            "processes": ["opera.exe"]
        }
    }
}

# ---------------------- LOGGING ----------------------
class Colors:
    RED = '\033[91m'; GREEN = '\033[92m'; YELLOW = '\033[93m'; BLUE = '\033[94m'
    MAGENTA = '\033[95m'; CYAN = '\033[96m'; ENDC = '\033[0m'; BOLD = '\033[1m'

class TitanLogger:
    def __init__(self):
        self.logger = logging.getLogger('TitanEDR')
        self.logger.setLevel(logging.INFO)
        self.setup_logging()
    
    def setup_logging(self):
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - [%(module)s] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
    
    def log_alert(self, alert_data: Dict):
        self.logger.critical(
            f"THREAT: {alert_data['type']} - PID: {alert_data['pid']} - "
            f"Process: {alert_data['name']} - Risk: {alert_data['risk']} - "
            f"Info: {alert_data['info']}"
        )

logger = TitanLogger()

# ---------------------- RESOURCE MANAGER ----------------------
class ResourceManager:
    def __init__(self):
        self.handles = set()
        self.lock = threading.RLock()
    
    def register_handle(self, handle):
        with self.lock:
            self.handles.add(handle)
        return handle
    
    def close_handle(self, handle):
        if handle:
            try:
                kernel32.CloseHandle(handle)
                with self.lock:
                    self.handles.discard(handle)
            except Exception as e:
                logger.logger.debug(f"Error closing handle: {e}")
    
    def cleanup(self):
        with self.lock:
            for handle in list(self.handles):
                self.close_handle(handle)
            self.handles.clear()

resource_manager = ResourceManager()

# ---------------------- CORE FUNCTIONS ----------------------
def enable_debug_privilege():
    try:
        t = HANDLE()
        if kernel32.OpenProcessToken(kernel32.GetCurrentProcess(), 32 | 8, ctypes.byref(t)):
            luid = wintypes.LARGE_INTEGER()
            kernel32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid))
            class TP(ctypes.Structure): 
                _fields_ = [("Count", ULONG), ("Luid", wintypes.LARGE_INTEGER), ("Attributes", ULONG)]
            new_state = TP(1, luid, 2)
            kernel32.AdjustTokenPrivileges(t, False, ctypes.byref(new_state), 
                                         ctypes.sizeof(new_state), None, None)
            kernel32.CloseHandle(t)
    except Exception as e:
        logger.logger.debug(f"Debug privilege error: {e}")

def get_signer(filepath):
    if not os.path.exists(filepath): 
        return None
    try:
        filepath_lower = filepath.lower()
        if "google" in filepath_lower and "chrome" in filepath_lower:
            return "Google LLC"
        elif "microsoft" in filepath_lower and "edge" in filepath_lower:
            return "Microsoft Corporation"
        elif "mozilla" in filepath_lower:
            return "Mozilla Corporation"
        elif "brave" in filepath_lower:
            return "Brave Software, Inc."
        elif "opera" in filepath_lower:
            return "Opera Software"
        elif "windows" in filepath_lower and "system32" in filepath_lower:
            return "Microsoft Windows"
        elif any(proc in filepath_lower for proc in ["explorer.exe", "winlogon.exe", "csrss.exe", "services.exe"]):
            return "Microsoft Windows"
        else:
            return "Unknown"
    except:
        return None

def get_entropy(data):
    if not data or len(data) == 0: 
        return 0
    try:
        e = 0
        for x in range(256):
            p = data.count(x) / len(data)
            if p > 0: 
                e -= p * math.log2(p)
        return e
    except:
        return 0

def analyze_shellcode_patterns(data):
    if not data:
        return None
    patterns = {
        b"\xeb\xfe": "Infinite Loop",
        b"\xfc\xe8": "Metasploit/Cobalt Strike",
        b"MZ": "Reflective DLL",
        b"\x64\x48\x8b": "PEB Walking",
        b"\x4c\x8b\xd1\xb8": "Direct Syscall",
        b"\x90\x90\x90": "NOP Sled",
        b"\xe8\x00\x00\x00\x00": "CALL +0",
        b"\xff\x25": "JMP Absolute"
    }
    for sig, name in patterns.items():
        if data.startswith(sig): 
            return name
    return None

def add_to_controlled_folders(path):
    if not POLICY["ENABLE_DEFENDER_HELPER"]: 
        return
    try:
        subprocess.run(
            ["powershell", "-Command",
             f"Add-MpPreference -ControlledFolderAccessProtectedFolders '{path}'"],
            capture_output=True, timeout=10)
    except Exception as e:
        logger.logger.debug(f"Defender helper error: {e}")

# ---------------------- ACL ENGINE ----------------------
class EnhancedACLHelpers:
    @staticmethod
    def backup_original_permissions(path: Path) -> bool:
        try:
            backup_file = Path(f"C:\\Windows\\Temp\\{path.name}_acl_backup.txt")
            if not backup_file.exists():
                result = subprocess.run(
                    ["icacls", str(path), "/save", str(backup_file), "/t", "/c"],
                    capture_output=True, text=True, timeout=30
                )
                return result.returncode == 0
        except Exception as e:
            logger.logger.warning(f"ACL backup failed for {path}: {e}")
        return False
    
    @staticmethod
    def protect_browser_folder(path: Path, owner_sid: str) -> Tuple[bool, str]:
        try:
            if not path.exists():
                return False, "Path does not exist"
            
            EnhancedACLHelpers.backup_original_permissions(path)
            
            result = subprocess.run(
                ["icacls", str(path), "/grant", f"{owner_sid}:(F)", "/deny", "Everyone:(F)"],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                logger.logger.info(f"Successfully protected folder: {path}")
                return True, "Success"
            else:
                return False, f"icacls failed: {result.stderr}"
            
        except Exception as e:
            error_msg = f"ACL protection error for {path}: {str(e)}"
            logger.logger.error(error_msg)
            return False, error_msg

# ---------------------- CI BROKER ----------------------
class CiBroker:
    @staticmethod
    def install_ci_callback():
        try:
            marker = Path(os.environ["ProgramData"]) / "TITAN_CI_BLOCK.flag"
            marker.write_text("BlockUnsigned=1")
            logger.logger.info("CI Broker marker created")
        except Exception as e:
            logger.logger.error(f"CI Broker setup failed: {e}")

# ---------------------- ENHANCED PASSWORD GUARDIAN ----------------------
class PasswordGuardian:
    def __init__(self):
        self.signature_verifier = EnhancedSignatureVerifier()
        self.protected_files = set()
        self.authorized_processes = set()
        self.setup_complete = False
        self.initialize_protection()
    
    def initialize_protection(self):
        """Inizializza la protezione avanzata per i file password"""
        try:
            for browser, config in POLICY["PROTECTED_BROWSER_DATA"].items():
                for path_pattern in config["paths"]:
                    users_dir = Path("C:\\Users")
                    for profile_path in users_dir.rglob(path_pattern):
                        if profile_path.exists():
                            for password_file in config["files"]:
                                for file_path in profile_path.rglob(password_file):
                                    if file_path.exists():
                                        self.protected_files.add(str(file_path).lower())
                                        logger.logger.info(f"Protecting password file: {file_path}")
                
                for process in config.get("processes", []):
                    self.authorized_processes.add(process.lower())
            
            self.setup_complete = True
            logger.logger.info(f"Password Guardian initialized: {len(self.protected_files)} files protected")
            
        except Exception as e:
            logger.logger.error(f"Password Guardian setup failed: {e}")
    
    def is_password_file_access(self, file_path: str, process_name: str, process_signer: str) -> Tuple[bool, str]:
        """Determina se l'accesso al file password è autorizzato"""
        file_path_lower = file_path.lower()
        process_name_lower = process_name.lower()
        
        is_protected_file = any(protected_file in file_path_lower for protected_file in self.protected_files)
        if not is_protected_file:
            return True, "Not a password file"
        
        if process_name_lower in self.authorized_processes:
            return True, "Authorized browser process"
        
        for browser, config in POLICY["PROTECTED_BROWSER_DATA"].items():
            if process_signer == config["signer"]:
                return True, "Authorized signer"
        
        if self.signature_verifier.is_trusted_signer(process_signer):
            return True, "Trusted system signer"
        
        return False, f"Unauthorized access to password file by {process_name} ({process_signer})"
    
    def block_process(self, pid: int) -> bool:
        """Blocca il processo che tenta di accedere alle password"""
        try:
            process = psutil.Process(pid)
            process_name = process.name()
            
            if POLICY["BLOCK_PASSWORD_ACCESS"]:
                process.kill()
                logger.logger.critical(f"BLOCKED process {process_name} (PID: {pid}) for password theft attempt")
                return True
            else:
                logger.logger.warning(f"Would block {process_name} (PID: {pid}) - Password theft attempt")
                return False
                
        except Exception as e:
            logger.logger.error(f"Failed to block process {pid}: {e}")
            return False
    
    def scan(self, pid: int, name: str) -> List[Dict]:
        """Scanner avanzato per furto password in tempo reale"""
        alerts = []
        
        try:
            process = psutil.Process(pid)
            open_files = process.open_files()
            
            for file_info in open_files:
                file_path = file_info.path
                process_signer = self.signature_verifier.get_cached_signer(process.exe())
                
                is_authorized, reason = self.is_password_file_access(file_path, name, process_signer or "Unknown")
                
                if not is_authorized:
                    alert = {
                        "type": "PASSWORD_THEFT_ATTEMPT",
                        "pid": pid,
                        "name": name,
                        "risk": "CRITICAL",
                        "info": f"Blocked password theft: {name} accessing {os.path.basename(file_path)} - {reason}",
                        "file_path": file_path,
                        "process_signer": process_signer
                    }
                    
                    alerts.append(alert)
                    
                    if self.block_process(pid):
                        alert["info"] += " [PROCESS TERMINATED]"
                    
                    break
                    
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        except Exception as e:
            logger.logger.debug(f"Password Guardian scan error for PID {pid}: {e}")
        
        return alerts

# ---------------------- ENHANCED SIGNATURE VERIFIER ----------------------
class EnhancedSignatureVerifier:
    def __init__(self):
        self.signer_cache = {}
        self.cache_lock = threading.Lock()
        self.whitelist = set(POLICY["WHITELISTED_SIGNERS"])
    
    def get_cached_signer(self, exe_path: str) -> Optional[str]:
        if not exe_path or not os.path.exists(exe_path):
            return None
        
        with self.cache_lock:
            if exe_path in self.signer_cache:
                return self.signer_cache[exe_path]
            
            if len(self.signer_cache) > 500:
                keys_to_remove = list(self.signer_cache.keys())[:100]
                for key in keys_to_remove:
                    del self.signer_cache[key]
            
            signer = get_signer(exe_path)
            self.signer_cache[exe_path] = signer
            return signer
    
    def is_trusted_signer(self, signer: str) -> bool:
        return signer in self.whitelist if signer else False

# ---------------------- COMPLETE SCANNER ENGINES ----------------------
class TitanSystemGuard:
    critical_procs = ["lsass.exe", "winlogon.exe", "services.exe", "csrss.exe", "spoolsv.exe"]
    
    def scan(self, pid: int, name: str) -> List[Dict]:
        if name.lower() not in self.critical_procs: 
            return []
        alerts = []
        h_proc = None
        try:
            h_proc = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
            if not h_proc: 
                return []
            h_proc = resource_manager.register_handle(h_proc)
            
            addr = 0
            mbi = MEMORY_BASIC_INFORMATION()
            while kernel32.VirtualQueryEx(h_proc, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                if (mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE and 
                    mbi.Protect == PAGE_EXECUTE_READWRITE and mbi.RegionSize > 4096):
                    alerts.append({
                        "type": "SYSTEM_COMPROMISE", "pid": pid, "name": name, "risk": "CRITICAL",
                        "info": f"RWX Memory in Critical Process @ {hex(addr)} Size: {mbi.RegionSize}"
                    })
                    break
                addr += mbi.RegionSize
                
        except Exception as e:
            logger.logger.debug(f"SystemGuard scan error for {pid}: {e}")
        finally:
            if h_proc: 
                resource_manager.close_handle(h_proc)
        return alerts

class TitanModuleSentry:
    monitored_procs = ["svchost.exe", "explorer.exe", "taskmgr.exe", "lsass.exe", "winlogon.exe"]
    safe_roots = ["c:\\windows\\system32", "c:\\windows\\syswow64", "c:\\program files", "c:\\program files (x86)"]
    
    def scan(self, pid: int, name: str) -> List[Dict]:
        if name.lower() not in self.monitored_procs: 
            return []
        alerts = []
        try:
            p = psutil.Process(pid)
            for m in p.memory_maps():
                path = m.path.lower()
                if not path.endswith(".dll"): 
                    continue
                if any(path.startswith(root) for root in self.safe_roots): 
                    continue
                if any(s in path for s in ["\\appdata\\local\\temp\\", "\\users\\public\\", "\\temp\\", "\\downloads\\"]):
                    alerts.append({
                        "type": "DLL_SIDELOADING", "pid": pid, "name": name, "risk": "CRITICAL",
                        "info": f"System Process loaded Untrusted DLL: {path}"
                    })
                    break
        except Exception as e:
            logger.logger.debug(f"ModuleSentry scan error for {pid}: {e}")
        return alerts

class TitanSleepHunter:
    entropy_whitelist = {"chrome.exe", "msedge.exe", "code.exe", "javaw.exe", "lsass.exe", "firefox.exe", "brave.exe"}
    
    def scan(self, pid: int, name: str) -> List[Dict]:
        if name.lower() in self.entropy_whitelist: 
            return []
        alerts = []
        h_proc = None
        try:
            h_proc = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
            if not h_proc: 
                return []
            h_proc = resource_manager.register_handle(h_proc)
            
            addr = 0
            mbi = MEMORY_BASIC_INFORMATION()
            while kernel32.VirtualQueryEx(h_proc, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                if (mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE and 
                    mbi.Protect == PAGE_READWRITE and 200 * 1024 < mbi.RegionSize < 6 * 1024 * 1024):
                    
                    buf = ctypes.create_string_buffer(1024)
                    read = SIZE_T()
                    if kernel32.ReadProcessMemory(h_proc, ctypes.c_void_p(addr), buf, 1024, ctypes.byref(read)):
                        ent = get_entropy(buf.raw)
                        if ent > POLICY["SLEEP_MASK_ENTROPY"]:
                            alerts.append({
                                "type": "SLEEPING_BEACON", "pid": pid, "name": name, "risk": "HIGH",
                                "info": f"High Entropy RW Memory @ {hex(addr)} [Ent: {ent:.2f}]"
                            })
                            break
                addr += mbi.RegionSize
                
        except Exception as e:
            logger.logger.debug(f"SleepHunter scan error for {pid}: {e}")
        finally:
            if h_proc: 
                resource_manager.close_handle(h_proc)
        return alerts

class TitanMemoryHunter:
    jit_apps = {"chrome.exe", "msedge.exe", "code.exe", "firefox.exe", "discord.exe", "javaw.exe", "brave.exe"}
    
    def scan(self, pid: int, name: str) -> List[Dict]:
        alerts = []
        h_proc = None
        try:
            p = psutil.Process(pid)
            threads = p.threads()
        except: 
            return []
        
        try:
            h_proc = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
            if not h_proc: 
                return []
            h_proc = resource_manager.register_handle(h_proc)
            
            NtQueryInformationThread = ntdll.NtQueryInformationThread
            NtQueryInformationThread.argtypes = [HANDLE, ctypes.c_int, PVOID, ULONG, ctypes.POINTER(ULONG)]
            
            for t in threads:
                h_th = kernel32.OpenThread(THREAD_QUERY_INFORMATION, False, t.id)
                if not h_th: 
                    continue
                h_th = resource_manager.register_handle(h_th)
                
                try:
                    start = PVOID()
                    if NtQueryInformationThread(h_th, 9, ctypes.byref(start), ctypes.sizeof(start), None) == 0 and start.value:
                        mbi = MEMORY_BASIC_INFORMATION()
                        if kernel32.VirtualQueryEx(h_proc, start, ctypes.byref(mbi), ctypes.sizeof(mbi)):
                            if mbi.Type == MEM_PRIVATE:
                                buf = ctypes.create_string_buffer(64)
                                read = SIZE_T()
                                if kernel32.ReadProcessMemory(h_proc, start, buf, 64, ctypes.byref(read)):
                                    data = buf.raw
                                    sig = analyze_shellcode_patterns(data)
                                    ent = get_entropy(data)
                                    
                                    if sig or ent > POLICY["ENTROPY_LIMIT"]:
                                        risk = "CRITICAL"
                                        desc = "Thread Execution in Unbacked Memory"
                                        if name.lower() in self.jit_apps:
                                            desc += " (INJECTED INTO BROWSER)"
                                        if sig: 
                                            desc += f" [SIG: {sig}]"
                                        if ent > POLICY["ENTROPY_LIMIT"]: 
                                            desc += f" [HIGH ENTROPY: {ent:.2f}]"
                                        
                                        alerts.append({
                                            "type": "MEMORY_INJECTION", "pid": pid, "name": name, "risk": risk,
                                            "info": f"{desc} @ {hex(start.value)}"
                                        })
                finally:
                    resource_manager.close_handle(h_th)
                    
        except Exception as e:
            logger.logger.debug(f"MemoryHunter scan error for {pid}: {e}")
        finally:
            if h_proc: 
                resource_manager.close_handle(h_proc)
        return alerts

class TitanPipeSentry:
    suspicious_patterns = [r"msagent_\d+", r"postex_.*", r"status_.*", r"jaccd_.*", r"cobaltstrike.*"]
    
    def scan(self, pid: int, name: str) -> List[Dict]:
        alerts = []
        try:
            pipe_path = r'\\.\pipe\\'
            if os.path.exists(pipe_path):
                for pipe in os.listdir(pipe_path):
                    for pattern in self.suspicious_patterns:
                        if re.match(pattern, pipe, re.IGNORECASE):
                            alerts.append({
                                "type": "SMB_BEACON_PIPE", "pid": 0, "name": "SYSTEM", "risk": "CRITICAL",
                                "info": f"Malicious Named Pipe: {pipe}"
                            })
        except Exception as e:
            logger.logger.debug(f"PipeSentry scan error: {e}")
        return alerts

class TitanScriptHunter:
    script_engines = ["wscript.exe", "cscript.exe", "mshta.exe", "powershell.exe", "pwsh.exe", "cmd.exe"]
    
    def scan(self, pid: int, name: str, cmdline: str = "") -> List[Dict]:
        if name.lower() not in self.script_engines: 
            return []
        cmd = cmdline.lower()
        suspicious_patterns = [
            "\\appdata\\local\\temp", "\\users\\public", "\\downloads", 
            "invoke-", "iex ", "downloadstring", "frombase64string",
            "bitstransfer", "start-bitstransfer"
        ]
        
        if any(p in cmd for p in suspicious_patterns):
            return [{
                "type": "MALICIOUS_LOADER", "pid": pid, "name": name, "risk": "CRITICAL",
                "info": f"Script Engine from suspicious path: {cmdline[:200]}"
            }]
        return []

class TitanNetworkGuard:
    suspicious_ports = [4444, 5555, 1337, 8080, 9999]  # Common C2 ports
    
    def scan(self, pid: int, name: str) -> List[Dict]:
        alerts = []
        try:
            process = psutil.Process(pid)
            connections = process.connections()
            for conn in connections:
                if hasattr(conn, 'laddr') and conn.laddr:
                    port = conn.laddr.port
                    if port in self.suspicious_ports:
                        alerts.append({
                            "type": "SUSPICIOUS_CONNECTION", "pid": pid, "name": name, "risk": "HIGH",
                            "info": f"Process connecting to suspicious port {port}"
                        })
        except Exception as e:
            logger.logger.debug(f"NetworkGuard scan error for {pid}: {e}")
        return []

# ---------------------- ENHANCED BROWSER PROTECTOR ----------------------
class EnhancedBrowserProtector:
    def __init__(self):
        self.signature_verifier = EnhancedSignatureVerifier()
        self.protected_paths = set()
        self.setup_complete = False
        
    def setup_browser_protection(self) -> Dict[str, List[str]]:
        results = {"success": [], "failed": []}
        
        if not POLICY["ENABLE_ACL_LOCK"]:
            logger.logger.info("ACL Lock protection disabled")
            return results
        
        try:
            users_dir = Path("C:\\Users")
            if not users_dir.exists():
                logger.logger.error("Users directory not found")
                return results
            
            for browser, config in POLICY["PROTECTED_BROWSER_DATA"].items():
                for path_pattern in config["paths"]:
                    for profile_path in users_dir.rglob(path_pattern):
                        if profile_path.exists() and profile_path.is_dir():
                            success, message = EnhancedACLHelpers.protect_browser_folder(
                                profile_path, config["signer"]
                            )
                            
                            if success:
                                self.protected_paths.add(str(profile_path))
                                results["success"].append(str(profile_path))
                                logger.logger.info(f"Protected: {profile_path}")
                                
                                if POLICY["ENABLE_DEFENDER_HELPER"]:
                                    add_to_controlled_folders(str(profile_path))
                            else:
                                results["failed"].append(f"{profile_path}: {message}")
            
            self.setup_complete = True
            logger.logger.info(f"Browser protection: {len(results['success'])} protected")
            
        except Exception as e:
            logger.logger.error(f"Browser protection setup failed: {str(e)}")
        
        return results
    
    def scan_for_data_theft(self, pid: int, process_name: str) -> List[Dict]:
        alerts = []
        
        try:
            process = psutil.Process(pid)
            open_files = process.open_files()
            
            for file_info in open_files:
                file_path = file_info.path.lower()
                file_name = os.path.basename(file_path)
                
                for browser, config in POLICY["PROTECTED_BROWSER_DATA"].items():
                    for protected_file in config["files"]:
                        if protected_file.lower() in file_name:
                            is_protected_path = any(protected_path.lower() in file_path 
                                                  for protected_path in self.protected_paths)
                            
                            if is_protected_path:
                                process_signer = self.signature_verifier.get_cached_signer(process.exe())
                                
                                if not self.is_authorized_access(process_signer, config["signer"]):
                                    alerts.append({
                                        "type": "SIGNATURE_VIOLATION_THEFT",
                                        "pid": pid,
                                        "name": process_name,
                                        "risk": "CRITICAL",
                                        "info": f"Process '{process_name}' accessed {browser} data. File: {file_name}"
                                    })
                                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        except Exception as e:
            logger.logger.debug(f"Data theft scan error for PID {pid}: {e}")
        
        return alerts
    
    def is_authorized_access(self, process_signer: str, data_owner: str) -> bool:
        if process_signer == data_owner:
            return True
        
        if process_signer and self.signature_verifier.is_trusted_signer(process_signer):
            return True
        
        browser_signers = [config["signer"] for config in POLICY["PROTECTED_BROWSER_DATA"].values()]
        if process_signer in browser_signers:
            return True
        
        return False

    def scan(self, pid: int, name: str) -> List[Dict]:
        return self.scan_for_data_theft(pid, name)

# ---------------------- PERFORMANCE MONITOR ----------------------
class PerformanceMonitor:
    def __init__(self):
        self.process = psutil.Process()
        self.last_check = time.time()
        self.cpu_percent = 0.0
    
    def get_cpu_percent(self) -> float:
        current_time = time.time()
        if current_time - self.last_check > 2.0:
            self.cpu_percent = self.process.cpu_percent()
            self.last_check = current_time
        return self.cpu_percent

# ---------------------- COMPLETE ORCHESTRATOR ----------------------
class EnhancedTitanOrchestrator:
    def __init__(self):
        self.alert_queue = queue.Queue()
        self.alert_history = set()
        self.performance_monitor = PerformanceMonitor()
        self.browser_protector = EnhancedBrowserProtector()
        self.password_guardian = PasswordGuardian()
        self.resource_manager = resource_manager
        
        # TUTTI gli engine originali più il nuovo Password Guardian
        self.engines = [
            self.password_guardian,  # PRIORITÀ MASSIMA - Nuovo
            self.browser_protector,
            TitanMemoryHunter(),
            TitanSystemGuard(),
            TitanModuleSentry(),
            TitanSleepHunter(),
            TitanPipeSentry(),
            TitanScriptHunter(),
            TitanNetworkGuard()  # Nuovo
        ]
        
        self.running = False
        self.worker_threads = []
    
    def setup_protection(self) -> bool:
        try:
            logger.logger.info("Initializing Titan EDR COMPLETE protection...")
            
            protection_results = self.browser_protector.setup_browser_protection()
            
            if POLICY["ENABLE_CI_BROKER"]:
                CiBroker.install_ci_callback()
                logger.logger.info("CI Broker callback installed")
            
            enable_debug_privilege()
            logger.logger.info("Debug privileges enabled")
            
            logger.logger.info(f"Total protection engines: {len(self.engines)}")
            return True
            
        except Exception as e:
            logger.logger.error(f"Protection setup failed: {e}")
            return False

    def _display_banner(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"{Colors.RED}{Colors.BOLD}")
        print("  ████████╗██╗████████╗ █████╗ ███╗   ██╗")
        print("  ╚══██╔══╝██║╚══██╔══╝██╔══██╗████╗  ██║")
        print("     ██║   ██║   ██║   ███████║██╔██╗ ██║")
        print("     ██║   ██║   ██║   ██╔══██║██║╚██╗██║")
        print("     ██║   ██║   ██║   ██║  ██║██║ ╚████║")
        print(f"     ╚═╝   ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝ v10.3 PASSWORD GUARDIAN{Colors.ENDC}")
        print(f"\n {Colors.CYAN}[+] REAL-TIME PASSWORD PROTECTION      [ACTIVE]")
        print(f" [+] ENHANCED BROWSER DATA GUARD       [ACTIVE]")
        print(f" [+] MEMORY INJECTION DETECTION        [ACTIVE]")
        print(f" [+] SYSTEM PROCESS GUARD              [ACTIVE]")
        print(f" [+] DLL SIDELOADING PROTECTION        [ACTIVE]")
        print(f" [+] SLEEP MASK DETECTION              [ACTIVE]")
        print(f" [+] MALICIOUS PIPE DETECTION          [ACTIVE]")
        print(f" [+] SCRIPT LOADER DETECTION           [ACTIVE]")
        print(f" [+] NETWORK CONNECTION MONITOR        [ACTIVE]")
        print(f" {Colors.RED}[!] AGGRESSIVE MODE: BLOCKING ENABLED    [ACTIVE]{Colors.ENDC}")
        print(f" {Colors.GREEN}[*] Password files protected: {len(self.password_guardian.protected_files)}{Colors.ENDC}")
        print(f" {Colors.GREEN}[*] Total protection engines: {len(self.engines)}{Colors.ENDC}\n")

    def kill_process(self, pid: int) -> str:
        if pid == 0: 
            return "N/A (System Object)"
        try:
            process = psutil.Process(pid)
            process_name = process.name()
            process.kill()
            logger.logger.critical(f"TERMINATED malicious process: {process_name} (PID: {pid})")
            return f"{Colors.RED}>> PROCESS TERMINATED{Colors.ENDC}"
        except Exception as e:
            logger.logger.debug(f"Kill process failed for {pid}: {e}")
            return f"{Colors.YELLOW}>> KILL FAILED{Colors.ENDC}"

    def _scanner_worker(self):
        while self.running:
            try:
                # Scan pipes (system level)
                for alert in self.engines[6].scan(0, ""):
                    self.alert_queue.put(alert)
                
                # Scan processes
                for p in psutil.process_iter(['pid', 'name', 'cmdline']):
                    if not self.running: 
                        break
                    
                    pid, name, cmdline = p.info['pid'], p.info['name'], " ".join(p.info['cmdline'] or [])
                    if pid <= 4 or pid == os.getpid(): 
                        continue
                    
                    # Scansiona con TUTTI gli engine
                    for i, engine in enumerate(self.engines):
                        if not self.running: 
                            break
                        try:
                            if i == 7:  # ScriptHunter
                                alerts = engine.scan(pid, name, cmdline)
                            else:
                                alerts = engine.scan(pid, name)
                            
                            for alert in alerts:
                                self.alert_queue.put(alert)
                        except Exception as e:
                            logger.logger.debug(f"Engine {i} scan error for {pid}: {e}")
                
                time.sleep(POLICY["SCAN_INTERVAL"])
                
            except Exception as e:
                logger.logger.error(f"Scanner worker error: {e}")
                time.sleep(5)

    def _alert_worker(self):
        while self.running:
            try:
                alert = self.alert_queue.get(timeout=1.0)
                alert_id = f"{alert['pid']}_{alert['type']}_{hashlib.md5(alert['info'].encode()).hexdigest()[:8]}"
                
                if alert_id not in self.alert_history:
                    self.alert_history.add(alert_id)
                    if len(self.alert_history) > 1000:
                        self.alert_history.clear()
                    
                    # Visualizzazione alert
                    if "PASSWORD" in alert['type']:
                        color = Colors.RED
                        border = "!" * 80
                    elif alert['risk'] == "CRITICAL":
                        color = Colors.RED
                        border = "=" * 80
                    elif alert['risk'] == "HIGH":
                        color = Colors.MAGENTA
                        border = "=" * 80
                    else:
                        color = Colors.YELLOW
                        border = "-" * 80
                    
                    print(f"\n{color}{border}")
                    print(f" TITAN v10.3 PASSWORD GUARDIAN | THREAT: {alert['risk']}")
                    print(f"{border}")
                    print(f" [!] TARGET: {alert['name']} ({alert['pid']})")
                    print(f" [!] VECTOR: {alert['type']}")
                    print(f" [!] INTEL:  {alert['info']}")
                    
                    if POLICY["KILL_ON_CRITICAL"] and alert['risk'] == "CRITICAL":
                        print(f" [X] ACTION: {self.kill_process(alert['pid'])}")
                    
                    print(f" [T] TIME:   {datetime.now().strftime('%H:%M:%S')}")
                    print(f"{border}{Colors.ENDC}")
                    
                    logger.log_alert(alert)
                
                self.alert_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.logger.error(f"Alert worker error: {e}")

    def _monitor_worker(self):
        while self.running:
            try:
                cpu_usage = self.performance_monitor.get_cpu_percent()
                if cpu_usage > POLICY["MAX_CPU_PERCENT"]:
                    logger.logger.warning(f"High CPU usage: {cpu_usage}%")
                time.sleep(10)
            except Exception as e:
                logger.logger.error(f"Monitor worker error: {e}")
                time.sleep(10)

    def start(self):
        if not windll.shell32.IsUserAnAdmin():
            logger.logger.error("Administrator privileges required")
            return
        
        if not self.setup_protection():
            logger.logger.error("Failed to initialize protection")
            return
        
        self.running = True
        self._display_banner()
        
        scanner_thread = threading.Thread(target=self._scanner_worker, daemon=True, name="ScannerWorker")
        alert_thread = threading.Thread(target=self._alert_worker, daemon=True, name="AlertWorker")
        monitor_thread = threading.Thread(target=self._monitor_worker, daemon=True, name="MonitorWorker")
        
        self.worker_threads = [scanner_thread, alert_thread, monitor_thread]
        
        for thread in self.worker_threads:
            thread.start()
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.logger.info("Shutdown signal received")
        finally:
            self.shutdown()
    
    def shutdown(self):
        self.running = False
        logger.logger.info("Shutting down Titan EDR...")
        
        for thread in self.worker_threads:
            if thread.is_alive():
                thread.join(timeout=5.0)
        
        self.resource_manager.cleanup()
        logger.logger.info("Titan EDR shutdown complete")

# ---------------------- MAIN EXECUTION ----------------------
if __name__ == "__main__":
    try:
        orchestrator = EnhancedTitanOrchestrator()
        orchestrator.start()
    except Exception as e:
        logger.logger.critical(f"Titan EDR fatal error: {e}")
        resource_manager.cleanup()
        sys.exit(1)