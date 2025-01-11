from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict, Counter
import time
import threading
import platform
import subprocess
import re

# 소스 IP별로 프로토콜 카운트를 저장할 변수
traffic_stats = defaultdict(Counter)
# 소스 IP별 트래픽 수를 추적하는 변수
src_traffic_count = Counter()


def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        proto = packet[IP].proto

        # 소스 IP별로 프로토콜 카운트 업데이트
        traffic_stats[src_ip].update([proto])

        # 트래픽 수를 카운팅
        src_traffic_count.update([src_ip])

        """
        # 패킷 세부 출력
        dst_ip = packet[IP].dst
        print(f"[+] Packet: {src_ip} -> {dst_ip} (Protocol: {proto})")

        if TCP in packet:
            print(
                f"    TCP Packet - Src Port: {packet[TCP].sport}, Dst Port: {packet[TCP].dport}"
            )
        elif UDP in packet:
            print(
                f"    UDP Packet - Src Port: {packet[UDP].sport}, Dst Port: {packet[UDP].dport}"
            )
        elif ICMP in packet:
            print("    ICMP Packet")
        """


def get_host_info(ip):
    """
    Windows에서는 nslookup, Linux에서는 host 명령어를 사용하여 IP 주소에 대한 도메인 정보를 조회합니다.
    """
    system_platform = platform.system().lower()

    try:
        if system_platform == "windows":
            result = subprocess.run(["nslookup", ip], capture_output=True, text=True)
        if system_platform == "linux":
            result = subprocess.run(["host", ip], capture_output=True, text=True)
        else:
            return "The OS is neither winodws nor linux."


        if result.returncode == 0:
            # nslookup 또는 host 명령어의 출력에서 도메인 정보 추출
            output = result.stdout.strip()

            print(output)

            # Windows의 경우, 'Name: ' 다음에 나오는 정보를 추출
            if system_platform == "windows":
                # 정규 표현식을 사용하여 도메인과 IP를 추출
                domain_info = re.search(r"Name:\s+([^\n]+)", output)
                if domain_info:
                    return domain_info.group(1).strip()
                else:
                    return "No domain information found"

            # Linux의 경우, 'name pointer' 다음에 나오는 정보 추출
            if system_platform == "linux":
                domain_info = re.search(r"pointer\s+([^\n]+)", output)
                if domain_info:
                    return domain_info.group(1).strip()
                else:
                    return "No domain information found"
        else:
            return "No domain information found"
    except Exception as e:
        return f"Error: {str(e)}"


def display_stats():
    while True:
        time.sleep(10)  # 30초마다 통계 출력
        print("\n=== Traffic Summary (Top 5 Source IPs) ===")

        # 트래픽 수가 많은 상위 5개의 소스 IP 추출
        top_5_sources = src_traffic_count.most_common(5)

        for src_ip, _ in top_5_sources:
            print(f"\nSource IP: {src_ip}")
            # 해당 소스 IP에 대한 프로토콜별 트래픽 출력
            for proto, count in traffic_stats[src_ip].items():
                protocol_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(
                    proto, f"Protocol {proto}"
                )
                print(f"  {protocol_name}: {count} packets")
            # 해당 소스 IP에 대한 도메인 정보 출력
            host_info = get_host_info(src_ip)
            print(f"  Domain Info: {host_info}")

        print("========================================\n")
        traffic_stats.clear()  # 카운터 초기화
        src_traffic_count.clear()  # 트래픽 수 카운터 초기화


if __name__ == "__main__":

    interface = input("Enter the network interface to monitor (e.g., eth0, wlan0): ")
    print(f"[*] Sniffing on {interface}...")

    # 실시간 통계 표시를 위한 스레드 실행
    stats_thread = threading.Thread(target=display_stats, daemon=True)
    stats_thread.start()

    # 패킷 캡처 시작
    try:
        sniff(iface=interface, prn=packet_callback, store=False)
    except PermissionError:
        print(
            "[!] Permission denied: Run the script with elevated privileges (e.g., sudo)."
        )
    except KeyboardInterrupt:
        print("\n[*] Stopping packet sniffing...")
