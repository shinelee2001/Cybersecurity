#!/usr/bin/env bash
# ==============================================================================
# Linux Live Forensics Triage Collector
# 원칙: 휘발성 데이터 우선 수집 -> 비휘발성 데이터 확보 -> 수집 파일 해시 무결성 기록
# ==============================================================================

set -u

# 1. 수집 디렉터리 생성 및 기본 설정
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
HOSTNAME_STR=$(hostname 2>/dev/null || echo "unknown_host")
OUT_DIR="./evidence_${HOSTNAME_STR}_${TIMESTAMP}"

mkdir -p "${OUT_DIR}/volatile"
mkdir -p "${OUT_DIR}/non_volatile"
mkdir -p "${OUT_DIR}/files"

echo "[+] 포렌식 데이터 수집 시작: ${TIMESTAMP}"
echo "[+] 증거 저장 경로: ${OUT_DIR}"

# ------------------------------------------------------------------------------
# 1. 휘발성 데이터 수집 (Order of Volatility 준수)
# ------------------------------------------------------------------------------

# ① 시스템 기본 상태
echo "[*] (1/8) 시스템 기본 상태 수집 중..."
{
    echo "=== DATE ==="; date -u; date
    echo -e "\n=== UPTIME ==="; uptime
    echo -e "\n=== HOSTNAME & UNAME ==="; hostname; uname -a
} > "${OUT_DIR}/volatile/01_system_status.txt" 2>&1

# ② 전체 프로세스 트리
echo "[*] (2/8) 프로세스 계보 및 트리 수집 중..."
{
    echo "=== PS AUXF ==="; ps auxf
    echo -e "\n=== PS -EF --FOREST ==="; ps -ef --forest 2>/dev/null
} > "${OUT_DIR}/volatile/02_process_tree.txt" 2>&1

# ③ 네트워크 연결
echo "[*] (3/8) 활성 네트워크 소켓 및 연결 상태 수집 중..."
{
    echo "=== SS -TULNP ==="; ss -tulnp
    echo -e "\n=== SS -TANP ==="; ss -tanp
    echo -e "\n=== NETSTAT -ANP ==="; netstat -anp 2>/dev/null
} > "${OUT_DIR}/volatile/03_network_connections.txt" 2>&1

# ④ 열린 파일 / 소켓 및 삭제된 실행 파일(Deleted) 추적
echo "[*] (4/8) 열린 파일 디스크립터 및 unlinked 프로세스 파일 수집 중..."
{
    echo "=== LSOF -I ==="; lsof -i 2>/dev/null
    echo -e "\n=== LSOF (DELETED FILES) ==="; lsof 2>/dev/null | grep -E 'deleted|DEL'
} > "${OUT_DIR}/volatile/04_open_files_and_sockets.txt" 2>&1

# ⑤ 현재 로그인 세션 및 접속 이력
echo "[*] (5/8) 로그인 세션 및 사용자 히스토리 수집 중..."
{
    echo "=== WHO ==="; who
    echo -e "\n=== W ==="; w
    echo -e "\n=== LAST (TOP 50) ==="; last -n 50 2>/dev/null
    echo -e "\n=== LASTLOG ==="; lastlog 2>/dev/null
} > "${OUT_DIR}/volatile/05_user_sessions.txt" 2>&1

# ⑥ 네트워크 테이블 (ARP & Routing)
echo "[*] (6/8) ARP 테이블 및 라우팅 정보 수집 중..."
{
    echo "=== ARP -A ==="; arp -a 2>/dev/null || ip neigh
    echo -e "\n=== ROUTE -N ==="; route -n 2>/dev/null || ip route
} > "${OUT_DIR}/volatile/06_network_routing_tables.txt" 2>&1

# ⑦ 임시 디렉터리 파일 점검 (/tmp, /dev/shm)
echo "[*] (7/8) 임시 실행 경로(/tmp, /dev/shm) 아티팩트 목록화 중..."
{
    echo "=== FIND /tmp -ls ==="; find /tmp -ls 2>/dev/null
    echo -e "\n=== FIND /dev/shm -ls ==="; find /dev/shm -ls 2>/dev/null
    echo -e "\n=== FIND /var/tmp -ls ==="; find /var/tmp -ls 2>/dev/null
} > "${OUT_DIR}/volatile/07_temp_directories.txt" 2>&1

# ⑧ 스케줄러(Cron) 등록 작업
echo "[*] (8/8) Crontab 및 스케줄러 등록 작업 수집 중..."
{
    echo "=== CRONTAB (CURRENT USER) ==="; crontab -l 2>/dev/null
    echo -e "\n=== CRONTAB (ROOT) ==="; crontab -u root -l 2>/dev/null
    echo -e "\n=== /etc/crontab & /etc/cron.* ==="
    cat /etc/crontab 2>/dev/null
    ls -la /etc/cron.* /var/spool/cron/ 2>/dev/null
} > "${OUT_DIR}/volatile/08_cron_schedules.txt" 2>&1

# ------------------------------------------------------------------------------
# 2. 비휘발성 데이터 및 중요 파일 보존
# ------------------------------------------------------------------------------

# ⑨ 로그 디렉터리 아카이브 (/var/log/)
echo "[*] (9/13) /var/log 디렉터리 압축 백업 중..."
tar -czf "${OUT_DIR}/non_volatile/var_log_archive.tar.gz" /var/log/ 2>/dev/null

# ⑩ auditd 감사 로그 복사 (/var/log/audit/)
echo "[*] (10/13) auditd 로그 보존 중..."
if [ -d "/var/log/audit" ]; then
    mkdir -p "${OUT_DIR}/files/audit_logs"
    cp -r /var/log/audit/* "${OUT_DIR}/files/audit_logs/" 2>/dev/null
fi

# ⑪ SSH 인가 키 파일 백업 (authorized_keys)
echo "[*] (11/13) 시스템 전역 SSH authorized_keys 수집 중..."
mkdir -p "${OUT_DIR}/files/ssh_keys"
find /root /home -maxdepth 3 -name "authorized_keys" -exec cp --parents {} "${OUT_DIR}/files/ssh_keys/" \; 2>/dev/null

# ⑫ Systemd 서비스 유닛 파일 수집
echo "[*] (12/13) 커스텀 서비스 유닛 파일(/etc/systemd/system/) 복사 중..."
mkdir -p "${OUT_DIR}/files/systemd_services"
cp -r /etc/systemd/system/*.service "${OUT_DIR}/files/systemd_services/" 2>/dev/null

# ⑬ 임시 폴더 내 의심 파일 해시값 계산
echo "[*] (13/13) /tmp 및 /dev/shm 내 전체 파일 해시 기록 중..."
{
    find /tmp /dev/shm /var/tmp -type f -exec sha256sum {} + 2>/dev/null
    find /tmp /dev/shm /var/tmp -type f -exec md5sum {} + 2>/dev/null
} > "${OUT_DIR}/non_volatile/temp_files_hashes.txt" 2>&1

# ------------------------------------------------------------------------------
# 3. 법적 증거 무결성 유지: 수집된 모든 아티팩트 즉시 해시화
# ------------------------------------------------------------------------------
echo "[*] 수집된 모든 증거 파일의 SHA256 / MD5 무결성 해시 매니페스트 생성 중..."
cd "${OUT_DIR}" || exit 1
find . -type f ! -name "MANIFEST_*" -exec sha256sum {} + > "MANIFEST_SHA256.txt"
find . -type f ! -name "MANIFEST_*" -exec md5sum {} + > "MANIFEST_MD5.txt"
cd - > /dev/null

echo -e "\n[+] 모든 라이브 포렌식 데이터 수집 완료."
echo "[+] 결과 폴더: ${OUT_DIR}"
echo "[+] 해시 매니페스트: ${OUT_DIR}/MANIFEST_SHA256.txt"
