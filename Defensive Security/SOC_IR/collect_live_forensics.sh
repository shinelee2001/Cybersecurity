#!/usr/bin/env bash
# ==============================================================================
# Linux Live Forensics Triage Collector v2
#
# 목적:
#   침해사고 발생 Linux 서버에서 초동 대응에 필요한 핵심 아티팩트를
#   빠르게 수집하기 위한 Live Forensics Triage Collector
#
# 원칙:
#   1. 휘발성 데이터 우선 수집
#   2. 최소한의 시스템 변경
#   3. 주요 Persistence / Account / Log 아티팩트 확보
#   4. 삭제되었으나 실행 중인 파일(/proc/PID/exe) 복구 시도
#   5. 수집 과정 자체를 기록
#   6. 수집된 증거 사본에 대해 SHA-256 무결성 매니페스트 생성
#
# 권장 실행:
#   sudo ./linux_triage.sh
#
# 외부 증거 저장소 사용:
#   sudo OUT_BASE=/mnt/evidence ./linux_triage.sh
#
# 주의:
#   Live Forensics는 시스템 상태를 완전히 보존하는 방식이 아니다.
#   본 스크립트 실행 자체가 프로세스 생성, 파일 접근, 로그 생성,
#   파일시스템 metadata/cache 변경 등을 유발할 수 있다.
# ==============================================================================

set -u

# ------------------------------------------------------------------------------
# 0. 기본 환경 설정
# ------------------------------------------------------------------------------

umask 077

export LC_ALL=C
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
HOSTNAME_STR="$(hostname 2>/dev/null || echo "unknown_host")"

# 기본값은 현재 디렉터리.
# 외장 디스크 / IR Storage 사용 시:
# OUT_BASE=/mnt/evidence ./linux_triage.sh
OUT_BASE="${OUT_BASE:-.}"

OUT_DIR="${OUT_BASE}/evidence_${HOSTNAME_STR}_${TIMESTAMP}"

VOLATILE_DIR="${OUT_DIR}/volatile"
NON_VOLATILE_DIR="${OUT_DIR}/non_volatile"
FILES_DIR="${OUT_DIR}/files"
META_DIR="${OUT_DIR}/metadata"

mkdir -p \
    "${VOLATILE_DIR}" \
    "${NON_VOLATILE_DIR}" \
    "${FILES_DIR}" \
    "${META_DIR}"

COLLECTION_LOG="${META_DIR}/collection.log"


# ------------------------------------------------------------------------------
# Helper Functions
# ------------------------------------------------------------------------------

log()
{
    local msg="$1"

    echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] ${msg}" \
        | tee -a "${COLLECTION_LOG}"
}


command_exists()
{
    command -v "$1" >/dev/null 2>&1
}


section()
{
    echo
    echo "=============================================================================="
    echo "$1"
    echo "=============================================================================="
}


# ------------------------------------------------------------------------------
# 0-1. 수집 시작 메타데이터
# ------------------------------------------------------------------------------

log "[+] Linux Live Forensics Triage Collector 시작"
log "[+] Hostname: ${HOSTNAME_STR}"
log "[+] Evidence path: ${OUT_DIR}"

if [ "${EUID}" -ne 0 ]; then
    log "[!] WARNING: root 권한이 아닙니다."
    log "[!] 일부 프로세스, 네트워크, audit, SSH, systemd 증거가 누락될 수 있습니다."
fi


# Collector 자체 정보 기록
{
    section "COLLECTION INFORMATION"

    echo "UTC Start Time:"
    date -u '+%Y-%m-%dT%H:%M:%SZ'

    echo
    echo "Local Start Time:"
    date '+%Y-%m-%dT%H:%M:%S%z'

    echo
    echo "Hostname:"
    hostname 2>/dev/null

    echo
    echo "Collector PID:"
    echo "$$"

    echo
    echo "Collector User:"
    id

    echo
    echo "Working Directory:"
    pwd

    echo
    echo "Output Directory:"
    echo "${OUT_DIR}"

    echo
    echo "Collector Script:"
    echo "$0"

    if [ -f "$0" ] && command_exists sha256sum; then
        echo
        echo "Collector SHA256:"
        sha256sum "$0"
    fi

} > "${META_DIR}/collection_metadata.txt" 2>&1


# ==============================================================================
# 1. 휘발성 데이터
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. 시스템 상태
# ------------------------------------------------------------------------------

log "[*] (1/12) 시스템 기본 상태 수집"

{
    section "UTC DATE"
    date -u '+%Y-%m-%dT%H:%M:%SZ'

    section "LOCAL DATE"
    date '+%Y-%m-%dT%H:%M:%S%z'

    section "UPTIME"
    uptime

    section "HOSTNAME"
    hostname

    section "UNAME"
    uname -a

    section "OS RELEASE"
    cat /etc/os-release 2>/dev/null

    section "CURRENT USER"
    id

    section "ENVIRONMENT"
    env 2>/dev/null

} > "${VOLATILE_DIR}/01_system_status.txt" 2>&1


# ------------------------------------------------------------------------------
# 2. 프로세스
# ------------------------------------------------------------------------------

log "[*] (2/12) 프로세스 트리 수집"

{
    section "PS AUXF"
    ps auxf

    section "PS -EF --FOREST"
    ps -ef --forest 2>/dev/null

    section "PS -EO"
    ps -eo \
        user,pid,ppid,lstart,etime,%cpu,%mem,args \
        --sort=pid 2>/dev/null

} > "${VOLATILE_DIR}/02_process_tree.txt" 2>&1


# ------------------------------------------------------------------------------
# 3. /proc 프로세스 스냅샷
# ------------------------------------------------------------------------------

log "[*] (3/12) /proc 프로세스 상세 정보 수집"

{
    for proc in /proc/[0-9]*; do

        [ -d "${proc}" ] || continue

        pid="${proc##*/}"

        echo
        echo "=============================================================================="
        echo "PID: ${pid}"
        echo "=============================================================================="

        echo -n "EXE: "
        readlink "${proc}/exe" 2>/dev/null
        echo

        echo -n "CWD: "
        readlink "${proc}/cwd" 2>/dev/null
        echo

        echo -n "ROOT: "
        readlink "${proc}/root" 2>/dev/null
        echo

        echo -n "CMDLINE: "
        tr '\0' ' ' < "${proc}/cmdline" 2>/dev/null
        echo

        echo
        echo "--- STATUS ---"
        grep -E \
            '^(Name|State|Tgid|Pid|PPid|TracerPid|Uid|Gid|Threads|CapInh|CapPrm|CapEff|CapBnd|Seccomp):' \
            "${proc}/status" 2>/dev/null

    done

} > "${VOLATILE_DIR}/03_proc_snapshot.txt" 2>&1


# ------------------------------------------------------------------------------
# 4. 삭제된 실행파일 탐지 및 복구
# ------------------------------------------------------------------------------

log "[*] (4/12) 삭제된 실행파일(deleted executable) 탐지 및 복구"

DELETED_DIR="${FILES_DIR}/deleted_executables"

mkdir -p "${DELETED_DIR}"

{
    for proc in /proc/[0-9]*; do

        [ -d "${proc}" ] || continue

        pid="${proc##*/}"

        exe="$(readlink "${proc}/exe" 2>/dev/null || true)"

        if [[ "${exe}" == *"(deleted)"* ]]; then

            echo "PID=${pid}"
            echo "EXE=${exe}"

            echo -n "CMDLINE="
            tr '\0' ' ' < "${proc}/cmdline" 2>/dev/null
            echo

            echo

            # 실행 중인 deleted binary 복구 시도
            cp --preserve=all \
                "${proc}/exe" \
                "${DELETED_DIR}/${pid}_exe" \
                2>/dev/null || true

        fi

    done

} > "${VOLATILE_DIR}/04_deleted_executables.txt" 2>&1


# ------------------------------------------------------------------------------
# 5. 네트워크 연결 / Listening Socket
# ------------------------------------------------------------------------------

log "[*] (5/12) 네트워크 연결 및 Listening Socket 수집"

{
    if command_exists ss; then

        section "SS -TULNP"
        ss -tulnp

        section "SS -TANP"
        ss -tanp

        section "SS -UANP"
        ss -uanp

    fi

    if command_exists netstat; then

        section "NETSTAT -ANP"
        netstat -anp

    fi

} > "${VOLATILE_DIR}/05_network_connections.txt" 2>&1


# ------------------------------------------------------------------------------
# 6. 네트워크 인터페이스 / Routing / ARP / DNS
# ------------------------------------------------------------------------------

log "[*] (6/12) 네트워크 구성 정보 수집"

{
    section "IP ADDR"
    ip addr 2>/dev/null

    section "IP LINK"
    ip link 2>/dev/null

    section "IP ROUTE"
    ip route 2>/dev/null

    section "IP RULE"
    ip rule 2>/dev/null

    section "IP NEIGH"
    ip neigh 2>/dev/null

    if command_exists arp; then
        section "ARP -AN"
        arp -an 2>/dev/null
    fi

    section "DNS /etc/resolv.conf"
    cat /etc/resolv.conf 2>/dev/null

    section "/etc/hosts"
    cat /etc/hosts 2>/dev/null

} > "${VOLATILE_DIR}/06_network_configuration.txt" 2>&1


# ------------------------------------------------------------------------------
# 7. Firewall
# ------------------------------------------------------------------------------

log "[*] (7/12) Firewall 규칙 수집"

{
    if command_exists nft; then

        section "NFTABLES RULESET"
        nft list ruleset 2>/dev/null

    fi

    if command_exists iptables-save; then

        section "IPTABLES"
        iptables-save 2>/dev/null

    elif command_exists iptables; then

        section "IPTABLES -L -N -V"
        iptables -L -n -v 2>/dev/null

    fi

    if command_exists ip6tables-save; then

        section "IP6TABLES"
        ip6tables-save 2>/dev/null

    fi

    if command_exists ufw; then

        section "UFW STATUS"
        ufw status verbose 2>/dev/null

    fi

    if command_exists firewall-cmd; then

        section "FIREWALLD"
        firewall-cmd --list-all-zones 2>/dev/null

    fi

} > "${VOLATILE_DIR}/07_firewall_rules.txt" 2>&1


# ------------------------------------------------------------------------------
# 8. 열린 파일 / Socket / Deleted file
# ------------------------------------------------------------------------------

log "[*] (8/12) 열린 파일 및 Socket 수집"

{
    if command_exists lsof; then

        section "LSOF NETWORK"
        lsof -nP -i 2>/dev/null

        section "LSOF DELETED"
        lsof -nP 2>/dev/null | grep -Ei 'deleted|DEL'

    else

        echo "lsof command not available"

    fi

} > "${VOLATILE_DIR}/08_open_files_and_sockets.txt" 2>&1


# ------------------------------------------------------------------------------
# 9. 로그인 세션
# ------------------------------------------------------------------------------

log "[*] (9/12) 로그인 세션 및 접속 이력 수집"

{
    section "WHO"
    who

    section "W"
    w

    section "LAST"
    last -n 100 2>/dev/null

    section "LASTLOG"
    lastlog 2>/dev/null

    if command_exists loginctl; then

        section "LOGINCTL"
        loginctl list-sessions 2>/dev/null

    fi

} > "${VOLATILE_DIR}/09_user_sessions.txt" 2>&1


# ------------------------------------------------------------------------------
# 10. Kernel 상태
# ------------------------------------------------------------------------------

log "[*] (10/12) Kernel 및 Module 상태 수집"

{
    section "LSMOD"
    lsmod 2>/dev/null

    section "/proc/modules"
    cat /proc/modules 2>/dev/null

    section "DMESG"
    dmesg -T 2>/dev/null

    section "KERNEL TAINT"
    cat /proc/sys/kernel/tainted 2>/dev/null

} > "${VOLATILE_DIR}/10_kernel_state.txt" 2>&1


# ------------------------------------------------------------------------------
# 11. Mount / Storage
# ------------------------------------------------------------------------------

log "[*] (11/12) Mount 및 Storage 상태 수집"

{
    section "FINDMNT"
    findmnt 2>/dev/null

    section "MOUNT"
    mount

    section "LSBLK"
    lsblk -f 2>/dev/null

    section "DF"
    df -hT

    section "/proc/mounts"
    cat /proc/mounts 2>/dev/null

} > "${VOLATILE_DIR}/11_mount_storage.txt" 2>&1


# ------------------------------------------------------------------------------
# 12. 임시 디렉터리
# ------------------------------------------------------------------------------

log "[*] (12/12) 임시 디렉터리 아티팩트 목록 수집"

{
    section "/tmp"
    find /tmp -xdev -ls 2>/dev/null

    section "/var/tmp"
    find /var/tmp -xdev -ls 2>/dev/null

    section "/dev/shm"
    find /dev/shm -xdev -ls 2>/dev/null

} > "${VOLATILE_DIR}/12_temp_directories.txt" 2>&1


# ==============================================================================
# 2. Persistence
# ==============================================================================

log "[*] Persistence 정보 수집"


# ------------------------------------------------------------------------------
# Cron
# ------------------------------------------------------------------------------

{
    section "CURRENT USER CRONTAB"
    crontab -l 2>/dev/null

    section "ROOT CRONTAB"
    crontab -u root -l 2>/dev/null

    section "/etc/crontab"
    cat /etc/crontab 2>/dev/null

    section "/etc/cron.*"
    ls -la \
        /etc/cron.d \
        /etc/cron.daily \
        /etc/cron.hourly \
        /etc/cron.weekly \
        /etc/cron.monthly \
        2>/dev/null

    section "/var/spool/cron"
    find /var/spool/cron \
        -maxdepth 3 \
        -type f \
        -ls \
        2>/dev/null

} > "${NON_VOLATILE_DIR}/01_cron_persistence.txt" 2>&1


# ------------------------------------------------------------------------------
# Systemd
# ------------------------------------------------------------------------------

{
    if command_exists systemctl; then

        section "ENABLED UNIT FILES"
        systemctl list-unit-files \
            --state=enabled \
            --no-pager \
            2>/dev/null

        section "RUNNING SERVICES"
        systemctl list-units \
            --type=service \
            --state=running \
            --no-pager \
            2>/dev/null

        section "SYSTEMD TIMERS"
        systemctl list-timers \
            --all \
            --no-pager \
            2>/dev/null

        section "FAILED UNITS"
        systemctl --failed \
            --no-pager \
            2>/dev/null

    fi

} > "${NON_VOLATILE_DIR}/02_systemd_runtime.txt" 2>&1


mkdir -p "${FILES_DIR}/systemd"

if [ -d /etc/systemd/system ]; then

    cp -a \
        /etc/systemd/system \
        "${FILES_DIR}/systemd/" \
        2>/dev/null || true

fi


# ------------------------------------------------------------------------------
# SSH Authorized Keys
# ------------------------------------------------------------------------------

log "[*] SSH authorized_keys 수집"

mkdir -p "${FILES_DIR}/ssh_keys"

find /root /home \
    -maxdepth 4 \
    -type f \
    \( -name "authorized_keys" -o -name "authorized_keys2" \) \
    -exec cp --parents --preserve=all {} "${FILES_DIR}/ssh_keys/" \; \
    2>/dev/null


# ==============================================================================
# 3. Accounts / Privilege
# ==============================================================================

log "[*] 계정 및 권한 상태 수집"

{
    section "/etc/passwd"
    cat /etc/passwd 2>/dev/null

    section "/etc/group"
    cat /etc/group 2>/dev/null

    section "UID 0 ACCOUNTS"
    awk -F: '$3 == 0 {print}' /etc/passwd 2>/dev/null

    section "INTERACTIVE SHELL ACCOUNTS"
    awk -F: \
        '$7 !~ /(nologin|false)$/ {print $1 ":" $3 ":" $6 ":" $7}' \
        /etc/passwd \
        2>/dev/null

    section "/etc/sudoers"
    cat /etc/sudoers 2>/dev/null

    section "/etc/sudoers.d"
    if [ -d /etc/sudoers.d ]; then

        for file in /etc/sudoers.d/*; do

            [ -f "${file}" ] || continue

            echo
            echo "### ${file}"
            cat "${file}" 2>/dev/null

        done

    fi

} > "${NON_VOLATILE_DIR}/03_accounts_privileges.txt" 2>&1


# ==============================================================================
# 4. Logs
# ==============================================================================

# ------------------------------------------------------------------------------
# Journald
# ------------------------------------------------------------------------------

log "[*] systemd journal 수집"

if command_exists journalctl; then

    {
        section "JOURNAL BOOTS"

        journalctl \
            --list-boots \
            --no-pager \
            2>/dev/null

        section "CURRENT BOOT JOURNAL"

        journalctl \
            -b \
            --no-pager \
            -o short-iso \
            2>/dev/null

    } > "${NON_VOLATILE_DIR}/04_journal_current_boot.txt" 2>&1

fi


# ------------------------------------------------------------------------------
# /var/log Archive
# ------------------------------------------------------------------------------

log "[*] /var/log 아카이브 생성"

if [ -d /var/log ]; then

    tar \
        --acls \
        --xattrs \
        --numeric-owner \
        -czf "${NON_VOLATILE_DIR}/var_log_archive.tar.gz" \
        /var/log \
        2>/dev/null || \
    tar \
        -czf "${NON_VOLATILE_DIR}/var_log_archive.tar.gz" \
        /var/log \
        2>/dev/null || true

fi


# ------------------------------------------------------------------------------
# Auditd
# ------------------------------------------------------------------------------

log "[*] auditd 로그 보존"

if [ -d /var/log/audit ]; then

    mkdir -p "${FILES_DIR}/audit_logs"

    cp -a \
        /var/log/audit/. \
        "${FILES_DIR}/audit_logs/" \
        2>/dev/null || true

fi


# ==============================================================================
# 5. 임시 디렉터리 파일 해시
# ==============================================================================

log "[*] /tmp /var/tmp /dev/shm 파일 SHA-256 계산"

{
    for dir in /tmp /var/tmp /dev/shm; do

        [ -d "${dir}" ] || continue

        echo
        echo "=============================================================================="
        echo "${dir}"
        echo "=============================================================================="

        find "${dir}" \
            -xdev \
            -type f \
            -exec sha256sum {} + \
            2>/dev/null

    done

} > "${NON_VOLATILE_DIR}/05_temp_files_sha256.txt" 2>&1


# ==============================================================================
# 6. 추가 핵심 파일 보존
# ==============================================================================

log "[*] 네트워크 / SSH / 보안 설정 파일 보존"

CONFIG_DIR="${FILES_DIR}/configuration"

mkdir -p "${CONFIG_DIR}"

for file in \
    /etc/hosts \
    /etc/resolv.conf \
    /etc/passwd \
    /etc/group \
    /etc/sudoers \
    /etc/ssh/sshd_config
do

    if [ -f "${file}" ]; then

        cp \
            --parents \
            --preserve=all \
            "${file}" \
            "${CONFIG_DIR}/" \
            2>/dev/null || true

    fi

done


if [ -d /etc/ssh/sshd_config.d ]; then

    cp -a \
        /etc/ssh/sshd_config.d \
        "${CONFIG_DIR}/" \
        2>/dev/null || true

fi


if [ -d /etc/sudoers.d ]; then

    cp -a \
        /etc/sudoers.d \
        "${CONFIG_DIR}/" \
        2>/dev/null || true

fi


# ==============================================================================
# 7. 수집 종료 메타데이터
# ==============================================================================

{
    section "UTC END TIME"
    date -u '+%Y-%m-%dT%H:%M:%SZ'

    section "LOCAL END TIME"
    date '+%Y-%m-%dT%H:%M:%S%z'

    section "FINAL DISK USAGE"
    du -sh "${OUT_DIR}" 2>/dev/null

} > "${META_DIR}/collection_end.txt" 2>&1


log "[*] 증거 파일 SHA-256 무결성 매니페스트 생성"


# ==============================================================================
# 8. SHA-256 Evidence Manifest
# ==============================================================================

(
    cd "${OUT_DIR}" || exit 1

    find . \
        -type f \
        ! -name "MANIFEST_SHA256.txt" \
        -print0 \
        | sort -z \
        | xargs -0 sha256sum \
        > "MANIFEST_SHA256.txt"
)


# Manifest 자체 Hash
if command_exists sha256sum; then

    sha256sum \
        "${OUT_DIR}/MANIFEST_SHA256.txt" \
        > "${OUT_DIR}/MANIFEST_SHA256.txt.sha256"

fi


# ==============================================================================
# 완료
# ==============================================================================

END_TIMESTAMP="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

log "[+] 모든 Live Forensics 데이터 수집 완료"
log "[+] 종료 시각: ${END_TIMESTAMP}"
log "[+] 결과 폴더: ${OUT_DIR}"
log "[+] SHA256 Manifest: ${OUT_DIR}/MANIFEST_SHA256.txt"

echo
echo "=============================================================================="
echo "[+] COLLECTION COMPLETE"
echo "=============================================================================="
echo "Evidence Directory : ${OUT_DIR}"
echo "SHA256 Manifest    : ${OUT_DIR}/MANIFEST_SHA256.txt"
echo
