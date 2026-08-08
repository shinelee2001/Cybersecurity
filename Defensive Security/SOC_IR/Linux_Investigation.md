# SOC Linux Server Investigation Cheat Sheet

> 목적: Linux 서버에서 보안 이벤트가 발생했을 때 **탐지 → 확인 → 범위 확장 → 침해 판단 → 에스컬레이션**을 빠르게 수행하기 위한 SOC 분석용 실전 노트.
>
> 기반: 사용자가 정리한 Linux 로그/인증/권한 상승/프로세스 분석 노트를 통합하고, 실제 조사에 필요한 조회 명령을 보강함.
>
> **원칙:** 단일 로그나 단일 명령만으로 침해를 단정하지 않는다. `사용자 + 자산 + 시간 + 네트워크 + 변경 이력`을 함께 본다.

---

## 0. 가장 먼저 기억할 것

### 관찰 가능한 행위
- 로그인/로그아웃: SSH, console
- 인증 실패/성공
- 권한 상승: `sudo`, `su`, `pkexec`
- 명령/프로세스 실행
- 계정/그룹 변경
- 파일 생성/수정/삭제
- SSH 키 등록
- cron/systemd 기반 지속성
- 네트워크 연결 및 리스닝 포트
- 서비스 시작/중지

### 로그의 한계
- 모든 행위가 기본 설정에서 기록되는 것은 아니다.
- root 권한 공격자는 로그/히스토리를 삭제하거나 변경할 수 있다.
- `.bash_history`는 **보조 단서**이지 신뢰 가능한 감사 로그가 아니다.
- `auditd`도 **관련 audit rule이 설정되어 있어야** 상세 `execve`/파일 접근을 볼 수 있다.
- `wtmp`, `btmp`, `lastlog`도 root가 삭제/변조할 수 있으므로 "바이너리니까 안전"하다고 단정하지 않는다.
- journald는 설정에 따라 `/run/log/journal`(휘발성) 또는 `/var/log/journal`(영속성)에 저장될 수 있다.
- 컨테이너 로그는 호스트 `/var/log`가 아니라 stdout/stderr, runtime 또는 수집 플랫폼에만 존재할 수 있다.

### 신뢰도 우선순위 예시

| 데이터 소스 | 주요 용도 | 신뢰도/주의 |
|---|---|---|
| EDR/eBPF | 프로세스 트리, 커맨드라인, 네트워크 | 매우 높음. 에이전트 상태 확인 필요 |
| auditd | syscall/execve/파일 접근 | 높음. **룰 설정 여부 확인 필수** |
| auth.log / secure | SSH, sudo, su, PAM | 높음. root가 삭제 가능 |
| journald | 서비스, 인증, 커널, 애플리케이션 | 높음. 보존 정책 확인 |
| wtmp/btmp/lastlog | 로그인 세션/실패 | 중간~높음. 변조 가능 |
| bash_history | 인터랙티브 셸 명령 | 낮음~중간. 쉽게 우회/삭제 가능 |

---

# 1. 최초 5분 트리아지

## 1.1 조사 기준 시간과 호스트 확인

```bash
hostnamectl
hostname -f 2>/dev/null || hostname
whoami
id
date -Is
date -u -Is
timedatectl
uptime
```

확인 포인트:
- 서버 이름/역할이 알림 대상과 맞는가?
- 시스템 시간이 UTC/KST 중 무엇인가?
- 최근 재부팅이 있었는가?
- 로그 타임존과 SIEM 타임존이 동일한가?

### 부팅 이력

```bash
journalctl --list-boots
who -b
uptime -s
```

> `journalctl -b -1` = **이전 부팅 세션**.  
> `journalctl -b -l`은 이전 부팅이 아니라 현재 부팅 로그에서 긴 줄을 잘리지 않게 출력하는 옵션이다.

---

## 1.2 현재 로그인 세션

```bash
who
w
users
```

보다 상세히:

```bash
who -u
w -h
ps -ft pts/0
```

의심 포인트:
- 평소 없는 관리자 계정
- 비정상 시간대 로그인
- Bastion/VPN을 거치지 않은 출발지
- root 직접 로그인
- 장시간 유지되는 알 수 없는 세션

---

## 1.3 최근 로그인/실패 로그인

```bash
last -Fai | head -50
sudo lastb -Fai | head -50
lastlog | head -50
```

특정 계정:

```bash
last -Fai <USER>
sudo lastb -Fai <USER>
lastlog -u <USER>
```

---

## 1.4 현재 프로세스와 네트워크 빠른 확인

```bash
ps -eo user,pid,ppid,lstart,etime,cmd --forest
ss -plant
ss -lntup
```

의심 프로세스 빠른 검색:

```bash
ps auxww | grep -Ei 'curl|wget|nc |ncat|socat|python|perl|bash -c|sh -c|/tmp/|/dev/shm/' | grep -v grep
```

> `curl`, `wget`, `python`, `bash` 자체는 정상 도구다. **누가, 언제, 어떤 부모 프로세스에서, 어떤 인자로 실행했는지**가 핵심이다.

---

# 2. Linux 로그 위치 빠르게 찾기

## Debian/Ubuntu 계열

| 목적 | 대표 위치 |
|---|---|
| 인증/SSH/sudo | `/var/log/auth.log` |
| 일반 시스템 | `/var/log/syslog` |
| 커널 | `/var/log/kern.log` 또는 `journalctl -k` |
| 패키지 | `/var/log/dpkg.log`, `/var/log/apt/` |
| 웹 | `/var/log/nginx/`, `/var/log/apache2/` |

## RHEL/CentOS/Rocky/Alma 계열

| 목적 | 대표 위치 |
|---|---|
| 인증/SSH/sudo | `/var/log/secure` |
| 일반 시스템 | `/var/log/messages` |
| 커널 | `journalctl -k`, `/var/log/messages` 등 |
| 패키지 | `/var/log/dnf.log`, 구형 환경의 `/var/log/yum.log` |
| 웹 | `/var/log/nginx/`, `/var/log/httpd/` |

## 공통/주요 바이너리 로그

```text
/var/log/audit/audit.log   # auditd
/var/log/wtmp              # 성공 로그인/로그아웃
/var/log/btmp              # 실패 로그인
/var/log/lastlog           # 계정별 마지막 로그인
```

현재 시스템에서 실제 존재하는 로그 확인:

```bash
sudo find /var/log -maxdepth 2 -type f -printf '%TY-%Tm-%Td %TH:%TM %10s %p\n' 2>/dev/null | sort -r | head -100
```

---

# 3. journalctl 실전 사용

## 기본

```bash
journalctl -xe
journalctl -b
journalctl -b -1
journalctl -k
journalctl -p err -n 50
```

## 시간 범위 지정

```bash
journalctl --since '2026-08-08 01:50:00' --until '2026-08-08 02:30:00' --no-pager -o short-iso
```

실전에서는 조사 범위를 변수처럼 고정하면 편하다.

```bash
START='2026-08-08 01:50:00'
END='2026-08-08 02:30:00'
journalctl --since "$START" --until "$END" --no-pager -o short-iso
```

## SSH

배포판에 따라 unit 이름이 `ssh` 또는 `sshd`일 수 있다.

```bash
journalctl -u ssh --since "$START" --until "$END" --no-pager
journalctl -u sshd --since "$START" --until "$END" --no-pager
```

프로세스 이름 기반:

```bash
journalctl _COMM=sshd --since "$START" --until "$END" --no-pager
journalctl _COMM=sudo --since "$START" --until "$END" --no-pager
journalctl _COMM=su --since "$START" --until "$END" --no-pager
```

## cron / systemd

```bash
journalctl -u cron --since "$START" --until "$END" --no-pager
journalctl -u crond --since "$START" --until "$END" --no-pager
journalctl --since "$START" --until "$END" | grep -Ei 'CRON|CROND|systemd.*(Started|Stopped|Created|Reloaded)'
```

## journald 보존/무결성 상태

```bash
journalctl --disk-usage
journalctl --list-boots
sudo journalctl --verify
```

---

# 4. 텍스트 로그 조회 기본기

## 실시간

```bash
sudo tail -F /var/log/auth.log
sudo tail -F /var/log/secure
```

## 문맥 포함 검색

```bash
grep -n -C 3 'Failed password' /var/log/auth.log
grep -n -B 5 -A 10 'Accepted password' /var/log/auth.log
```

## 여러 회전 로그 포함

```bash
sudo grep -H 'Failed password' /var/log/auth.log /var/log/auth.log.1 2>/dev/null
sudo zgrep -H 'Failed password' /var/log/auth.log*.gz 2>/dev/null
```

RHEL:

```bash
sudo grep -H 'Failed password' /var/log/secure /var/log/secure-* 2>/dev/null
sudo zgrep -H 'Failed password' /var/log/secure*.gz 2>/dev/null
```

## IP 빈도 집계

필드 위치에 의존하는 `awk '{print $11}'`보다 `from <IP>` 패턴을 뽑는 방식이 안전하다.

```bash
grep 'Failed password' /var/log/auth.log \
  | sed -nE 's/.* from ([^ ]+).*/\1/p' \
  | sort | uniq -c | sort -rn | head -20
```

성공 로그인 IP:

```bash
grep -E 'Accepted (password|publickey)' /var/log/auth.log \
  | sed -nE 's/.* from ([^ ]+).*/\1/p' \
  | sort | uniq -c | sort -rn
```

---

# 5. SSH 인증 분석

## 5.1 실패 이벤트

```bash
sudo grep -E 'Failed password|Invalid user|authentication failure' /var/log/auth.log
# RHEL
sudo grep -E 'Failed password|Invalid user|authentication failure' /var/log/secure
```

### 특정 IP

```bash
sudo grep '<IP>' /var/log/auth.log
sudo journalctl _COMM=sshd --since "$START" --until "$END" | grep '<IP>'
```

### 특정 계정

```bash
sudo grep -E 'Failed password.*for (invalid user )?<USER>|Accepted .* for <USER>' /var/log/auth.log
```

### Brute force 패턴

특징:
- 단일/소수 계정에 짧은 간격으로 반복
- 동일 IP 또는 소수 IP
- 수십~수백 회 반복
- 이후 성공이 이어지면 위험도 급상승

```bash
grep 'Failed password' /var/log/auth.log \
  | sed -nE 's/.* for (invalid user )?([^ ]+) from ([^ ]+).*/\2 \3/p' \
  | sort | uniq -c | sort -rn | head -30
```

### Password spraying 패턴

특징:
- 하나의 IP가 다수 계정을 순차적으로 시도
- 계정당 실패 횟수는 많지 않을 수 있음

```bash
grep -E 'Failed password|Invalid user' /var/log/auth.log \
  | sed -nE 's/.* from ([^ ]+).*/\1/p' \
  | sort | uniq -c | sort -rn | head -20
```

IP 하나를 잡은 뒤 대상 계정 확인:

```bash
grep '<IP>' /var/log/auth.log | grep -E 'Failed password|Invalid user'
```

### 운영 오류 가능성이 높은 패턴
- 내부 관리 IP
- 동일 서비스 계정
- 정확히 5분/10분/1시간 주기
- 패스워드 변경 직후 시작
- 배치/백업 서버와 연결됨

판단 전에 확인:
- 계정 소유자
- CM/작업 승인
- 비밀번호 변경 시점
- 해당 IP 자산의 역할

---

## 5.2 성공 로그인

```bash
sudo grep -E 'Accepted password|Accepted publickey' /var/log/auth.log
# RHEL
sudo grep -E 'Accepted password|Accepted publickey' /var/log/secure
```

### 확인해야 할 4가지
1. 정상 계정인가?
2. 정상 출발지인가? — Bastion/VPN/관리망/신규 IP
3. 직전 실패가 있었는가?
4. 로그인 직후 `sudo`, 파일 전송, 다운로드, 지속성 생성이 있었는가?

### 실패 → 성공 연결

```bash
grep '<IP>' /var/log/auth.log | grep -E 'Failed password|Invalid user|Accepted'
```

계정 기준:

```bash
grep '<USER>' /var/log/auth.log | grep -E 'Failed password|Accepted|session opened|session closed'
```

### 세션 지속 시간 확인

```bash
last -Fai <USER>
```

현재도 접속 중인지:

```bash
who
w
```

---

## 5.3 root 직접 로그인

```bash
grep -E 'Accepted .* for root|Failed password for root' /var/log/auth.log
```

위험도 높은 조합:

```text
신규 IP + 야간 + root 로그인 + sudo/bash 또는 파일 다운로드
반복 실패 → root 성공
Bastion/VPN 미경유
root 공개키 로그인 + authorized_keys 최근 변경
```

정상 가능 조합:

```text
예외 승인 + 정해진 Bastion + maintenance window + 승인된 작업 명령
```

---

# 6. SSH 공개키 및 authorized_keys 분석

로그만으로는 기존 정상 키인지 공격자가 새로 심은 키인지 구분하기 어렵다.

## authorized_keys 위치 확인

```bash
sudo find /root /home -type f -path '*/.ssh/authorized_keys' -print 2>/dev/null
```

권한/수정 시각:

```bash
sudo stat /root/.ssh/authorized_keys 2>/dev/null
sudo find /home -type f -path '*/.ssh/authorized_keys' -exec stat -c '%y %U:%G %a %n' {} \; 2>/dev/null
```

내용 검토:

```bash
sudo cat /root/.ssh/authorized_keys 2>/dev/null
sudo grep -RHE '^(ssh-|ecdsa-|sk-)' /home/*/.ssh/authorized_keys 2>/dev/null
```

키 fingerprint 확인:

```bash
sudo ssh-keygen -lf /root/.ssh/authorized_keys 2>/dev/null
sudo ssh-keygen -lf /home/<USER>/.ssh/authorized_keys 2>/dev/null
```

분석 포인트:
- 파일 mtime이 사고 시간과 겹치는가?
- 새로운 키가 추가되었는가?
- root 계정에 원래 키가 존재했는가?
- 로그인 직전 `authorized_keys` 변경 흔적이 있는가?
- FIM/auditd에 쓰기 이벤트가 있는가?

### auditd에서 키 파일 변경 검색 — 룰이 사전에 존재한 경우

```bash
sudo ausearch -f /root/.ssh/authorized_keys -i
sudo ausearch -f /home/<USER>/.ssh/authorized_keys -i
```

---

# 7. sudo / su / pkexec 권한 상승

## 7.1 sudo 로그

```bash
sudo grep 'sudo:' /var/log/auth.log
sudo journalctl _COMM=sudo --since "$START" --until "$END" --no-pager
```

특정 사용자:

```bash
grep 'sudo:.*<USER>' /var/log/auth.log
```

위험 신호 예시:

```text
COMMAND=/bin/bash
COMMAND=/bin/sh
COMMAND=/usr/sbin/useradd ...
COMMAND=/usr/sbin/usermod ...
COMMAND=/bin/chmod ... /etc/sudoers
COMMAND=/usr/bin/curl ...
COMMAND=/usr/bin/wget ...
COMMAND=/usr/bin/systemctl enable ...
COMMAND=/usr/bin/crontab ...
```

> `TTY=pts/0`은 pseudo-terminal 세션을 의미한다. SSH에서 흔하지만 **그 자체만으로 SSH임을 단정하지 않는다.** 로그인 세션과 함께 상관분석한다.

### 사용자의 sudo 권한 확인

```bash
sudo -l -U <USER>
```

관리 그룹 확인:

```bash
getent group sudo
getent group wheel
```

---

## 7.2 sudoers 변경

```bash
sudo stat /etc/sudoers
sudo find /etc/sudoers.d -maxdepth 1 -type f -exec stat -c '%y %U:%G %a %n' {} \;
sudo grep -RHE 'NOPASSWD|ALL=\(ALL' /etc/sudoers /etc/sudoers.d 2>/dev/null
```

최근 변경 파일:

```bash
sudo find /etc/sudoers.d -type f -mmin -1440 -ls 2>/dev/null
```

auditd:

```bash
sudo ausearch -f /etc/sudoers -i
sudo ausearch -f /etc/sudoers.d -i
```

확인 포인트:
- 신규 `.conf`/override 파일
- `NOPASSWD:ALL`
- 특정 서비스 계정에 과도한 권한
- 사고 직전/직후 mtime
- 변경 후 즉시 sudo 성공

---

## 7.3 su

```bash
sudo grep -E 'su:|session opened for user root' /var/log/auth.log
sudo journalctl _COMM=su --since "$START" --until "$END"
```

확인 포인트:
- 어떤 원래 사용자가 root로 전환했는가?
- 정상 관리 패턴인가?
- 전환 직후 실행된 명령은 무엇인가?

---

## 7.4 pkexec

```bash
sudo journalctl _COMM=pkexec --since "$START" --until "$END"
sudo grep -Ei 'pkexec|polkit' /var/log/auth.log /var/log/syslog 2>/dev/null
```

취약점 악용 시 표준 인증 로그가 충분하지 않을 수 있으므로 auditd/EDR/프로세스 텔레메트리와 결합한다.

---

# 8. 계정 생성/변경/관리자 그룹 추가

## 인증/시스템 로그

```bash
sudo grep -Ei 'useradd|adduser|usermod|userdel|passwd|groupadd|groupmod' /var/log/auth.log /var/log/syslog 2>/dev/null
sudo journalctl --since "$START" --until "$END" | grep -Ei 'useradd|adduser|usermod|userdel|passwd|groupadd|groupmod'
```

RHEL:

```bash
sudo grep -Ei 'useradd|usermod|userdel|passwd|groupadd|groupmod' /var/log/secure /var/log/messages 2>/dev/null
```

## 현재 계정 목록

```bash
getent passwd
```

UID 0 계정:

```bash
awk -F: '$3 == 0 {print $1,$3,$6,$7}' /etc/passwd
```

로그인 가능한 셸을 가진 계정:

```bash
awk -F: '$7 !~ /(nologin|false)$/ {print $1,$3,$6,$7}' /etc/passwd
```

일반 사용자 범위의 계정 확인:

```bash
awk -F: '$3 >= 1000 && $1 != "nobody" {print $1,$3,$6,$7}' /etc/passwd
```

관리 그룹:

```bash
getent group sudo
getent group wheel
```

계정 파일 변경 시간:

```bash
stat /etc/passwd /etc/shadow /etc/group /etc/gshadow
```

분석 포인트:
- 생성 시각이 사고 시간대와 겹치는가?
- 이름이 정상 서비스 계정처럼 위장되어 있는가?
- 생성 직후 `passwd` → sudo/wheel 추가 → 로그인으로 이어지는가?
- 기존 기준선에 없던 계정인가?

> `backup`, `sync`, `monitor`, `nagios` 같은 이름 자체는 IOC가 아니다. **기존 자산 기준선과 승인 이력**이 중요하다.

---

# 9. cron 지속성

## 시스템 cron

```bash
sudo ls -lah /etc/cron* /var/spool/cron 2>/dev/null
sudo find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly \
  -maxdepth 2 -type f -exec stat -c '%y %U:%G %a %n' {} \; 2>/dev/null | sort
```

## 사용자 crontab

현재 사용자:

```bash
crontab -l
```

특정 사용자:

```bash
sudo crontab -l -u <USER>
```

가능한 전체 사용자 검사:

```bash
while IFS=: read -r u _; do
  sudo crontab -l -u "$u" 2>/dev/null && echo "--- $u ---"
done < /etc/passwd
```

## 로그

```bash
sudo grep -Ei 'CRON|CROND' /var/log/syslog /var/log/cron 2>/dev/null
sudo journalctl --since "$START" --until "$END" | grep -Ei 'CRON|CROND'
```

위험 신호:
- `curl ... | bash`
- `wget ... && chmod +x ...`
- `/tmp`, `/var/tmp`, `/dev/shm` 실행
- 숨김 파일 `.update`, `.cache`, `.sys`
- `>/dev/null 2>&1`로 출력 은닉
- root crontab 신규 등록

> 출력 리다이렉션 자체는 정상 운영에서도 흔하다. 경로/명령/소유자/등록 시각을 함께 본다.

---

# 10. systemd 서비스/타이머 지속성

## 실행 중 서비스

```bash
systemctl --type=service --state=running
```

## enabled 서비스

```bash
systemctl list-unit-files --type=service --state=enabled
```

## 타이머

```bash
systemctl list-timers --all
systemctl list-unit-files --type=timer
```

## 최근 unit 파일

```bash
sudo find /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system \
  -type f -mmin -1440 -exec stat -c '%y %U:%G %a %n' {} \; 2>/dev/null | sort
```

특정 서비스 조사:

```bash
systemctl status <SERVICE> --no-pager
systemctl cat <SERVICE>
journalctl -u <SERVICE> --since "$START" --until "$END" --no-pager
```

위험 신호:
- `ExecStart=/tmp/...`
- `ExecStart=/dev/shm/...`
- 숨김 파일/임시 경로
- 정상 업데이트/모니터링 서비스처럼 위장한 이름
- 사고 시간대에 신규 unit 생성 + `enable` + `start`

---

# 11. 추가 지속성 위치 빠른 점검

기존 노트의 cron/systemd/SSH 키 외에 실제 Linux 조사에서 자주 보는 위치다.

```bash
sudo ls -la /etc/profile /etc/profile.d 2>/dev/null
sudo find /home /root -maxdepth 2 \( -name '.bashrc' -o -name '.bash_profile' -o -name '.profile' \) -ls 2>/dev/null
sudo cat /etc/rc.local 2>/dev/null
sudo cat /etc/ld.so.preload 2>/dev/null
sudo find /root /home -path '*/.config/systemd/user/*' -type f -ls 2>/dev/null
```

특히 `/etc/ld.so.preload`에 예상하지 못한 shared library가 있으면 우선순위를 높인다.

---

# 12. 프로세스 분석

## 전체 프로세스 + 부모/자식

```bash
ps -eo user,pid,ppid,lstart,etime,%cpu,%mem,cmd --forest
```

대안:

```bash
pstree -aps
```

특정 PID:

```bash
PID=<PID>
ps -fp "$PID"
ps -o user,pid,ppid,lstart,etime,cmd -p "$PID"
cat /proc/$PID/status
tr '\0' ' ' < /proc/$PID/cmdline; echo
readlink -f /proc/$PID/exe
readlink -f /proc/$PID/cwd
```

부모 확인:

```bash
PPID=$(ps -o ppid= -p "$PID" | tr -d ' ')
ps -fp "$PPID"
```

### 의심해야 하는 조합

```text
sshd → bash → curl/wget → chmod → /tmp/<binary>
nginx/apache → sh/bash/python
cron/systemd → /tmp 또는 /dev/shm 실행파일
서비스 계정(www-data, nginx 등) → sudo/root shell
python/perl/bash → 외부 IP 장기 연결
```

## 삭제되었지만 실행 중인 바이너리

```bash
sudo ls -l /proc/*/exe 2>/dev/null | grep '(deleted)'
sudo lsof +L1 2>/dev/null
```

이는 공격자가 실행 후 파일을 삭제한 경우 유용한 흔적이 될 수 있다. 정상 업데이트/교체 과정에서도 발생할 수 있으므로 프로세스와 패키지 상태를 확인한다.

---

# 13. 명령 실행 흔적

## bash history

```bash
history
cat ~/.bash_history
sudo cat /root/.bash_history 2>/dev/null
```

전체 사용자 history 탐색:

```bash
sudo find /root /home -maxdepth 2 -name '.*history' -type f -print 2>/dev/null
```

키워드:

```bash
sudo grep -RHiE 'curl|wget|nc |ncat|socat|chmod \+x|useradd|usermod|crontab|systemctl|authorized_keys|base64|python -c|python3 -c' \
  /root/.*history /home/*/.*history 2>/dev/null
```

### history 한계
- 비대화형 셸은 기록되지 않을 수 있음
- 세션 종료 전에는 파일에 아직 flush되지 않을 수 있음
- `HISTFILE` 비활성화 가능
- `history -c`/파일 삭제 가능
- 스크립트 내부 실행은 개별 명령으로 남지 않을 수 있음

따라서 다음과 결합:
- sudo 로그
- auditd
- EDR/eBPF
- 프로세스/네트워크 텔레메트리
- 서비스 로그

---

# 14. auditd 실전 분석

## auditd가 동작 중인가?

```bash
systemctl status auditd --no-pager
sudo auditctl -s
sudo auditctl -l
```

> `auditctl -l`로 어떤 규칙이 실제 설정되어 있는지 먼저 본다. 기본 설정만으로 모든 `execve`가 기록되는 것은 아니다.

## 시간 범위

```bash
sudo ausearch -ts '08/08/2026 01:50:00' -te '08/08/2026 02:30:00' -i
```

환경/버전에 따라 `-ts`, `-te` 날짜 형식 지원이 다를 수 있으므로 `man ausearch`로 확인한다.

## 특정 사용자/UID

```bash
id <USER>
sudo ausearch -ua <UID> -i
```

## 실행 파일

```bash
sudo ausearch -x /usr/bin/sudo -i
sudo ausearch -x /usr/bin/curl -i
sudo ausearch -x /usr/bin/wget -i
```

## 특정 파일

```bash
sudo ausearch -f /etc/sudoers -i
sudo ausearch -f /etc/passwd -i
sudo ausearch -f /root/.ssh/authorized_keys -i
```

## 인증 보고서

```bash
sudo aureport -au
sudo aureport -au --summary
sudo aureport -x --summary
```

### audit 필드 핵심

```text
uid   = 원래 로그인 사용자
auid  = audit login UID. sudo 이후에도 원래 사용자 추적에 유용
euid  = 실행 시 유효 권한
exe   = 실행 파일
comm  = 프로세스명
proctitle / EXECVE = 명령행/인자
```

특히 root로 실행된 프로세스에서도 `auid`가 일반 사용자이면 **누가 root 권한을 사용했는지** 연결하는 데 유용하다.

---

# 15. 파일 분석

## 최근 변경 파일

최근 60분:

```bash
sudo find /etc /home /root /tmp /var/tmp /dev/shm -xdev -type f -mmin -60 -ls 2>/dev/null
```

최근 24시간:

```bash
sudo find /etc /home /root /tmp /var/tmp /dev/shm -xdev -type f -mtime -1 -ls 2>/dev/null
```

> `-mtime -1`은 "오늘"이 아니라 현재 시각 기준 약 24시간 범위라는 점에 주의.

## 임시 디렉터리 실행 파일

```bash
sudo find /tmp /var/tmp /dev/shm -xdev -type f -perm /111 -ls 2>/dev/null
```

## 숨김 파일

```bash
sudo find /tmp /var/tmp /dev/shm -xdev -type f -name '.*' -ls 2>/dev/null
```

## 특정 파일 메타데이터

```bash
stat <FILE>
file <FILE>
sha256sum <FILE>
ls -l --full-time <FILE>
```

ELF라면:

```bash
readelf -h <FILE> 2>/dev/null
strings -a <FILE> | head -100
```

> 의심 파일을 실행해서 확인하지 않는다. 해시/메타데이터/정적 문자열부터 확인한다.

## 패키지 소유 파일인지 확인

Debian/Ubuntu:

```bash
dpkg -S <FILE>
```

RHEL 계열:

```bash
rpm -qf <FILE>
```

RHEL 패키지 무결성:

```bash
rpm -V <PACKAGE>
```

---

# 16. 네트워크 분석

## 현재 TCP 연결

```bash
ss -plant
```

## 리스닝 포트

```bash
ss -lntup
```

## UDP

```bash
ss -uanp
```

## 특정 PID

```bash
sudo lsof -nP -a -p <PID> -i
```

## 전체 네트워크 프로세스

```bash
sudo lsof -nP -i
```

확인 포인트:
- 서버 역할과 무관한 outbound 연결
- 비정상 외부 IP/포트
- `bash`, `python`, `perl`, 임시 경로 바이너리가 네트워크 연결 보유
- 서버에서 원래 열지 않는 리스닝 포트
- 장기 연결/주기적 beacon 패턴

### 방화벽 현재 상태

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
```

사고 시간대에 방화벽 정책이 변경되었다면 관리자 변경 이력과 대조한다.

---

# 17. 프로세스 ↔ 네트워크 ↔ 파일 연결하기

예: SIEM에서 `10.10.20.30:4444` outbound 탐지

### 1) 연결 PID 찾기

```bash
ss -plant | grep '10.10.20.30:4444'
```

### 2) PID 조사

```bash
PID=<PID>
ps -fp "$PID"
tr '\0' ' ' < /proc/$PID/cmdline; echo
readlink -f /proc/$PID/exe
readlink -f /proc/$PID/cwd
```

### 3) 부모 프로세스

```bash
PPID=$(ps -o ppid= -p "$PID" | tr -d ' ')
ps -fp "$PPID"
```

### 4) 실행 파일

```bash
FILE=$(readlink -f /proc/$PID/exe)
stat "$FILE"
sha256sum "$FILE"
file "$FILE"
```

### 5) 로그 시간축

```bash
journalctl --since "$START" --until "$END" --no-pager | grep -Ei '<USER>|<PID>|curl|wget|sudo|sshd|systemd|cron'
```

이렇게 **socket → PID → parent → executable → user → login → privilege escalation** 순으로 연결하면 단일 IOC보다 훨씬 강한 근거가 된다.

---

# 18. 서비스 시작/중지 분석

최근 서비스 이벤트:

```bash
journalctl --since "$START" --until "$END" \
  | grep -Ei 'Started|Stopped|Starting|Stopping|Reloaded|Failed'
```

특정 서비스:

```bash
systemctl status <SERVICE> --no-pager
journalctl -u <SERVICE> --since "$START" --until "$END" --no-pager
```

의심 포인트:
- 로그인 직후 새 서비스 시작
- 사고 시간에 EDR/auditd/로그 수집 서비스 중지
- `sshd`, 방화벽, 보안 에이전트 설정 변경
- 지속성 unit enable

---

# 19. 로그 삭제/수집 장애/Anti-Forensics 확인

## 로그 파일 상태

```bash
sudo stat /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages 2>/dev/null
sudo du -sh /var/log/* 2>/dev/null | sort -h | tail
```

## 주요 수집 서비스

```bash
systemctl status systemd-journald --no-pager
systemctl status rsyslog --no-pager 2>/dev/null
systemctl status auditd --no-pager 2>/dev/null
```

## 디스크 부족

```bash
df -h
df -i
journalctl --disk-usage
```

## 로그 회전

```bash
ls -lah /var/log/auth.log* /var/log/secure* /var/log/syslog* /var/log/messages* 2>/dev/null
cat /etc/logrotate.conf
ls -la /etc/logrotate.d
```

의심 포인트:
- 사고 시간대만 비정상적으로 로그 공백
- 보안 에이전트/rsyslog/auditd가 갑자기 중지
- 로그 파일 크기가 0으로 초기화
- rotation 정책과 맞지 않는 삭제/변경
- SIEM에는 공백이지만 호스트 journal에는 로그 존재 → 수집 경로 문제 가능

---

# 20. 웹 서버가 포함된 경우

## Nginx

```bash
sudo tail -n 200 /var/log/nginx/access.log
sudo tail -n 200 /var/log/nginx/error.log
sudo grep '<IP>' /var/log/nginx/access.log
```

## Apache

```bash
sudo tail -n 200 /var/log/apache2/access.log 2>/dev/null
sudo tail -n 200 /var/log/httpd/access_log 2>/dev/null
```

웹 요청 직후 `www-data/nginx/apache` 자식으로 shell/python이 실행되면 웹셸/RCE 가능성을 우선 확인한다.

```bash
ps -eo user,pid,ppid,lstart,cmd --forest | grep -E 'www-data|nginx|apache|httpd'
```

---

# 21. 컨테이너 / Kubernetes 환경

호스트 `/var/log`에 애플리케이션 로그가 없다고 "로그 없음"으로 판단하지 않는다.

Docker:

```bash
docker ps 2>/dev/null
docker logs --since 1h <CONTAINER> 2>/dev/null
```

containerd/Kubernetes:

```bash
sudo crictl ps 2>/dev/null
kubectl get pods -A
kubectl logs -n <NAMESPACE> <POD> --since=1h
kubectl logs -n <NAMESPACE> <POD> -c <CONTAINER> --previous
```

노드에서 흔한 경로:

```bash
sudo ls -lah /var/log/containers /var/log/pods 2>/dev/null
```

분석 포인트:
- 컨테이너 재시작으로 현재 로그가 사라졌는가?
- `--previous` 로그가 필요한가?
- 호스트 프로세스인지 컨테이너 프로세스인지?
- 보안/로그 수집 daemonset이 정상인가?

---

# 22. 실전 타임라인 상관분석

예시 사고:

```text
01:55~02:05  SSH 실패 180회
02:06        admin 로그인 성공
02:08        sudo /bin/bash
02:10        curl 외부 URL
02:11        /tmp/.update 생성/실행
02:13        systemd unit 생성
02:14        신규 외부 연결
```

## 분석 순서

### 1) 실패

```bash
sudo lastb -Fai | head -100
grep -E 'Failed password|Invalid user' /var/log/auth.log
```

### 2) 성공

```bash
grep -E 'Accepted password|Accepted publickey' /var/log/auth.log
last -Fai <USER>
```

### 3) 권한 상승

```bash
grep 'sudo:' /var/log/auth.log | grep '<USER>'
journalctl _COMM=sudo --since "$START" --until "$END"
```

### 4) 실행/다운로드

```bash
sudo ausearch -ua <UID> -ts recent -i 2>/dev/null
ps -eo user,pid,ppid,lstart,cmd --forest
```

### 5) 지속성

```bash
sudo find /root /home -path '*/.ssh/authorized_keys' -type f -exec stat -c '%y %n' {} \; 2>/dev/null
sudo find /etc/cron.d /etc/systemd/system -type f -mmin -180 -ls 2>/dev/null
systemctl list-timers --all
```

### 6) 네트워크

```bash
ss -plant
ss -lntup
```

### 7) 파일

```bash
sudo find /tmp /var/tmp /dev/shm -type f -mmin -180 -ls 2>/dev/null
```

---

# 23. SOC 판단 프레임워크

## 낮은 위험도 예시

```text
내부 관리망 IP
+ 정상 관리자
+ 업무시간
+ 승인된 변경 작업
+ 평소 사용 명령
+ 지속성/외부 연결 없음
```

## 중간 위험도 예시

```text
정상 관리자
+ 신규 IP
+ 야간
+ sudo 사용
+ 명령은 관리 목적처럼 보임
+ 승인 여부 불명
```

→ 관리자/작업 이력 확인이 필요.

## 높은 위험도 예시

```text
반복 SSH 실패
→ 로그인 성공
→ sudo/root shell
→ curl/wget 다운로드
→ /tmp 실행
→ authorized_keys/cron/systemd 변경
→ 신규 외부 IP 연결
```

이 경우 각 이벤트가 독립적으로는 정상 가능성이 있어도 **공격 흐름으로 연결되면 침해 가능성이 크게 상승**한다.

---

# 24. 분석 시 반드시 묻는 컨텍스트 5가지

## 사용자
- 일반 사용자/관리자/서비스 계정인가?
- 계정 소유자가 현재 재직/근무 중인가?
- 평소 이 서버에 접속하는가?

## 자산
- 운영/개발/DB/웹/Bastion 중 무엇인가?
- 인터넷 노출 여부는?
- 중요 데이터가 있는가?

## 시간
- 업무시간인가?
- maintenance window인가?
- 정기 배치 시간과 겹치는가?

## 네트워크
- Bastion/VPN/관리망 IP인가?
- 처음 보는 IP인가?
- 서버 역할상 허용된 목적지인가?

## 변경
- 배포/패치/점검/비밀번호 변경이 있었는가?
- 작업 티켓/승인 이력이 있는가?

---

# 25. 자주 쓰는 원라이너 모음

## SSH 실패 IP Top 20

```bash
grep 'Failed password' /var/log/auth.log \
  | sed -nE 's/.* from ([^ ]+).*/\1/p' \
  | sort | uniq -c | sort -rn | head -20
```

## SSH 성공 목록

```bash
grep -E 'Accepted (password|publickey)' /var/log/auth.log
```

## root 로그인

```bash
grep -E 'Accepted .* for root|Failed password for root' /var/log/auth.log
```

## sudo 위험 명령

```bash
grep 'sudo:' /var/log/auth.log \
  | grep -Ei 'COMMAND=.*(bash|sh|useradd|usermod|passwd|chmod|chown|curl|wget|crontab|systemctl)'
```

## 최근 계정/그룹 변경

```bash
journalctl --since '24 hours ago' | grep -Ei 'useradd|usermod|userdel|passwd|groupadd|groupmod'
```

## 최근 systemd/cron 파일

```bash
sudo find /etc/systemd/system /etc/cron.d -type f -mtime -1 -ls 2>/dev/null
```

## 임시 경로 실행 파일

```bash
sudo find /tmp /var/tmp /dev/shm -type f -perm /111 -ls 2>/dev/null
```

## 삭제된 실행파일

```bash
sudo ls -l /proc/*/exe 2>/dev/null | grep '(deleted)'
```

## 외부 연결 포함 전체 TCP

```bash
ss -plant
```

## listening port

```bash
ss -lntup
```

## PID 상세

```bash
PID=<PID>; ps -fp "$PID"; tr '\0' ' ' < /proc/$PID/cmdline; echo; readlink -f /proc/$PID/exe; readlink -f /proc/$PID/cwd
```

---

# 26. 사건 유형별 빠른 플레이북

## A. "SSH Brute Force" 알림

1. 실패 횟수/IP/대상 계정 집계
2. 같은 IP에서 성공이 있었는지 확인
3. 성공 세션 시간 확인
4. 직후 sudo/프로세스/파일/네트워크 확인
5. 다른 서버에도 같은 IP가 접근했는지 SIEM에서 scope 확장

핵심 명령:

```bash
grep '<IP>' /var/log/auth.log | grep -E 'Failed|Invalid|Accepted'
last -Fai <USER>
journalctl _COMM=sudo --since "$START" --until "$END"
ss -plant
```

---

## B. "비정상 sudo" 알림

1. 실행자/TTY/PWD/USER/COMMAND 확인
2. 직전 로그인 출발지 확인
3. 해당 사용자의 정상 업무인지 확인
4. 명령이 계정/권한/지속성/다운로드에 연결되는지 확인
5. 후속 프로세스와 네트워크 확인

```bash
grep 'sudo:.*<USER>' /var/log/auth.log
last -Fai <USER>
ps -eo user,pid,ppid,lstart,cmd --forest
ss -plant
```

---

## C. "신규 계정 생성" 알림

1. `useradd`/`usermod` 발생 시각
2. 누가 생성했는지 auditd/sudo 확인
3. sudo/wheel 추가 여부
4. 비밀번호 설정 여부
5. 생성 직후 로그인 여부
6. SSH key/cron/systemd 등록 여부

```bash
getent passwd <USER>
getent group sudo | grep '<USER>'
getent group wheel | grep '<USER>'
last -Fai <USER>
sudo crontab -l -u <USER> 2>/dev/null
sudo stat /home/<USER>/.ssh/authorized_keys 2>/dev/null
```

---

## D. "의심스러운 outbound 연결" 알림

1. socket → PID
2. PID → executable/command line
3. PID → parent
4. process user → 로그인 세션
5. 파일 hash/mtime
6. 지속성 여부

```bash
ss -plant | grep '<IP>'
ps -fp <PID>
tr '\0' ' ' < /proc/<PID>/cmdline; echo
readlink -f /proc/<PID>/exe
sha256sum <FILE>
```

---

## E. "systemd/cron 의심 이벤트" 알림

1. unit/cron 파일 경로
2. 생성/수정 시간
3. 소유자/권한
4. 실행 명령과 바이너리
5. 누가 생성했는지 auditd/sudo
6. 실행 후 네트워크 활동

```bash
stat <UNIT_OR_CRON_FILE>
systemctl cat <SERVICE>
journalctl -u <SERVICE> --since "$START" --until "$END"
ss -plant
```

---

# 27. 에스컬레이션 시 기록해야 할 최소 정보

```text
[Alert]
- 탐지명:
- 최초 탐지 시각:
- 탐지 소스:

[Asset]
- Hostname:
- IP:
- 서버 역할:
- 중요도:

[Identity]
- User:
- UID/AUID:
- Privilege:

[Access]
- Source IP:
- Auth method: password/publickey/etc.
- Bastion/VPN 경유 여부:
- Fail → Success 여부:

[Execution]
- Command line:
- PID / PPID:
- Executable path:
- Hash:

[Persistence]
- authorized_keys:
- cron:
- systemd:
- account/group changes:

[Network]
- Destination IP/Port:
- Listening ports:

[Timeline]
- T0:
- T1:
- T2:

[Assessment]
- 정상 근거:
- 의심 근거:
- 침해 가능성: Low / Medium / High
- 추가 필요한 확인:
```

---

# 28. 현장 조사 시 주의사항

- 침해 의심 파일을 직접 실행하지 않는다.
- 증거 수집 전에 `history -c`, 로그 삭제, 서비스 재시작 같은 행위를 하지 않는다.
- 실제 차단/계정 잠금/프로세스 kill은 조직의 IR 절차에 따라 수행한다.
- 명령 실행 자체도 시스템 상태를 조금씩 변화시킬 수 있으므로 중요한 사고에서는 DFIR/IR 절차와 증거 보존 정책을 우선한다.
- 호스트 로그가 없다고 이벤트가 없었다고 판단하지 않는다. SIEM, journald, auditd, EDR, Bastion/VPN, 네트워크 로그까지 확장한다.
- 공격자는 정상 관리 도구(`curl`, `ssh`, `systemctl`, `python`)를 그대로 사용할 수 있다. **도구명보다 컨텍스트와 행위 체인**을 본다.

---

# 29. 가장 중요한 공격 흐름 한 줄 요약

```text
Authentication → Session → Privilege → Execution → Persistence → Network → Scope
```

SOC 분석은 결국 아래 질문을 연결하는 작업이다.

```text
누가 로그인했는가?
→ 어디서 왔는가?
→ 어떤 권한을 얻었는가?
→ 무엇을 실행했는가?
→ 무엇을 남겼는가?
→ 어디와 통신했는가?
→ 다른 자산/계정까지 확장되었는가?
```

**단일 이벤트보다 이 연결 관계가 침해 판단의 핵심이다.**
