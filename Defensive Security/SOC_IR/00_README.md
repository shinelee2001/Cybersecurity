# Linux SOC / IR 실전 노트

> 목적: Linux 서버 보안 이벤트를 **초동 대응 → 로그 확인 → 인증/권한 → 프로세스/파일/네트워크 → 지속성 → SIEM 상관분석 → 복구** 순서로 빠르게 조사하기 위한 실전 참고서

## 파일 구성

| 파일 | 용도 |
|---|---|
| [`01. Linux 사고 초동 대응 · 증거 보존 · 격리`](Linux_Investigation.md#01.-Linux-사고-초동-대응-·-증거-보존-·-격리) | 사고 발생 직후 무엇을 먼저 확인하고 보존할지 |
| [`02. Linux 로그 구조 · 수집 · 분석 기초`](Linux_Investigation.md#02.-Linux-로그-구조-·-수집-·-분석-기초) | `/var/log`, journald, auditd, 세션 기록과 기본 검색법 |
| [`03. SSH · PAM · 인증 · 세션 분석`](Linux_Investigation.md#03.-SSH-·-PAM-·-인증-·-세션-분석) | SSH 성공/실패, brute force, spraying, PAM, SSH 터널링 |
| [`04. 계정 침해 · 권한 상승 · 지속성`](Linux_Investigation.md#04.-계정-침해-·-권한-상승-·-지속성) | sudo/su, 신규 계정, sudoers, SSH key, cron/systemd 지속성 |
| [`05. 프로세스 · 명령 · 파일 · 네트워크 침해행위 분석`](Linux_Investigation.md#05.-프로세스-·-명령-·-파일-·-네트워크-침해행위-분석) | 프로세스 트리, 위험 명령, 파일 이동, C2, 유출, lateral movement |
| [`06. auditd · FIM · SELinux · AppArmor`](Linux_Investigation.md#06.-auditd-·-FIM-·-SELinux-·-AppArmor) | auditd 이벤트/규칙, FIM, SELinux/AppArmor 분석 |
| [`07. SIEM 탐지 룰 · UEBA · 로그 품질`](Linux_Investigation.md#07.-SIEM-탐지-룰-·-UEBA-·-로그-품질) | 탐지 유스케이스, UEBA, 파싱/수집 품질, Splunk/Elastic/Sigma |
| [`08. 특수 환경: AWS · 컨테이너 · 웹 · Rootkit · 공급망 · Miner`](Linux_Investigation.md#08.-특수-환경:-AWS-·-컨테이너-·-웹-·-Rootkit-·-공급망-·-Miner) | AWS EC2, Docker/Kubernetes, 웹 로그, rootkit, 공급망, miner |

## 권장 분석 순서

```text
1. 시간/호스트/계정/IP 확정
2. 현재 세션 및 네트워크 연결 확인
3. auth.log/secure + last/lastb/who
4. sudo/su/PAM + auditd execve
5. 프로세스 트리 + /proc + 최근 파일
6. cron/systemd/authorized_keys/sudoers 지속성
7. outbound 연결/C2/유출/내부 횡단 확인
8. SIEM·EDR·방화벽·클라우드 로그로 교차 검증
9. 증거 보존 후 격리/차단
10. 타임라인·IOC·영향 범위·재발 방지 정리
```

## 분석 원칙

- **단일 로그만으로 결론 내리지 않는다.** `auth/secure → auditd → journald → process/file/network → SIEM/EDR` 순으로 맥락을 보강한다.
- `.bash_history`는 단서일 뿐이다. 비대화형 셸, `unset HISTFILE`, `history -c` 등으로 빠지거나 조작될 수 있다.
- IP·계정·명령 자체보다 **정상 경로(Bastion/VPN), 시간, 자산 역할, 과거 패턴, 승인 작업**을 함께 본다.
- 격리는 서비스 영향이 있으므로 **증거 보존 후** 수행하는 것이 기본이다. 단, 진행 중인 피해가 명확하면 조직 절차에 따라 신속히 차단한다.
- `iptables`, 계정 잠금, SSH 설정 변경, audit 규칙 로드 등 **상태 변경 명령은 운영 승인 후 실행**한다.

## 원본 노트에서 정리하며 바로잡은 명백한 표기

실전 사용성을 위해 일부 명백한 오타/경로 표기는 정리했다. 예: `sshd_config`, `/var/log/audit/audit.log`, `MaxAuthTries`, `AllowUsers`, `/etc/cron.d`, 이전 부팅은 `journalctl -b -1`.
