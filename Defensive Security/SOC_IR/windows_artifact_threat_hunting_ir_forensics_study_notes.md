# 2026 실전형 사이버훈련장 — 윈도우 아티팩트 위협 사냥 학습노트
## Incident Response · Digital Forensics · Threat Hunting 관점의 심화 정리

> 대상 자료: `[2026 실전형 사이버훈련장] 윈도우 아티팩트 위협 사냥`
>
> 확인된 구성: **17개 강의 / 194개 교재 이미지**
>
> 원본 자료에는 01~14강, 16~18강이 포함되어 있으며 **15강 자료는 ZIP에 존재하지 않는다.**
>
> 목적: 강의 내용을 단순히 “아티팩트 위치와 도구 사용법”으로 암기하는 것이 아니라, 실제 침해사고에서 **가설 수립 → 증거 수집 → 상관분석 → 타임라인 → 침해 범위 산정 → 탐지 규칙으로 환류**하는 방법을 이해하는 데 초점을 둔다.

---

# 0. 이 과정을 공부할 때 가져야 할 핵심 관점

윈도우 포렌식에서 중요한 것은 아티팩트 이름을 많이 외우는 것이 아니다.

분석가는 결국 다음 질문에 답해야 한다.

1. **무엇이 처음 들어왔는가?**
2. **사용자가 무엇을 실행했는가?**
3. **어떤 프로세스가 생성되었는가?**
4. **어떤 부모 프로세스에서 시작되었는가?**
5. **명령행 인자는 무엇이었는가?**
6. **공격자가 지속성을 어떻게 확보했는가?**
7. **파일이 언제 생성·수정·실행되었는가?**
8. **타임스탬프가 조작되었는가?**
9. **외부 통신이나 후속 행위가 있었는가?**
10. **다른 호스트에도 같은 흔적이 존재하는가?**

이를 한 문장으로 정리하면 다음과 같다.

> **Windows Artifact Hunting은 “흔적을 찾는 기술”이 아니라 서로 다른 흔적을 연결하여 공격자의 행위 체인을 복원하는 기술이다.**

---

# 0.1 증거를 세 층으로 생각하자

실무에서는 증거를 다음 세 층으로 나누어 보면 편하다.

```text
[Layer 1] Live / Volatile Evidence
    Memory
    Process
    Network Connection
    Handle
    Loaded DLL
    Command Line

[Layer 2] Configuration / Persistence Evidence
    Registry
    Service
    Scheduled Task
    WMI
    Startup
    Autorun Points

[Layer 3] Historical / Disk Evidence
    $MFT
    $UsnJrnl
    Prefetch
    UserAssist
    Amcache
    ShimCache
    Jump List
    LNK
    Event Log
    Browser / Download Artifact
```

Layer 1은 현재 상태를 보여준다.

Layer 2는 공격자가 시스템에 **어떻게 다시 실행되도록 흔적을 남겼는지** 보여준다.

Layer 3는 과거 행위를 복원하는 데 강하다.

가장 강한 결론은 보통 여러 층의 증거가 일치할 때 나온다.

예:

```text
Prefetch: malware.exe 실행 흔적
        +
$MFT: malware.exe 생성 시간
        +
Registry Run Key: malware.exe 등록
        +
Memory: malware.exe 프로세스 존재
        +
Sysmon 3: 외부 IP 연결

=> 단순 파일 존재가 아니라 실제 실행 + 지속성 + 통신까지 입증 가능
```

---

# 0.2 Artifact와 사실을 구분해야 한다

포렌식 분석에서 가장 위험한 실수 중 하나는 다음과 같은 논리이다.

```text
Artifact가 존재한다
→ 공격이다
```

올바른 논리는 다음과 같다.

```text
Artifact가 존재한다
→ 특정 행위가 있었을 가능성을 높인다
→ 다른 증거로 교차검증한다
→ 정상 행위 가능성을 제거한다
→ 최종 판단한다
```

예를 들어 Prefetch는 매우 유용하지만 다음을 혼동하면 안 된다.

```text
Prefetch 존재
≈ 프로그램 실행 흔적

Prefetch 존재
≠ 악성 프로그램이라는 증거
```

마찬가지로 Run Key에 실행 파일이 등록되어 있다고 해서 무조건 악성은 아니다.

정상 프로그램도 자동 실행을 위해 사용한다.

따라서 분석가는 항상 다음 네 가지를 같이 본다.

```text
Path
Signer
Parent / Creator
Time
```

그리고 가능하면 다음까지 본다.

```text
Hash
Command Line
Network
User
Persistence
File Origin
```

---

# 0.3 분석의 핵심은 Baseline이다

“이상하다”는 것은 정상 기준이 존재할 때만 의미가 있다.

예:

```text
C:\Windows\System32\svchost.exe
```

는 정상적인 경로이다.

하지만 다음은 강한 이상 신호이다.

```text
C:\Users\Public\svchost.exe
C:\Users\alice\AppData\Roaming\svchost.exe
C:\Windows\Temp\svchost.exe
```

이름은 같지만 **위치가 다르다.**

또한 정상 `svchost.exe`라고 해도 부모 프로세스와 명령행이 이상하면 조사 대상이 된다.

즉 프로세스 분석은 이름 하나가 아니라 다음의 조합이다.

```text
Name
Path
Parent
Command Line
Signer
Start Time
User
Loaded Modules
Network
```

---

# 0.4 조사 시 가장 중요한 규칙: Correlation

아티팩트 하나는 “힌트”인 경우가 많다.

서로 다른 아티팩트가 동일한 사건을 가리키면 증거력이 크게 상승한다.

예:

```text
Browser Download
      ↓
Zone.Identifier
      ↓
$MFT Creation Time
      ↓
Prefetch
      ↓
Process Tree
      ↓
Registry Persistence
      ↓
Network Connection
```

이 흐름을 복원하는 것이 Threat Hunting과 DFIR의 핵심이다.

---

# Part I. 사고대응과 증거수집

# 1. 01강 — 윈도우 침해사고와 대응절차 개요

## 1.1 침해사고 유형

윈도우 시스템에서 흔히 조사하는 사고는 다음 범주로 나눌 수 있다.

- 악성코드 감염
- 계정 탈취
- 비인가 접근
- 권한 상승
- 내부자 위협
- 데이터 유출
- 서비스 거부 공격
- 웹/애플리케이션 침해 이후 단말 장악

각 사고는 출발점이 다르지만 최종적으로는 Windows endpoint에 다음과 같은 흔적을 남긴다.

```text
Process
File
Registry
Memory
Network
Authentication
Persistence
Execution Artifact
```

## 1.2 사고대응의 일반적인 단계

실무적으로 다음 흐름을 기억하면 좋다.

```text
Preparation
   ↓
Detection / Identification
   ↓
Triage
   ↓
Containment
   ↓
Evidence Collection
   ↓
Analysis
   ↓
Eradication
   ↓
Recovery
   ↓
Lessons Learned
```

기관이나 프레임워크에 따라 단계 명칭은 조금 다르지만 본질은 같다.

### Preparation

사고가 발생하기 전에 준비한다.

- 로그 수집 정책
- EDR 배포
- 시간 동기화
- 포렌식 수집 도구
- 분석 VM
- 증거 저장 공간
- 연락 체계
- 격리 절차
- 사건 번호 체계

### Detection / Identification

경보가 실제 침해인지 판단한다.

예:

```text
EDR alert
SIEM correlation
User report
IDS alert
Abnormal login
Threat intelligence hit
```

### Triage

우선순위를 정한다.

```text
영향 호스트 수
계정 권한
데이터 중요도
공격자 현재 활동 여부
외부 통신 여부
횡적 이동 여부
```

### Containment

추가 피해를 막는다.

- 네트워크 격리
- 계정 잠금
- 토큰 폐기
- 악성 도메인 차단
- C2 차단

중요한 점은 **격리 전에 휘발성 증거가 사라질 수 있다는 사실**이다.

따라서 상황에 따라 다음 순서를 고려한다.

```text
Memory acquisition
Network state capture
Process state capture
→ Isolation
```

단, 실제 기업 환경에서는 확산 위험이 높은 랜섬웨어나 웜이면 증거 확보보다 즉시 격리가 우선될 수 있다.

즉 포렌식적으로 완벽한 수집과 사업 피해 최소화 사이에서 판단해야 한다.

---

# 1.3 사고 현장에서 반드시 남겨야 하는 기본 기록

```text
Case ID
Evidence ID
Hostname
Username
IP address
Acquisition time
Timezone
Collector
Collection method
Tool version
Source path
Destination path
Hash
Notes
```

특히 **시간대(Timezone)** 는 중요하다.

다음이 서로 다를 수 있다.

```text
Windows Local Time
UTC
Event Log timestamp
MFT timestamp
EDR backend timestamp
SIEM normalized timestamp
```

이를 정규화하지 않으면 타임라인이 뒤틀린다.

---

# 1.4 Chain of Custody

포렌식에서는 “무엇을 발견했는가?”만큼 중요한 것이 “그 증거가 원본과 동일한가?”이다.

따라서 다음을 기록한다.

```text
누가 수집했는가
언제 수집했는가
어디서 수집했는가
어떤 도구를 사용했는가
누구에게 전달했는가
어디에 보관했는가
해시는 무엇인가
```

SHA-256은 악성 여부를 판정하는 용도뿐 아니라 **증거 동일성 검증**에도 사용한다.

---

# 2. 02강 — 윈도우 아티팩트 수집 이론

## 2.1 생성 증거와 보관 증거

윈도우 포렌식 관점에서 증거는 크게 다음과 같이 볼 수 있다.

```text
System-generated evidence
User-generated evidence
```

### System-generated

운영체제 또는 애플리케이션이 자동으로 생성한다.

예:

- Event Log
- Prefetch
- Registry
- $MFT
- $UsnJrnl
- Amcache
- UserAssist
- LNK
- Jump List

### User-generated

사용자가 직접 생성한 데이터이다.

예:

- Documents
- Archives
- Scripts
- Downloads
- Email attachments

분석가는 두 종류를 연결한다.

```text
사용자가 다운로드한 파일
        ↓
운영체제가 생성한 실행 흔적
```

---

# 2.2 Live Response와 Dead-box Forensics

## Live Response

실행 중인 시스템에서 데이터를 수집한다.

장점:

- 메모리 확보 가능
- 현재 네트워크 연결 확인 가능
- 실행 중 프로세스 확인 가능
- 복호화된 데이터가 메모리에 존재할 수 있음

단점:

- 시스템 상태를 변경한다.
- 수집 도구 자체가 흔적을 남긴다.
- 공격자가 탐지할 수 있다.

## Dead-box

시스템을 종료한 뒤 디스크 이미지를 분석한다.

장점:

- 디스크 증거를 안정적으로 보존
- 분석 중 원본 변경 최소화

단점:

- 메모리 증거 소실
- 네트워크 세션 소실
- fileless 공격 흔적 일부 소실

따라서 현대 IR에서는 보통 다음을 선호한다.

```text
Live volatile collection
        ↓
Disk / artifact collection
        ↓
Offline analysis
```

---

# 2.3 휘발성의 순서(Order of Volatility)

일반적인 개념은 다음과 같다.

```text
CPU / registers
Memory
Network state
Processes
Temporary filesystem data
Disk
Remote logs / backups
```

실무에서는 모든 것을 완벽히 순서대로 할 수 없지만 원칙은 간단하다.

> **사라질 가능성이 높은 증거부터 확보한다.**

---

# 2.4 Windows에서 우선 수집할 아티팩트

## Memory

확인 가능한 내용:

- 프로세스
- 명령행
- 로드 DLL
- 네트워크
- 인젝션 흔적
- 복호화된 페이로드
- credential artifact

## Registry Hive

주요 Hive:

```text
SYSTEM
SOFTWARE
SAM
SECURITY
NTUSER.DAT
UsrClass.dat
```

## NTFS Metadata

```text
$MFT
$UsnJrnl
$LogFile
```

## Execution Artifact

```text
Prefetch
UserAssist
Amcache
ShimCache
BAM/DAM
Jump Lists
LNK
```

## Logs

```text
Security.evtx
System.evtx
Application.evtx
PowerShell logs
TaskScheduler logs
Defender logs
Sysmon logs
```

---

# 2.5 Raw-level collection이 필요한 이유

일반 Windows API로 파일을 복사하면 다음 문제가 생길 수 있다.

- 잠긴 파일 접근 실패
- 사용 권한 문제
- 일부 메타데이터 손실
- Alternate Data Stream 누락 가능성

따라서 포렌식 수집 도구는 raw filesystem 또는 low-level API를 사용하여 데이터를 획득하는 경우가 많다.

이 개념이 중요한 이유는 다음과 같다.

```text
Explorer에서 보이지 않는다
≠ 존재하지 않는다
```

특히 다음이 대표적이다.

```text
$MFT
$UsnJrnl
ADS
Deleted record
Locked registry hive
```

---

# 2.6 수집 도구를 사용할 때 주의할 점

교재에는 Live Response 계열 수집 도구 사용 예가 포함되어 있다.

실무에서는 도구 이름 자체보다 다음을 확인해야 한다.

```text
무엇을 수집하는가?
어떤 권한이 필요한가?
원본 시스템에 어떤 흔적을 남기는가?
압축하는가?
해시를 생성하는가?
시간 정보를 보존하는가?
메모리를 포함하는가?
```

예를 들어 CDIR Collector, CyLR, Velociraptor collector, KAPE target 등 어떤 도구를 쓰더라도 **수집 범위를 이해하고 사용하는 것**이 중요하다.

---

# 3. 03강 — 윈도우 아티팩트 수집 실습

강의에서는 실제 수집 도구를 실행하여 다음과 같은 데이터를 확보하는 흐름을 실습한다.

```text
Memory
$MFT
Prefetch
Registry Hive
Event / system artifact
```

## 3.1 수집 전에 해야 할 일

```text
1. 사건 번호 부여
2. 대상 호스트 식별
3. 현재 시각 기록
4. Timezone 기록
5. 네트워크 상태 기록
6. 관리자 권한 여부 확인
7. 저장 공간 확인
8. 수집 도구 해시 기록
```

## 3.2 수집 후 해야 할 일

```text
1. 파일 개수 확인
2. 크기 확인
3. SHA-256 계산
4. 압축본 생성
5. 원본 read-only 보관
6. 분석본 생성
7. 사건 기록에 등록
```

## 3.3 실무적으로 권장하는 Evidence Directory 구조

```text
CASE-2026-001/
├─ 00_notes/
├─ 01_memory/
├─ 02_registry/
├─ 03_ntfs/
├─ 04_eventlogs/
├─ 05_execution_artifacts/
├─ 06_browser/
├─ 07_network/
├─ 08_malware/
├─ 09_timeline/
└─ 10_reports/
```

파일명 예:

```text
HOST01_20261005_134500_memory.raw
HOST01_SYSTEM.hive
HOST01_$MFT
HOST01_prefetch.zip
```

---

# Part II. 악성코드 유입과 프로세스 이상징후

# 4. 04강 — 윈도우 단말의 악성코드 유입 경로와 이상징후 식별

## 4.1 대표적인 초기 유입 경로

교재는 Windows endpoint의 대표적인 악성코드 유입 경로를 설명한다.

### 1. Web / Drive-by

```text
Browser
→ Malicious webpage
→ Exploit / Download
→ Payload
```

조사 포인트:

```text
Browser history
Download history
Cache
Zone.Identifier
$MFT
Prefetch
Process tree
DNS / network
```

### 2. Email attachment

```text
Email
→ Office/PDF/HWP attachment
→ User opens file
→ Macro/Exploit
→ Child process
```

중요한 프로세스 체인:

```text
OUTLOOK.EXE
  └─ WINWORD.EXE
       └─ powershell.exe
```

또는

```text
HWP.EXE
  └─ cmd.exe
```

문서 프로그램이 shell 또는 script interpreter를 생성하면 강한 조사 포인트이다.

### 3. 이동식 저장장치

```text
USB
→ file copied
→ user execution
```

조사 포인트:

- USB device history
- SetupAPI log
- Registry USBSTOR
- LNK
- RecentDocs
- $MFT
- Prefetch

### 4. Network share / SMB

```text
Remote host
→ SMB share
→ file transfer
→ execution
```

조사 포인트:

- SMB logs
- 4624 logon type 3
- share access auditing
- destination file creation
- Prefetch
- process parent

---

# 4.2 이상징후는 네 가지 축으로 보자

강의의 흐름을 실무식으로 정리하면 다음 네 축이 된다.

```text
Process
Persistence
Memory
Filesystem / Timeline
```

이 네 가지를 순서대로 보면 대부분의 endpoint compromise를 빠르게 triage할 수 있다.

---

# 4.3 Process 관점

질문:

```text
어떤 프로세스가 실행되었는가?
정상 이름인가?
정상 위치인가?
정상 parent인가?
명령행이 정상인가?
```

예:

```text
winword.exe → powershell.exe
explorer.exe → cmd.exe → certutil.exe
wscript.exe → powershell.exe
```

이름 자체는 정상 프로그램이지만 **행위 관계가 비정상**일 수 있다.

---

# 4.4 Persistence 관점

질문:

```text
재부팅 후 다시 실행되도록 설정했는가?
로그인할 때 실행되는가?
서비스로 등록했는가?
스케줄러를 사용했는가?
```

---

# 4.5 Memory 관점

질문:

```text
디스크에는 없는데 메모리에서 실행되는 코드가 있는가?
RWX memory가 있는가?
unbacked executable region이 있는가?
정상 프로세스 내부에 의심 코드가 들어갔는가?
```

이것이 중요한 이유는 fileless 공격 때문이다.

```text
Disk file 없음
≠ 공격 없음
```

---

# 4.6 Filesystem / Timestamp 관점

질문:

```text
파일은 언제 생성되었는가?
언제 수정되었는가?
어디서 왔는가?
시간이 조작되었는가?
ADS가 존재하는가?
```

---

# 5. 05강 — 프로세스의 이상징후 분석 방법

## 5.1 Process Identification의 기본 필드

프로세스를 볼 때 최소 다음 값을 확인한다.

```text
Process Name
PID
PPID
Image Path
Command Line
Start Time
Exit Time
User
Session
Architecture
Signer
Version Info
```

이 중 특히 중요한 것은 다음 네 개다.

```text
Name + Path + Parent + Command Line
```

---

# 5.2 Process Name만 믿으면 안 된다

공격자는 Windows 시스템 프로세스와 유사한 이름을 사용한다.

예:

```text
svch0st.exe
scvhost.exe
lsasss.exe
explorer32.exe
```

또는 이름을 완전히 동일하게 만들 수 있다.

```text
svchost.exe
```

따라서 이름보다 경로를 확인한다.

정상 예:

```text
C:\Windows\System32\svchost.exe
```

의심 예:

```text
C:\Users\Public\svchost.exe
C:\Temp\svchost.exe
C:\ProgramData\svchost.exe
```

MITRE ATT&CK 관점에서는 이런 행위가 **Masquerading (T1036)** 과 연결된다.

---

# 5.3 Image Path 이상징후

운영체제 기본 실행 파일은 예상되는 디렉터리가 있다.

예:

```text
lsass.exe          → C:\Windows\System32\lsass.exe
services.exe       → C:\Windows\System32\services.exe
winlogon.exe       → C:\Windows\System32\winlogon.exe
explorer.exe       → C:\Windows\explorer.exe
svchost.exe        → C:\Windows\System32\svchost.exe
```

주의할 점:

- Windows 버전 차이
- WOW64
- System32 / SysWOW64
- Enterprise software

때문에 path만으로 악성 판정하지 않는다.

---

# 5.4 Parent Process 이상징후

정상적인 부모-자식 관계를 알아두면 위협 헌팅에 매우 강력하다.

예:

```text
services.exe
  └─ svchost.exe
```

또는 사용자 인터랙션:

```text
explorer.exe
  └─ notepad.exe
```

의심 체인:

```text
winword.exe
  └─ cmd.exe
       └─ powershell.exe
```

```text
excel.exe
  └─ rundll32.exe
```

```text
w3wp.exe
  └─ cmd.exe
```

```text
sqlservr.exe
  └─ powershell.exe
```

프로세스 트리는 단일 프로세스보다 훨씬 많은 맥락을 제공한다.

---

# 5.5 Command Line 이상징후

프로세스 이름이 정상이어도 명령행이 공격 행위를 드러낼 수 있다.

예:

```text
powershell.exe -enc ...
powershell.exe -nop -w hidden ...
cmd.exe /c ...
rundll32.exe javascript:...
regsvr32.exe /s /n /u /i:http...
mshta.exe http://...
```

실무에서 command line은 가장 가치 있는 telemetry 중 하나이다.

Windows Security 4688 또는 Sysmon Event ID 1에서 확보할 수 있다.

---

# 5.6 Version Information

PE 파일에는 다음과 같은 버전 정보가 들어갈 수 있다.

```text
CompanyName
FileDescription
FileVersion
ProductName
OriginalFilename
```

공격자가 시스템 파일을 위장해도 이 정보가 비어 있거나 부자연스러운 경우가 있다.

하지만 주의해야 한다.

> Version Info는 공격자가 임의로 넣을 수 있으므로 신뢰의 근거가 아니라 **추가 단서**이다.

디지털 서명도 함께 본다.

```text
Signed?
Signature valid?
Publisher expected?
Certificate revoked?
```

---

# 5.7 PID 하나로 판단하지 말 것

PID는 재사용된다.

따라서 조사 기록은 다음처럼 남기는 것이 좋다.

```text
PID + Process Start Time + Image Path
```

예:

```text
PID 1420
Start: 2026-10-05 11:23:02 UTC
Image: C:\Windows\System32\svchost.exe
```

---

# 6. 06강 — 프로세스 이상징후 정보 추출 실습

교재에서는 memory image에서 프로세스 관련 정보를 추출하는 실습을 진행한다.

핵심 사고 방식은 다음과 같다.

```text
Memory image
  ↓
OS/Profile identification
  ↓
Process list
  ↓
Process tree
  ↓
Command line
  ↓
DLL / image information
  ↓
Process dump
  ↓
Signature / version check
```

---

# 6.1 Volatility에서 자주 사용하는 프로세스 분석 기능

버전에 따라 플러그인 이름과 명령 형식은 다르므로 개념 중심으로 기억한다.

## pslist

현재 커널 프로세스 리스트를 기반으로 프로세스를 확인한다.

확인값:

```text
PID
PPID
Threads
Handles
Start Time
Exit Time
```

## pstree

부모-자식 관계를 트리 형태로 본다.

실무에서는 `pslist`보다 `pstree`를 먼저 보는 경우도 많다.

이유:

```text
Process name
```

만 보는 것보다

```text
Parent → Child
```

관계가 공격 체인을 더 잘 보여주기 때문이다.

## psscan

메모리 풀을 스캔하여 종료되었거나 숨겨진 프로세스 구조체 흔적까지 찾을 수 있다.

중요한 Cross-view 비교:

```text
pslist에는 없음
psscan에는 있음
```

가능성:

- 이미 종료된 프로세스
- DKOM/rootkit 계열 은닉
- stale structure

따라서 이것만으로 rootkit을 확정하지 않는다.

---

# 6.2 cmdline

프로세스 실행 인자를 확인한다.

이 정보는 다음을 드러낼 수 있다.

```text
Encoded PowerShell
Downloaded URL
Script path
Service parameter
LOLBin argument
```

예:

```text
powershell.exe -nop -w hidden -enc ...
```

프로세스 이름보다 명령행이 더 공격적인 증거가 되는 경우가 많다.

---

# 6.3 dlllist / ldrmodules

프로세스가 어떤 DLL을 로드했는지 확인한다.

조사 포인트:

- temp/user directory에서 DLL load
- unsigned DLL
- 정상 프로세스의 비정상 DLL
- loader list 불일치

`ldrmodules` 계열 분석은 다음과 같은 은닉/수동 매핑 탐지에 도움이 된다.

```text
PEB loader list
vs
VAD mapped file
```

---

# 6.4 malfind

실행 가능한 private memory 또는 injection 가능성이 있는 영역을 찾는 데 사용한다.

주요 관심 영역:

```text
PAGE_EXECUTE_READWRITE
PAGE_EXECUTE_READ
Private memory
MZ header in unexpected region
Shellcode-like bytes
```

주의:

정상 JIT 엔진도 실행 가능한 동적 메모리를 만든다.

예:

- Browser
- .NET
- Java

따라서 `malfind hit = malware`가 아니다.

---

# 6.5 procdump / memdump

의심 프로세스를 덤프하여 정적 분석으로 넘긴다.

흐름:

```text
Memory triage
  ↓
Suspicious PID
  ↓
Process dump
  ↓
Hash
  ↓
PE analysis
  ↓
Strings / Imports / YARA
```

---

# 6.6 sigcheck / Authenticode 검증

프로세스를 덤프한 뒤 다음을 확인한다.

```text
Digital signature
Publisher
File version
Hash
Compilation metadata
```

중요:

서명된 파일도 공격에 악용될 수 있다.

예:

```text
Signed LOLBin
Signed but vulnerable driver
Stolen certificate
```

따라서 `Signed = Safe`가 아니다.

---

# 7. 07강 — 프로세스 이상징후 분석 실습: 예제 시나리오 1

이 시나리오의 핵심은 **프로세스 이름만 보지 말고 관계와 속성을 좁혀 가는 방법**이다.

실습 흐름을 일반화하면 다음과 같다.

```text
1. Command line 조사
2. 프로세스 목록 조사
3. 의심 프로세스 선별
4. Parent/Child 확인
5. 서비스 프로세스 확인
6. 파일/버전 정보 확인
7. 정상 baseline과 비교
```

---

# 7.1 System Process Hunting

다음 프로세스들은 공격자가 자주 위장하는 대상이다.

```text
svchost.exe
services.exe
lsass.exe
csrss.exe
winlogon.exe
explorer.exe
smss.exe
```

프로세스 하나를 찾았으면 다음을 확인한다.

```text
Name
Path
Parent
PID/PPID
Command Line
Session
User
Loaded DLL
Network
Signer
```

---

# 7.2 svchost.exe를 분석할 때

정상 `svchost.exe`는 Windows 서비스를 호스팅한다.

따라서 단순히 여러 개 존재하는 것은 정상이다.

확인해야 하는 것은 다음이다.

```text
정상 경로인가?
services.exe 계열에서 생성되었는가?
어떤 service group을 호스팅하는가?
실행 인자가 자연스러운가?
의심 DLL을 로드했는가?
비정상 외부 네트워크 연결이 있는가?
```

---

# 7.3 Process Tree가 중요한 이유

예를 들어 다음 두 상황은 완전히 다르다.

```text
services.exe
 └─ svchost.exe
```

vs

```text
powershell.exe
 └─ svchost.exe
```

후자는 매우 강한 이상징후다.

즉 “svchost.exe가 존재한다”가 아니라 **누가 svchost.exe를 만들었는가**를 본다.

---

# 7.4 분석 결론을 쓸 때

나쁜 결론:

```text
svchost.exe가 수상하다.
```

좋은 결론:

```text
PID 3128의 svchost.exe는 정상 System32 경로가 아닌 사용자 디렉터리에서 실행되었으며,
부모 프로세스도 정상적인 services.exe가 아니다.
또한 파일의 서명 및 버전 정보가 Microsoft 정식 바이너리와 일치하지 않아
정상 시스템 프로세스를 위장한 실행 파일일 가능성이 높다.
```

---

# 8. 08강 — 프로세스 이상징후 분석 실습: 예제 시나리오 4

이 시나리오는 프로세스 리스트, DLL, 명령행, 네트워크 등 여러 데이터를 함께 보는 방법을 보여준다.

## 8.1 분석 우선순위

```text
pslist / pstree
      ↓
dlllist
      ↓
cmdline
      ↓
process-specific filtering
      ↓
netscan
```

한 번에 모든 프로세스를 분석하지 않는다.

먼저 의심 후보를 좁힌다.

---

# 8.2 의심 프로세스 후보를 만드는 기준

점수를 매기는 방식이 실무적으로 유용하다.

```text
+2 unusual parent
+2 unusual path
+2 unsigned
+2 suspicious command line
+2 external network connection
+1 strange start time
+1 abnormal user/session
+2 unexpected loaded DLL
```

예:

```text
Process A: 1 point
Process B: 8 points
```

이면 B를 먼저 조사한다.

이것이 threat hunting의 **risk-based triage** 개념이다.

---

# 8.3 Network correlation

Memory에서 `netscan` 계열 결과를 얻었다면 프로세스와 연결한다.

```text
PID
Local IP
Local Port
Remote IP
Remote Port
State
Timestamp
```

특히 다음은 우선 조사한다.

- 일반 사용자 애플리케이션이 아닌 프로세스의 외부 연결
- unusual port
- raw IP connection
- 장시간 유지되는 connection
- 사용자 프로세스가 서버 포트 listen

하지만 포트 번호만으로 악성 여부를 판단하지 않는다.

---

# Part III. 제어지속지점(Persistence) 분석

# 9. 09강 — 제어지속지점 이상징후 분석 방법

## 9.1 Persistence란 무엇인가

공격자가 최초 실행에 성공해도 시스템이 재부팅되거나 사용자가 로그아웃하면 악성 프로세스가 종료될 수 있다.

따라서 공격자는 다시 실행되도록 시스템 설정을 변경한다.

```text
Initial Execution
      ↓
Persistence
      ↓
Reboot / Logon
      ↓
Malware executes again
```

MITRE ATT&CK에서는 다양한 Persistence technique을 정의한다.

---

# 9.2 Registry Run Keys / Startup Folder

대표 위치:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

Startup:

```text
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup
```

조사 포인트:

```text
Value name
Executable path
Command line
File signer
Creation/modification time
User scope
```

MITRE ATT&CK:

```text
T1547.001 Registry Run Keys / Startup Folder
```

---

# 9.3 Windows Service

Service는 강력한 persistence 수단이다.

Registry:

```text
HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>
```

핵심 값:

```text
ImagePath
Start
Type
ServiceDll
DisplayName
ObjectName
```

조사 포인트:

- random service name
- user-writable directory의 binary
- cmd/powershell 실행
- unusual ServiceDll
- 짧은 시간 내 생성 후 실행

관련 로그:

```text
System 7045
Security 4697
```

MITRE ATT&CK:

```text
T1543.003 Windows Service
```

---

# 9.4 Scheduled Task

공격자는 일정 시간 또는 로그인/부팅 이벤트에 악성코드를 실행할 수 있다.

확인할 것:

```text
Task Name
Author
Trigger
Action
Executable
Arguments
Working Directory
Run As User
Hidden
```

아티팩트:

```text
C:\Windows\System32\Tasks
TaskScheduler Operational log
Registry TaskCache
```

MITRE ATT&CK:

```text
T1053.005 Scheduled Task
```

---

# 9.5 WMI Event Subscription

WMI는 fileless persistence에 자주 언급되는 기법이다.

구성 요소:

```text
Event Filter
Event Consumer
FilterToConsumerBinding
```

예:

```text
System boot condition
      ↓
WMI Consumer
      ↓
powershell / script execution
```

MITRE ATT&CK:

```text
T1546.003 WMI Event Subscription
```

---

# 9.6 Winlogon 관련 Persistence

중요 Registry 예:

```text
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
```

관심 값:

```text
Shell
Userinit
```

정상값에서 의심 executable이 추가되었는지 본다.

---

# 9.7 IFEO / Debugger Abuse

Image File Execution Options는 디버깅 기능이지만 persistence 또는 execution hijack에 악용될 수 있다.

대표 경로:

```text
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target.exe>
```

`Debugger` 값이 예상치 못한 프로그램을 가리키면 조사한다.

---

# 9.8 DLL 기반 Persistence

다음과 같은 지점도 조사 대상이다.

- AppInit_DLLs
- Winlogon notification/helper
- LSA provider
- ServiceDll
- COM hijacking
- Search-order hijacking

중요한 것은 모든 위치를 암기하는 것이 아니라 **Autoruns-like 관점**이다.

```text
Boot
Logon
Service
Explorer
Browser
Office
Scheduled task
WMI
DLL load
```

---

# 9.9 Persistence Hunting에서 가장 중요한 질문

```text
이 항목은 언제 생겼는가?
누가 만들었는가?
어떤 파일을 실행하는가?
그 파일은 어디에 있는가?
그 파일은 서명되었는가?
해당 파일이 실제 실행된 증거가 있는가?
```

즉 Persistence entry 하나만 확인해서 끝내지 않는다.

```text
Persistence
    ↓
Executable
    ↓
$MFT
    ↓
Prefetch
    ↓
Process
    ↓
Network
```

으로 pivot한다.

---

# 10. 10강 — 제어지속지점 실습: 예제 시나리오 1

강의에서는 수집된 persistence artifact를 도구로 분석하고 의심 항목을 필터링하는 흐름을 보여준다.

핵심 원리는 다음과 같다.

```text
전체 Autorun 항목
      ↓
정상 Microsoft / known-good 필터
      ↓
Unsigned / unusual path
      ↓
Target binary 확인
      ↓
File metadata / signature 확인
      ↓
실제 실행 흔적 확인
```

---

# 10.1 Known-good Filtering

실무에서는 수천 개의 정상 항목이 존재한다.

따라서 먼저 정상 noise를 줄인다.

예:

```text
Verified Microsoft
Known enterprise agent
Known EDR
Known driver
Approved software
```

하지만 주의한다.

> 정상 서명 파일을 악용하는 공격도 있으므로 “Verified만 숨기고 끝”이 아니라 필요 시 경로와 명령행을 본다.

---

# 10.2 Suspicious Persistence의 전형적인 특징

```text
Unsigned
User-writable path
Temp path
Random filename
System filename masquerading
Encoded command
Script interpreter
Network URL
Unexpected DLL
```

예:

```text
C:\Users\alice\AppData\Roaming\update.exe
```

이 경로 자체가 악성이라는 뜻은 아니지만 service나 system-wide autorun이 이 파일을 실행하면 강한 이상 신호이다.

---

# 10.3 File Metadata를 반드시 연결한다

Persistence entry가 의심되면 다음을 확인한다.

```text
SHA-256
Signer
VersionInfo
PE timestamp
MFT timestamps
ADS
Prefetch
```

---

# 11. 11강 — 제어지속지점 실습: 예제 시나리오 3

이 실습은 persistence 후보에서 실행 파일 속성까지 파고 들어가 정상/비정상을 비교하는 분석 사고를 보여준다.

## 11.1 PE 구조도 보조 증거가 될 수 있다

실행 파일을 조사할 때 다음을 본다.

```text
PE Header
Sections
Entry Point
Linker Version
Imports
Resources
Signer
```

정상 프로그램과 유사한 파일명을 사용해도 내부 구조가 크게 다를 수 있다.

---

# 11.2 Section을 볼 때

일반적으로 많이 보는 section:

```text
.text
.rdata
.data
.rsrc
.reloc
```

의심 포인트:

- 이상한 section 이름
- executable + writable section
- 지나치게 높은 entropy
- raw size / virtual size 불균형
- packer 흔적

하지만 컴파일러/패커에 따라 정상 파일에서도 예외가 존재한다.

---

# 11.3 Linker / Compiler Metadata

PE의 Linker version 또는 Rich Header 등은 파일 생성 환경을 추정하는 보조 자료가 될 수 있다.

하지만 이것도 조작 가능하다.

따라서 역할은 다음 정도이다.

```text
Attribution evidence X
Triage / comparison evidence O
```

---

# Part IV. NTFS 메타데이터와 타임스탬프

# 12. 12강 — NTFS 기반 파일시스템의 이상징후 식별

## 12.1 NTFS를 알아야 하는 이유

파일 탐색기에서 보이는 정보는 NTFS 내부 데이터의 일부에 불과하다.

공격자는 다음을 악용할 수 있다.

- Alternate Data Streams
- Timestomping
- Deleted file remnants
- Metadata manipulation

따라서 DFIR 분석가는 `$MFT` 구조를 이해해야 한다.

---

# 12.2 $MFT

NTFS에서 대부분의 파일과 디렉터리는 MFT record를 가진다.

MFT record에는 여러 attribute가 존재한다.

대표적으로:

```text
$STANDARD_INFORMATION
$FILE_NAME
$DATA
```

이 구조 덕분에 파일 하나에 대해 **서로 다른 종류의 타임스탬프를 비교**할 수 있다.

---

# 12.3 Alternate Data Streams (ADS)

NTFS 파일은 하나 이상의 data stream을 가질 수 있다.

일반적인 기본 stream은 이름이 없다.

추가 stream 예:

```text
normal.txt:secret
```

공격자는 ADS에 다음을 숨길 수 있다.

```text
Script
PowerShell
DLL
EXE data
Configuration
```

MITRE ATT&CK:

```text
T1564.004 NTFS File Attributes
```

---

# 12.4 Zone.Identifier

ADS의 대표적인 정상 활용은 `Zone.Identifier`이다.

인터넷에서 받은 파일에는 Mark-of-the-Web 정보가 남을 수 있다.

예:

```text
file.zip:Zone.Identifier
```

내용 예:

```text
[ZoneTransfer]
ZoneId=3
```

이것은 매우 중요한 초기 침투 증거다.

```text
Internet Download
      ↓
Zone.Identifier
      ↓
User opened file
```

단, 다음 상황에서는 MOTW가 사라질 수 있다.

- 특정 압축 해제 도구
- 복사 방식
- 파일시스템 변환
- 공격자의 제거

따라서 MOTW가 없다고 인터넷에서 받지 않은 것은 아니다.

---

# 12.5 MACB / MACE Timestamp

포렌식 문헌에서는 파일 시간을 다음처럼 표현하는 경우가 많다.

```text
M = Modified
A = Accessed
C = Created
B/E = MFT Entry Changed
```

도구마다 표기 방식이 조금 다르므로 컬럼명을 확인해야 한다.

---

# 12.6 $STANDARD_INFORMATION vs $FILE_NAME

NTFS는 동일한 파일에 대해 여러 attribute에 timestamp를 저장한다.

대표적으로:

```text
$STANDARD_INFORMATION (SI)
$FILE_NAME (FN)
```

공격자가 일반적인 API로 timestamp를 조작하면 SI 값만 변경되고 FN 값은 다르게 남는 경우가 있다.

따라서 다음과 같은 불일치가 timestomping의 단서가 된다.

```text
SI Creation: 2017-01-01
FN Creation: 2026-10-05
```

하지만 이것만으로 공격을 확정하면 안 된다.

파일 복사/이동/압축 해제/백업 복원 등 정상 동작도 차이를 만들 수 있다.

---

# 12.7 Timestomping

공격자가 파일 시간을 과거의 정상 시스템 파일과 맞추는 기법이다.

예:

```text
malware.dll timestamp
=
kernel32.dll timestamp
```

이런 완벽한 일치는 오히려 의심 신호가 될 수 있다.

MITRE ATT&CK:

```text
T1070.006 Timestomp
```

---

# 12.8 Timestamp 정밀도도 단서가 된다

NTFS timestamp는 높은 정밀도를 가진다.

공격자가 사람이 읽기 쉬운 초 단위 값으로 시간을 설정하면 fractional second 패턴이 부자연스러울 수 있다.

예:

```text
12:00:00.0000000
```

반대로 정상 파일은 다양한 sub-second 값이 존재하는 경우가 많다.

단, 이것도 도구/복사 방식에 따라 달라지므로 보조 근거로 사용한다.

---

# 12.9 MFT Record Number도 조사 힌트가 된다

파일이 최근 생성되었는데 timestamp만 매우 오래되었다면 다음을 비교할 수 있다.

```text
Timestamp
MFT record allocation pattern
USN activity
Directory context
Neighboring file creation
```

예:

```text
Timestamp: 2018
MFT record: 주변 2026년 생성 파일과 연속
```

이면 timestamp 조작 가능성을 생각할 수 있다.

---

# 13. 13강 — 파일시스템 메타파일 파싱 및 정보 추출

강의에서는 `$MFT`를 수집하고 AnalyzeMFT 계열 도구로 CSV 형태로 변환하여 분석하는 과정을 실습한다.

## 13.1 기본 흐름

```text
$MFT
 ↓
Parser
 ↓
CSV
 ↓
Spreadsheet / Timeline analysis
```

CSV에 포함될 수 있는 정보:

```text
Record Number
Filename
Parent Path
SI timestamps
FN timestamps
Attributes
Extension
```

---

# 13.2 왜 CSV로 변환하는가

수십만 MFT record를 사람이 raw hex로 보는 것은 비효율적이다.

CSV로 변환하면 다음을 할 수 있다.

```text
Filter
Sort
Pivot
Timeline
Keyword search
Extension search
Timestamp comparison
```

---

# 13.3 분석 시 추천 컬럼

```text
Full Path
Filename
Extension
Record Number
SI Creation
SI Modified
SI MFT Changed
SI Accessed
FN Creation
FN Modified
FN MFT Changed
FN Accessed
ADS flag
Deleted flag
```

---

# 13.4 Excel/Calc에서 분석할 때 주의

Timestamp column을 spreadsheet가 자동 변환하면서 정밀도를 잃을 수 있다.

따라서 원본 CSV를 항상 보존한다.

특히:

```text
sub-second precision
UTC offset
```

이 손실될 수 있다.

---

# 14. 14강 — 위협 시나리오 타임스탬프 분석 실습

이 실습의 핵심은 MFT의 SI/FN 시간과 ADS를 이용하여 공격 흐름을 시간순으로 복원하는 것이다.

## 14.1 Timeline 분석 순서

```text
1. MFT CSV 로드
2. FN Creation 기준 정렬
3. 이상 시간대 선정
4. Zone.Identifier / ADS 확인
5. 의심 파일 주변 이벤트 확인
6. 실행 흔적과 결합
```

---

# 14.2 Why FN Creation?

SI timestamp는 사용자 API를 통해 비교적 쉽게 조작될 수 있다.

FN timestamp는 다른 갱신 규칙을 가지기 때문에 timestomping 탐지에서 유용한 보조 기준이 된다.

하지만 이것 역시 절대적인 진실 값은 아니다.

따라서:

```text
SI
FN
USN
Prefetch
Event Log
```

를 같이 본다.

---

# 14.3 Download → Extraction → Execution 흐름 복원

교재 시나리오처럼 다운로드 파일과 이후 생성 파일을 시간순으로 연결하면 다음 형태의 공격 체인을 만들 수 있다.

```text
Downloaded archive
      ↓
Zone.Identifier
      ↓
Archive extraction
      ↓
Payload / decoy created
      ↓
Payload executed
      ↓
Persistence established
```

분석가는 동일 폴더의 파일 생성 시각을 묶어 본다.

예:

```text
12:01:02 archive.zip created
12:01:10 image.jpg created
12:01:10 payload.exe created
12:01:12 payload.exe Prefetch
```

이 네 줄은 각각 별개 증거지만 합치면 매우 강한 행위 체인이 된다.

---

# 14.4 Timestamp Timeline을 만들 때 지켜야 할 규칙

모든 시간을 하나의 시간대로 정규화한다.

추천:

```text
UTC
```

그리고 원본 timestamp도 별도 유지한다.

예:

```text
Original: 2026-10-05 21:32:01 +0900
Normalized: 2026-10-05 12:32:01 UTC
```

---

# Part V. 프로그램 실행흔적

# 15. 원본 ZIP에 15강이 없는 점

확인한 ZIP에는 `15강` 디렉터리가 존재하지 않는다.

따라서 이 노트는 임의로 15강 내용을 만들어 넣지 않는다.

다음 강의는 원본 번호를 그대로 따라 16강으로 이어간다.

---

# 16. 16강 — 프로그램 실행흔적과 관련된 윈도우 아티팩트

Windows에는 사용자가 프로그램을 실행하면서 자동으로 생성되는 다양한 흔적이 있다.

교재에서 중요한 아티팩트는 다음과 같다.

```text
Prefetch
UserAssist
BAM / DAM
RecentApps
ShimCache / AppCompatCache
Jump Lists
Amcache
```

각 아티팩트는 “프로그램 실행”을 서로 다른 관점에서 기록한다.

---

# 16.1 Prefetch

기본 경로:

```text
C:\Windows\Prefetch
```

일반 파일명:

```text
PROGRAM.EXE-XXXXXXXX.pf
```

예:

```text
CMD.EXE-XXXXXXXX.pf
```

얻을 수 있는 정보는 OS 버전에 따라 다르지만 일반적으로 다음이 중요하다.

```text
Executable name
Run count
Last run timestamps
Referenced files/directories
Volume information
```

Prefetch는 프로그램 실행 여부를 판단하는 데 매우 강한 증거이다.

그러나 시스템 설정/버전/삭제 여부에 따라 존재하지 않을 수 있다.

따라서:

```text
Prefetch 없음
≠ 실행되지 않음
```

---

# 16.2 UserAssist

Registry 기반 아티팩트이다.

사용자가 GUI를 통해 실행한 프로그램 흔적을 확인하는 데 유용하다.

특징:

- ROT13 인코딩된 값 이름을 볼 수 있음
- 실행 횟수
- 마지막 실행 관련 정보

일반적으로 user context를 파악하는 데 좋다.

중요:

```text
UserAssist
→ 사용자 인터랙티브 실행에 강함
```

따라서 service/background execution을 모두 포착하는 아티팩트가 아니다.

---

# 16.3 BAM / DAM

Background Activity Moderator / Desktop Activity Moderator는 사용자별 프로그램 실행 흔적을 제공할 수 있다.

Registry 기반이며 OS 버전에 따라 정보와 위치가 달라질 수 있다.

분석 시 다음을 확인한다.

```text
Executable path
User SID
Timestamp
```

---

# 16.4 RecentApps

일부 Windows 버전에서 실행 관련 정보를 제공한다.

중요한 점은 Windows 버전에 따라 아티팩트 생성 방식이 크게 달라질 수 있다는 것이다.

따라서 포렌식 도구 결과를 해석할 때 항상 다음을 확인한다.

```text
OS version
Artifact availability
Parser support
```

---

# 16.5 ShimCache / AppCompatCache

Windows Application Compatibility 기능과 관련된 Registry artifact이다.

과거에는 실행 여부를 판정할 때 널리 사용되었지만 해석에 주의해야 한다.

중요 원칙:

> **ShimCache entry가 존재한다고 해서 반드시 실행된 것은 아니다.**

파일이 시스템에 관찰되었음을 나타낼 수 있지만 OS 버전에 따라 의미가 달라진다.

따라서 실행 증거는 Prefetch, Amcache, UserAssist 등과 교차검증한다.

---

# 16.6 Jump Lists

사용자가 자주 열거나 최근 연 문서/경로를 추적하는 데 유용하다.

분석할 수 있는 것:

```text
Application
Recent file
Target path
LNK metadata
```

특히 사용자 행위 reconstruction에 좋다.

---

# 16.7 Amcache

Amcache는 프로그램/파일 실행과 설치 관련 정보를 제공하는 중요한 아티팩트다.

얻을 수 있는 정보는 OS 버전에 따라 차이가 있지만 흔히 다음을 활용한다.

```text
Path
File metadata
Hash-related data
Program information
Timestamps
```

Amcache도 단독으로 실행을 확정하기보다는 다른 증거와 결합한다.

---

# 16.8 Execution Artifact 비교

| Artifact | 강점 | 주의점 |
|---|---|---|
| Prefetch | 실행 시간, 횟수, 참조 파일 | 비활성/삭제 가능 |
| UserAssist | GUI 사용자 실행 | 모든 실행을 기록하지 않음 |
| BAM/DAM | 사용자별 실행 흔적 | OS 버전 차이 |
| ShimCache | 파일 존재/실행 관련 추적 | 단독 실행 증거로 위험 |
| Amcache | 프로그램/파일 메타데이터 | 버전별 구조 차이 |
| Jump List | 사용자 문서 접근 | 사용자 인터랙션 중심 |
| LNK | 파일/경로 접근 | 링크 생성 조건 존재 |

---

# 17. 17강 — Prefetch & Superfetch

## 17.1 Prefetch가 만들어진 이유

HDD 시대에는 storage → memory로 데이터를 읽는 데 latency가 컸다.

Windows는 프로그램 실행 패턴을 학습하여 필요한 파일을 미리 읽음으로써 실행 속도를 높였다.

이 최적화 기능이 포렌식 관점에서는 실행 흔적을 제공한다.

---

# 17.2 Prefetch 파일명

일반적인 형태:

```text
EXECUTABLE.EXE-HASH.pf
```

Hash는 실행 파일 경로/환경과 관련하여 생성된다.

같은 이름의 EXE라도 서로 다른 경로에서 실행되면 별도 Prefetch가 만들어질 수 있다.

이는 masquerading 탐지에도 유용하다.

예:

```text
C:\Windows\System32\svchost.exe
C:\Users\Public\svchost.exe
```

경로가 다르면 Prefetch 분석에서 별개의 실행 흔적으로 구분될 수 있다.

---

# 17.3 Prefetch에서 확인할 내용

```text
Executable name
Execution count
Last execution time(s)
Referenced files
Referenced directories
Volume serial
Volume path
```

참조 파일 목록은 매우 가치 있다.

예를 들어 malware가 실행될 때 특정 DLL/설정파일을 사용했다면 Prefetch 내부에 경로가 남을 수 있다.

---

# 17.4 Superfetch / SysMain

Superfetch는 시스템 전반의 사용 패턴을 기반으로 메모리 preload 최적화를 수행한다.

현대 Windows에서는 서비스 명칭과 내부 구현이 변화했지만 Prefetch와 함께 Windows 실행 최적화의 맥락을 이해하는 데 의미가 있다.

포렌식에서는 기능 이름보다 **실제 생성된 아티팩트와 OS 버전**을 기준으로 판단한다.

---

# 18. 18강 — Prefetch를 이용한 악성파일 실행시간 분석 실습

이 실습은 MFT와 Prefetch를 결합하는 전형적인 DFIR 분석을 보여준다.

## 18.1 핵심 질문

```text
악성 파일은 언제 생성되었는가?
언제 최초 실행되었는가?
몇 번 실행되었는가?
어떤 파일과 함께 생성되었는가?
```

---

# 18.2 MFT와 Prefetch를 결합하는 이유

MFT는 파일의 생성/수정 흔적을 제공한다.

Prefetch는 실행 흔적을 제공한다.

따라서:

```text
$MFT Creation
      ↓
Prefetch Last Run
```

를 연결하면 다음을 추정할 수 있다.

```text
File arrived
→ shortly after executed
```

이것은 악성 첨부/다운로드 시나리오에서 매우 강력하다.

---

# 18.3 예시 사고 타임라인

```text
11:27:40  archive downloaded
11:27:45  payload created
11:28:05  payload first execution
11:28:06  persistence created
11:28:07  outbound connection
```

이런 timeline이 만들어지면 단순 IOC 목록보다 훨씬 강한 사고 설명이 된다.

---

# Part VI. 실무형 아티팩트 상관분석

# 19. 질문 중심 Artifact Mapping

분석가는 “어떤 아티팩트를 볼까?”보다 **“어떤 질문에 답해야 하는가?”** 에서 시작해야 한다.

---

# 19.1 이 파일이 존재했는가?

강한 증거:

```text
$MFT
$UsnJrnl
Amcache
ShimCache
LNK
AV/EDR file event
```

보조:

```text
Browser cache
RecentDocs
Jump Lists
```

---

# 19.2 이 파일이 실행되었는가?

우선순위:

```text
Prefetch
Process creation log
EDR telemetry
Memory process
UserAssist
BAM/DAM
Amcache
ShimCache
```

주의:

ShimCache/Amcache의 의미는 OS 버전과 parser에 따라 세밀하게 해석해야 한다.

---

# 19.3 누가 실행했는가?

```text
Process token/user
Security 4688
EDR user context
UserAssist
BAM/DAM SID
Logon session
```

---

# 19.4 언제 실행했는가?

```text
Prefetch run time
Process creation event
EDR
BAM/DAM
UserAssist
Memory start time
```

---

# 19.5 어디서 왔는가?

```text
Zone.Identifier
Browser download database
Email attachment
LNK
MFT parent path
Archive extraction context
Network share logs
USB artifacts
```

---

# 19.6 지속성을 확보했는가?

```text
Run / RunOnce
Service
Scheduled Task
Startup folder
WMI
Winlogon
IFEO
COM hijacking
```

그리고 반드시 target executable의 실행 흔적까지 확인한다.

---

# 19.7 외부 통신을 했는가?

```text
Memory netscan
EDR network telemetry
Sysmon Event 3
Firewall
Proxy
DNS
PCAP
```

---

# 19.8 파일 시간을 조작했는가?

```text
SI vs FN mismatch
USN chronology
MFT record context
Prefetch execution time
Neighbor file creation times
EDR file creation
```

---

# 20. Artifact Evidence Confidence Matrix

| Evidence | 무엇을 강하게 말할 수 있는가 | 단독으로 말하면 위험한 것 |
|---|---|---|
| Prefetch | 실행 흔적 | 악성 여부 |
| UserAssist | 사용자 GUI 실행 | 모든 종류의 실행 |
| $MFT | 파일 metadata/history | 공격자 의도 |
| Zone.Identifier | Internet zone origin 가능성 | 실제 실행 여부 |
| Run Key | 자동실행 설정 | 실제 실행 성공 |
| Service entry | 서비스 등록 | 공격 여부 |
| Memory process | 해당 시점 실행 상태 | 최초 실행 경로 전체 |
| netscan | 연결/소켓 흔적 | C2 여부 확정 |
| ShimCache | 파일 관찰/호환성 흔적 | 항상 실행되었다는 확정 |
| Amcache | 파일/프로그램 메타데이터 | 단독 execution proof |

---

# Part VII. Memory Forensics Practical Reference

# 21. 메모리를 먼저 봐야 하는 상황

다음 상황이면 memory acquisition의 가치가 매우 높다.

```text
Fileless attack
PowerShell attack
Process injection
Credential theft
Ransomware active
Unknown network connection
Packed/unpacked malware
Decrypted config needed
```

---

# 21.1 Memory Triage 순서

```text
1. OS identification
2. pslist
3. pstree
4. psscan
5. cmdline
6. netscan
7. dlllist / ldrmodules
8. handles
9. malfind
10. suspicious process dump
```

---

# 21.2 pslist vs psscan

```text
pslist
→ active linked process structures 중심

psscan
→ memory pool scanning
```

비교표를 만든다.

| PID | pslist | psscan | 판단 |
|---:|---|---|---|
| 500 | O | O | 일반 프로세스 가능 |
| 712 | X | O | 종료/은닉/잔존 구조 조사 |

---

# 21.3 Process Tree Hunting Checklist

- [ ] Office → shell/script?
- [ ] Browser → shell?
- [ ] Web server → shell?
- [ ] Database → shell?
- [ ] services.exe가 아닌 parent의 svchost?
- [ ] user process가 SYSTEM child 생성?
- [ ] script host가 network tool 실행?
- [ ] `rundll32/regsvr32/mshta` unusual argument?

---

# 21.4 Memory Injection Hunting

의심 요소:

```text
Private executable VAD
RWX memory
MZ header in private region
Thread start outside module
PEB list mismatch
Injected DLL
```

관련 ATT&CK:

```text
T1055 Process Injection
```

하지만 브라우저/JIT/.NET 정상 activity를 반드시 배제한다.

---

# Part VIII. Persistence Hunting Practical Reference

# 22. Persistence Triage 순서

```text
1. Services
2. Scheduled Tasks
3. Run / RunOnce
4. Startup
5. WMI
6. Winlogon
7. IFEO
8. DLL/COM related autoruns
9. Drivers
10. Application-specific startup
```

---

# 22.1 Persistence에서 중요한 것은 Entry가 아니라 Target이다

예:

```text
HKCU\...\Run
    Updater = C:\Users\alice\AppData\Roaming\updater.exe
```

여기서 조사 대상은 두 개다.

```text
1. Run value
2. updater.exe
```

그리고 target file에서 다음으로 pivot한다.

```text
Hash
Signer
$MFT
Prefetch
Network
Process tree
```

---

# 22.2 Persistence Timeline

가능하면 다음 시점을 한 줄로 연결한다.

```text
10:31:10 malware.exe created
10:31:12 malware.exe executed
10:31:14 Run key modified
10:31:16 external C2 connection
```

이렇게 되면 persistence 등록 주체를 강하게 추정할 수 있다.

---

# Part IX. NTFS와 Timeline 심화

# 23. $MFT를 읽는 사고 방식

$MFT는 단순 파일 목록이 아니다.

질문:

```text
이 파일이 언제 나타났는가?
삭제되었는가?
이름이 바뀌었는가?
경로가 바뀌었는가?
SI/FN 시간이 일치하는가?
같은 시간대에 어떤 파일이 함께 생겼는가?
```

---

# 23.1 $UsnJrnl과 결합

$UsnJrnl은 파일 시스템 변경 이벤트를 기록한다.

예:

```text
FILE_CREATE
DATA_EXTEND
RENAME_OLD_NAME
RENAME_NEW_NAME
FILE_DELETE
```

이를 $MFT와 결합하면 매우 강력하다.

예:

```text
$MFT timestamp는 2019년
$UsnJrnl FILE_CREATE는 2026년
```

→ timestomping 가능성 증가.

---

# 23.2 $LogFile

NTFS transaction log인 `$LogFile`도 최근 filesystem operation 재구성에 도움을 줄 수 있다.

다만 parser와 Windows/NTFS 내부 구조에 대한 이해가 필요하다.

실무 우선순위는 보통:

```text
$MFT
$UsnJrnl
$LogFile
```

순으로 생각하면 편하다.

---

# 23.3 Copy와 Move의 Timestamp 변화

파일 timestamp 해석에서 가장 자주 틀리는 부분이다.

파일이 동일 volume에서 move되었는지, 다른 volume에서 copy되었는지에 따라 timestamp 동작이 다를 수 있다.

따라서 “Creation time이 바뀌었다 = 공격자가 조작했다”라고 단정하면 안 된다.

확인:

```text
Original path
Destination path
Volume
USN
LNK
Archive extraction
```

---

# 23.4 Timestomping Detection Checklist

- [ ] SI/FN mismatch
- [ ] Neighbor file timestamps와 부자연스러운 차이
- [ ] Exact timestamp cloning
- [ ] 00:00:00 또는 round seconds
- [ ] MFT record chronology mismatch
- [ ] USN chronology mismatch
- [ ] Prefetch execution이 file creation보다 비정상적으로 앞섬
- [ ] EDR file creation time과 NTFS time 불일치

---

# Part X. Execution Artifact 심화

# 24. 실행흔적을 하나만 보면 안 되는 이유

각 artifact는 생성 조건이 다르다.

예:

```text
Prefetch disabled
UserAssist only GUI
BAM version-dependent
ShimCache semantics version-dependent
Amcache schema changes
```

따라서 실무에서는 다음처럼 stacking한다.

```text
Prefetch
+ UserAssist
+ BAM
+ Amcache
+ Event 4688
+ EDR
```

2~3개가 같은 실행을 가리키면 신뢰도가 크게 높아진다.

---

# 24.1 Prefetch Timeline Interpretation

Prefetch에서 프로그램이 여러 번 실행되었다면 최근 실행 시각 여러 개가 기록될 수 있다.

분석할 때:

```text
First known execution
Last execution
Run count
```

을 구분한다.

Prefetch만으로 모든 과거 실행 시각을 무한히 보존하는 것은 아니다.

---

# 24.2 Prefetch 삭제도 흔적이다

공격자가 Prefetch를 삭제할 수 있다.

```text
C:\Windows\Prefetch\*.pf deletion
```

따라서 다음을 확인한다.

```text
$MFT deleted record
$UsnJrnl delete
EDR deletion telemetry
```

즉 “Prefetch가 없다”에서 분석을 끝내면 안 된다.

---

# 24.3 UserAssist에서 얻을 수 있는 사용자 맥락

UserAssist는 공격자가 직접 GUI에서 도구를 실행했는지, 사용자가 decoy/document를 열었는지 확인할 때 유용하다.

예:

```text
User opened suspicious document
      ↓
Office process child execution
```

을 보완할 수 있다.

---

# 24.4 LNK + Jump List + Prefetch 조합

매우 강력한 사용자 행위 복원 조합이다.

```text
LNK
→ 어떤 경로의 파일을 열었는가

Jump List
→ 어떤 application에서 최근 열었는가

Prefetch
→ 프로그램이 실행되었는가
```

---

# Part XI. Event Log / EDR와 연결하기

# 25. Windows Security Log

중요 Event ID 예:

```text
4624 Successful logon
4625 Failed logon
4648 Explicit credential logon
4672 Special privileges assigned
4688 Process creation
4697 Service installed
4698 Scheduled task created
4720 User created
4728/4732 Group membership change
1102 Audit log cleared
```

환경/감사정책에 따라 기록 여부가 달라진다.

---

# 25.1 Sysmon 주요 이벤트

구성에 따라 다음이 유용하다.

```text
1  Process Create
3  Network Connection
7  Image Load
8  CreateRemoteThread
10 Process Access
11 File Create
12 Registry Object Create/Delete
13 Registry Value Set
14 Registry Object Rename
15 FileCreateStreamHash
17/18 Named Pipe
19/20/21 WMI
22 DNS Query
```

특히 이 과정과 잘 연결되는 것:

```text
Process anomaly → Event 1
Persistence → Event 12/13
ADS → Event 15
Injection → Event 8/10
Network → Event 3
WMI persistence → Event 19/20/21
```

---

# 25.2 Event Log와 Artifact의 역할 차이

Event Log는 telemetry다.

NTFS/Registry artifact는 system state/history다.

둘은 서로 보완한다.

예:

```text
Sysmon 1
powershell.exe process created
      +
Prefetch
powershell execution
      +
Registry
Run key persistence
```

---

# Part XII. Threat Hunting으로 확장하기

# 26. Hunting은 IOC Search가 아니다

단순 헌팅:

```text
hash == abc123
```

는 IOC search다.

보다 강한 hunting은 행위를 찾는다.

예:

```text
Office process
→ script interpreter
→ network connection
```

또는

```text
Unsigned binary
+ user-writable path
+ persistence registry
```

---

# 26.1 Hunt Hypothesis 예시 1

가설:

> 사용자를 대상으로 한 악성 문서가 Office child process를 통해 PowerShell을 실행했을 수 있다.

데이터:

```text
Process creation
Command line
Office telemetry
PowerShell logs
Network
```

조건:

```text
ParentImage IN (WINWORD.EXE, EXCEL.EXE, POWERPNT.EXE)
AND
Image IN (powershell.exe, cmd.exe, wscript.exe, cscript.exe, mshta.exe)
```

---

# 26.2 Hunt Hypothesis 예시 2

가설:

> 공격자가 정상 Windows binary 이름을 사용자 디렉터리에 복사하여 위장했을 수 있다.

조건:

```text
ImageName == known_system_binary
AND
Path NOT IN expected_system_path
```

예:

```text
svchost.exe not under System32
lsass.exe not under System32
```

---

# 26.3 Hunt Hypothesis 예시 3

가설:

> 공격자가 사용자 writable directory의 실행 파일을 자동 실행에 등록했을 수 있다.

조건:

```text
Persistence target path contains:
AppData
Temp
Public
Downloads
ProgramData
```

그리고 다음을 추가한다.

```text
Unsigned
Rare hash
Recent creation
```

---

# 26.4 Hunt Hypothesis 예시 4

가설:

> 공격자가 timestomping으로 악성 파일을 오래된 파일처럼 위장했을 수 있다.

조건:

```text
SI timestamp << FN timestamp
OR
MFT timestamp inconsistent with USN
```

---

# 26.5 Hunt Hypothesis 예시 5

가설:

> Internet에서 다운로드된 파일이 짧은 시간 안에 실행되었을 수 있다.

상관분석:

```text
Zone.Identifier
+ MFT Creation
+ Prefetch
```

시간 조건:

```text
execution_time - creation_time < 5 minutes
```

이는 피싱/drive-by triage에 매우 강하다.

---

# Part XIII. IR Analyst Workflow

# 27. 실제 사고 발생 시 15분 Triage

## Minute 0~3

```text
Host
User
Alert source
Time
IP
EDR status
```

확인.

## Minute 3~6

```text
Process tree
Command line
Signer
Path
Hash
```

확인.

## Minute 6~9

```text
Network
DNS
Remote IP
Other affected hosts
```

확인.

## Minute 9~12

```text
Persistence
File creation
Parent process
```

확인.

## Minute 12~15

```text
Contain?
Memory collect?
Account disable?
Block IOC?
```

결정.

---

# 27.1 Host Forensics Workflow

```text
1. Preserve
2. Memory
3. Triage collection
4. Process analysis
5. Persistence analysis
6. Filesystem timeline
7. Execution artifacts
8. Network correlation
9. Scope expansion
10. Report
```

---

# 27.2 Scope Expansion

한 호스트에서 악성 파일을 찾았으면 다른 호스트에서도 검색한다.

검색 pivot:

```text
SHA-256
Filename
Path
Domain
IP
Registry value
Service name
Scheduled task
Command line fragment
Mutex
Certificate
```

하지만 hash는 쉽게 바뀐다.

더 강한 pivot:

```text
Parent-child relation
Persistence path
Command pattern
Network behavior
```

---

# Part XIV. 분석가가 자주 하는 실수

# 28. 실수 1 — 프로세스 이름만 본다

```text
svchost.exe → 정상
```

이 아니다.

```text
svchost.exe
+ path
+ parent
+ signer
+ command line
```

을 본다.

---

# 28.1 실수 2 — Prefetch가 없으면 실행 안 됐다고 결론

잘못이다.

가능성:

- disabled
- deleted
- OS behavior
- storage/server configuration
- cleanup

다른 artifact를 찾는다.

---

# 28.2 실수 3 — ShimCache entry = 실행 확정

OS 버전에 따라 semantics가 다르다.

교차검증 필수.

---

# 28.3 실수 4 — Timestamp를 절대 사실로 믿는다

Timestamp는 변경될 수 있다.

```text
SI
FN
USN
Prefetch
Event Log
```

교차검증한다.

---

# 28.4 실수 5 — 서명되어 있으면 정상

Signed binary도 공격에 악용된다.

```text
LOLBin
Signed vulnerable driver
Stolen cert
```

을 기억한다.

---

# 28.5 실수 6 — IOC 하나만 검색한다

IOC는 변경이 쉽다.

행위 기반 detection을 만든다.

---

# Part XV. 실전 체크리스트

# 29. 프로세스 분석 체크리스트

- [ ] 이름이 정상적인가?
- [ ] 철자 위장이 있는가?
- [ ] 실행 경로가 정상인가?
- [ ] Parent가 정상인가?
- [ ] PPID가 자연스러운가?
- [ ] Command line이 정상인가?
- [ ] Signer가 유효한가?
- [ ] Version Info가 자연스러운가?
- [ ] 시작 시각이 사건 시간대와 일치하는가?
- [ ] 외부 연결이 있는가?
- [ ] 이상 DLL이 있는가?
- [ ] private executable memory가 있는가?

---

# 30. Persistence 분석 체크리스트

- [ ] Run/RunOnce
- [ ] Startup
- [ ] Service
- [ ] Scheduled Task
- [ ] WMI
- [ ] Winlogon
- [ ] IFEO
- [ ] AppInit / DLL persistence
- [ ] COM hijack
- [ ] Driver
- [ ] target binary path
- [ ] target signer
- [ ] target file creation time
- [ ] target execution evidence

---

# 31. Filesystem 분석 체크리스트

- [ ] $MFT
- [ ] $UsnJrnl
- [ ] ADS
- [ ] Zone.Identifier
- [ ] SI timestamp
- [ ] FN timestamp
- [ ] deleted record
- [ ] file hash
- [ ] parent directory
- [ ] neighboring creation events

---

# 32. Execution Artifact 체크리스트

- [ ] Prefetch
- [ ] UserAssist
- [ ] BAM/DAM
- [ ] Amcache
- [ ] ShimCache
- [ ] Jump List
- [ ] LNK
- [ ] Event 4688
- [ ] Sysmon 1
- [ ] EDR

---

# Part XVI. 조사 보고서 작성법

# 33. 좋은 DFIR 보고서의 구조

```text
1. Executive Summary
2. Scope
3. Evidence Collected
4. Timeline
5. Findings
6. Root Cause
7. Persistence
8. Impact
9. IOC/IOA
10. Containment
11. Remediation
12. Detection Recommendations
```

---

# 33.1 Finding 작성 예

나쁜 표현:

```text
악성 파일이 실행됐다.
```

좋은 표현:

```text
2026-10-05 12:31:44 UTC에 `update.exe`가 사용자 Downloads 경로에 생성되었다.
동일 파일에 Internet Zone을 의미하는 Zone.Identifier가 존재했다.
12:32:11 UTC에 UPDATE.EXE Prefetch가 생성되었고,
EDR Process Create telemetry에서도 동일 SHA-256의 프로세스 실행이 확인되었다.
따라서 해당 파일은 인터넷에서 유입된 후 약 27초 이내에 실행된 것으로 판단된다.
```

이렇게 **증거 → 사실 → 판단** 순서로 작성한다.

---

# 33.2 Confidence를 명시한다

```text
Confirmed
High confidence
Moderate confidence
Low confidence
Unknown
```

예:

```text
High confidence:
Prefetch와 EDR Process Create가 모두 존재하므로 실행 사실은 높은 신뢰도로 판단한다.
```

---

# 33.3 IOC와 IOA를 분리한다

## IOC

```text
SHA-256
Filename
Domain
IP
URL
Registry path
```

## IOA

```text
WINWORD → PowerShell
User directory svchost
Unsigned service binary
Internet download followed by immediate execution
SI/FN timestomp mismatch
```

IOA가 장기 탐지에 더 유용한 경우가 많다.

---

# Part XVII. MITRE ATT&CK 연결

# 34. 과정에서 자주 만나는 Technique

| 행위 | ATT&CK |
|---|---|
| Phishing | T1566 |
| User Execution | T1204 |
| Command/Scripting Interpreter | T1059 |
| Masquerading | T1036 |
| Process Injection | T1055 |
| Scheduled Task | T1053.005 |
| Windows Service | T1543.003 |
| Registry Run Keys / Startup | T1547.001 |
| WMI Event Subscription | T1546.003 |
| NTFS File Attributes / ADS | T1564.004 |
| Timestomp | T1070.006 |

ATT&CK 매핑은 공격을 “악성코드 이름”이 아니라 **행위 단위로 설명**할 수 있게 해준다.

---

# Part XVIII. 핵심 명령/도구 개념 메모

# 35. Memory 분석

Volatility 계열에서 기억할 개념:

```text
pslist
pstree
psscan
cmdline
netscan
dlllist
ldrmodules
handles
malfind
procdump
svcscan
```

명령 구문은 Volatility 2와 3에서 크게 다르므로 실제 사용 시 버전 문서를 확인한다.

---

# 35.1 File/PE 확인

도구 예:

```text
sigcheck
Get-AuthenticodeSignature
Get-FileHash
PEStudio
Detect It Easy
```

PowerShell 예:

```powershell
Get-FileHash .\sample.exe -Algorithm SHA256
```

```powershell
Get-AuthenticodeSignature .\sample.exe
```

---

# 35.2 ADS 확인

PowerShell:

```powershell
Get-Item .\file.exe -Stream *
```

특정 stream 읽기:

```powershell
Get-Content .\file.exe -Stream Zone.Identifier
```

분석 대상에서 직접 실행/변경하지 말고 사본에서 수행한다.

---

# 35.3 Registry Persistence 확인

예:

```powershell
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
```

실무 IR에서는 live host에서 command를 무분별하게 실행하면 증거가 변할 수 있으므로 collector 또는 EDR remote query를 우선 고려한다.

---

# 35.4 Service 확인

```powershell
Get-CimInstance Win32_Service |
Select-Object Name, State, StartMode, PathName
```

특히 `PathName`을 본다.

---

# 35.5 Scheduled Task 확인

```powershell
Get-ScheduledTask
```

Action/Trigger까지 확인해야 한다.

---

# Part XIX. 공부 방법

# 36. 이 과정을 복습하는 가장 좋은 방법

## 1단계 — Artifact 이름 암기 금지

먼저 질문을 만든다.

```text
실행됐는가?
다운로드됐는가?
자동실행됐는가?
시간이 조작됐는가?
```

그 다음 필요한 artifact를 떠올린다.

---

# 36.1 2단계 — 하나의 공격을 여러 아티팩트로 설명

예:

```text
Internet download
→ Zone.Identifier
→ $MFT
→ Prefetch
→ Process
→ Run Key
→ Network
```

이 체인을 말로 설명할 수 있으면 과정 내용을 제대로 이해한 것이다.

---

# 36.2 3단계 — 정상 사례와 악성 사례 비교

예:

```text
정상 svchost
vs
위장 svchost
```

비교 필드:

```text
Path
Parent
Signer
Command line
Network
```

---

# 36.3 4단계 — Timeline 직접 만들기

다음 컬럼을 갖는 CSV를 만든다.

```text
TimeUTC, Source, Host, User, Event, Path, Process, Evidence
```

예:

```text
2026-10-05T12:31:44Z,MFT,HOST01,alice,File Create,C:\Users\alice\Downloads\a.zip,,MFT FN Creation
2026-10-05T12:32:11Z,Prefetch,HOST01,alice,Execution,C:\Users\alice\Downloads\a.exe,a.exe,Prefetch
```

이 습관이 실제 DFIR 업무에 매우 중요하다.

---

# Part XX. 전체 과정을 한 장으로 요약

# 37. Windows Endpoint Compromise Investigation Map

```text
                    ┌─────────────────┐
                    │ Initial Access  │
                    └────────┬────────┘
                             │
          ┌──────────────────┼──────────────────┐
          │                  │                  │
       Browser             Email              USB/SMB
          │                  │                  │
          └──────────────────┼──────────────────┘
                             ↓
                      File Creation
                             │
                 $MFT / USN / MOTW
                             │
                             ↓
                        Execution
                             │
          ┌──────────────────┼──────────────────┐
          │                  │                  │
      Prefetch          Process Tree       UserAssist
          │                  │                  │
          └──────────────────┼──────────────────┘
                             ↓
                         Behavior
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
     Memory              Network            Persistence
        │                    │                    │
   Injection             C2/DNS       Run/Service/Task/WMI
        │                    │                    │
        └────────────────────┼────────────────────┘
                             ↓
                          Timeline
                             │
                             ↓
                   Scope / Root Cause
                             │
                             ↓
                    Detection Engineering
```

---

# 38. 가장 중요한 20개 포인트

1. **프로세스 이름보다 경로가 중요하다.**
2. **경로보다 Parent/Command Line까지 보면 더 강하다.**
3. **Process Tree는 공격 체인을 보여준다.**
4. **Memory는 fileless/injection 분석의 핵심이다.**
5. **pslist와 psscan을 비교하면 숨겨진/종료된 프로세스 단서를 얻을 수 있다.**
6. **Signed라고 안전한 것은 아니다.**
7. **Persistence entry의 target executable까지 조사해야 한다.**
8. **Run Key는 정상 프로그램도 사용한다.**
9. **Service와 Scheduled Task는 공격자가 매우 선호하는 persistence 지점이다.**
10. **$MFT는 파일 이력 재구성의 중심이다.**
11. **SI와 FN timestamp 차이는 timestomping의 단서가 될 수 있다.**
12. **Timestamp 하나만 믿으면 안 된다.**
13. **ADS는 정상 기능이며 동시에 은닉에 악용될 수 있다.**
14. **Zone.Identifier는 다운로드 기원을 추적하는 강력한 단서다.**
15. **Prefetch는 실행 증거로 매우 강하지만 존재하지 않는다고 미실행을 뜻하지 않는다.**
16. **ShimCache는 무조건적인 실행 증거가 아니다.**
17. **Execution Artifact는 여러 개를 stacking해야 한다.**
18. **모든 시간을 UTC로 정규화하면 timeline 오류를 줄일 수 있다.**
19. **IOC보다 IOA가 장기 탐지에 더 강한 경우가 많다.**
20. **최종 목표는 Artifact 찾기가 아니라 공격자의 행위 체인 복원이다.**

---

# 39. 최종 사고대응용 Mini Playbook

```text
[Alert]
   ↓
Identify host/user/time
   ↓
Inspect process tree + command line
   ↓
Check path/signer/hash
   ↓
Check memory + network
   ↓
Check persistence
   ↓
Check $MFT / USN / MOTW
   ↓
Check Prefetch / UserAssist / Amcache
   ↓
Build timeline
   ↓
Determine root cause
   ↓
Scope other hosts
   ↓
Contain / eradicate
   ↓
Create SIEM/EDR detections
```

---

# 40. 분석 결과를 SIEM 탐지로 바꾸는 사고방식

포렌식 결과가 다음과 같다고 하자.

```text
WINWORD.EXE
  └─ powershell.exe -enc ...
```

포렌식 보고서에서 끝내지 않는다.

Detection rule로 바꾼다.

```text
parent_process = WINWORD.EXE
AND
process IN (powershell.exe, cmd.exe, wscript.exe, cscript.exe, mshta.exe)
```

다른 예:

```text
persistence target in user-writable directory
```

탐지 조건:

```text
Registry Run Key modified
AND
ImagePath contains AppData/Temp/Downloads/Public
```

또 다른 예:

```text
system binary masquerading
```

탐지 조건:

```text
ImageName = svchost.exe
AND
ImagePath != C:\Windows\System32\svchost.exe
```

이런 식으로 DFIR 결과를 다시 예방/탐지 체계로 환류해야 한다.

---

# 41. 마지막 정리

이 과정에서 배우는 아티팩트는 각각 독립적인 주제가 아니다.

가장 중요한 연결은 다음이다.

```text
유입 흔적
      ↓
파일 생성 흔적
      ↓
실행 흔적
      ↓
프로세스 행위
      ↓
지속성
      ↓
네트워크/후속 행위
      ↓
타임라인
```

숙련된 IR/DFIR 분석가는 다음과 같이 생각한다.

```text
“Prefetch가 있다.”
```

에서 멈추지 않고,

```text
“이 파일은 언제 시스템에 들어왔고,
누가 실행했으며,
무슨 프로세스를 만들었고,
어떤 지속성을 남겼으며,
어디로 통신했고,
다른 시스템에도 같은 행위가 있는가?”
```

까지 이어간다.

이 질문에 증거 기반으로 답할 수 있으면 단순 아티팩트 분석을 넘어 **사고대응·포렌식 분석가의 사고방식**에 가까워진 것이다.
