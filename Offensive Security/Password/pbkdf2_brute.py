import sys
import hashlib
import argparse
from tqdm import tqdm

def main():
    parser = argparse.ArgumentParser(
        description="PBKDF2-HMAC 다중 변형 Dictionary Attack"
    )
    parser.add_argument("wordlist", help="단어장 파일 경로")
    parser.add_argument("hash", help="목표 해시 (hex string)")
    parser.add_argument("salt", help="salt (hex string)")
    parser.add_argument("iterations", type=int, help="반복 횟수")
    
    parser.add_argument("-a", "--algorithm", 
                        choices=[
                            "sha1", "sha224", "sha256", "sha384", "sha512",
                            "sha3_224", "sha3_256", "sha3_384", "sha3_512",
                            "blake2b", "blake2s"
                        ],
                        default="sha256",
                        help="PBKDF2 내부 HMAC 알고리즘 (기본: sha256)")
    
    parser.add_argument("-d", "--dklen", type=int, default=32,
                        help="출력 길이 (기본 32바이트, SHA1은 보통 20)")
    parser.add_argument("-e", "--encoding", choices=["utf-8", "latin1", "ascii"], 
                        default="utf-8", help="비밀번호 인코딩")
    
    args = parser.parse_args()

    target = bytes.fromhex(args.hash)
    salt = bytes.fromhex(args.salt)

    print(f"[+] PBKDF2 공격 시작")
    print(f"    알고리즘    : PBKDF2-HMAC-{args.algorithm.upper()}")
    print(f"    Target hash : {args.hash}")
    print(f"    Salt        : {args.salt}")
    print(f"    Iterations  : {args.iterations}")
    print(f"    dklen       : {args.dklen}")
    print(f"    Wordlist    : {args.wordlist}\n")

    try:
        with open(args.wordlist, "r", encoding=args.encoding, errors="ignore") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print("[-] 단어장 파일을 찾을 수 없습니다.")
        sys.exit(1)

    for line in tqdm(lines, desc="Cracking", unit="pw"):
        password = line.strip()
        if not password:
            continue

        try:
            derived = hashlib.pbkdf2_hmac(
                args.algorithm,
                password.encode(args.encoding),
                salt,
                args.iterations,
                dklen=args.dklen
            )
        except ValueError as e:
            print(f"[-] 오류: {e}")
            sys.exit(1)

        if derived == target:
            print(f"\n[+] 성공! 비밀번호: → {password}")
            print(f"    사용된 알고리즘: PBKDF2-HMAC-{args.algorithm.upper()}")
            return

    print("\n[-] 단어장 끝까지 찾았으나 실패")

if __name__ == "__main__":
    main()
