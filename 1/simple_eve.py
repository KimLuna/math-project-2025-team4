import json
import logging
import argparse
import sys
import os

from aes import aes_decrypt_b64
from functions import make_shared_secret, derive_aes_key


def find_dh_secret_key(public_key, g, p):
    logging.info(f"[*] Attacking DLP: Finding 'a' where {g}^a % {p} == {public_key}")

    for a in range(1, p):
        # g^a mod p가 공유키가 되는 a를 계산
        if pow(g, a, p) == public_key:
            logging.info(f"[*] SUCCESS! Found secret key a = {a}")
            return a

    logging.error("[!] FAILED! Could not find secret key.")
    return None


def main(filename):
    logging.info(f"[*] Reading DH log file: {filename}")
    p, g, A, B = 0, 0, 0, 0
    aes_messages = []

    try:
        with open(filename, "r") as f:
            for line in f:
                try:
                    msg = json.loads(line.strip())
                except json.JSONDecodeError:
                    continue
                opcode = msg.get("opcode")

                # opcode 1: 키 교환 메시지
                if opcode == 1:
                    if "parameter" in msg:
                        # 밥의 첫 응답 (p, g, B)
                        p = msg["parameter"]["p"]
                        g = msg["parameter"]["g"]
                        B = msg["public"]
                    else:
                        # 앨리스의 응답 (A)
                        A = msg["public"]

                # opcode 2: AES 암호문
                elif opcode == 2:
                    aes_messages.append(msg["encryption"])

    except FileNotFoundError:
        logging.error(f"[!] File not found: {filename}")
        return
    except Exception as e:
        logging.error(f"[!] Error reading file: {e}")
        return

    aes_key = None
    print(f"\n--- Decrypting {filename} (DH Protocol) ---")

    if p == 0 or A == 0 or B == 0:
        logging.error("[!] Log file is incomplete. Missing p, g, A, or B.")
        return

    a = find_dh_secret_key(A, g, p)

    if a:
        # 공유 비밀키 계산
        s = make_shared_secret(B, a, p)
        aes_key = derive_aes_key(s)
        logging.info(f"[*] AES Key found (len={len(aes_key)})")
    else:
        logging.error("[!] DH Attack Failed: Could not find 'a'")

    # 최종적으로 AES 메시지를 해독한다.
    if aes_key:
        for i, enc_msg in enumerate(aes_messages):
            try:
                msg = aes_decrypt_b64(aes_key, enc_msg)
                print(f"Decrypted Message {i+1}: {msg}")
            except Exception as e:
                # 복호화 실패 에러 처리
                print(f"Decrypted Message {i+1}: FAILED (Error: {e})")
    else:
        print("Could not find AES key. Decryption failed.")


if __name__ == "__main__":
    logging.basicConfig(level="INFO", format="%(message)s")

    parser = argparse.ArgumentParser(description="Decrypt DH project log files.")
    # 로그 파일을 인수로 받도록 설정
    parser.add_argument("logfile", help="The path to the .log file to decrypt")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    main(args.logfile)
