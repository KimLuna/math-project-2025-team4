import p2
import socket
import threading
import argparse
import logging
import json
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aes
from functions import (
    is_prime,
    find_prime_400_500
)

def handler(conn):
    my_private_key = None
    rec_aes_key = None

    peer_addr = conn.getpeername()
    logging.info(f"[*] Bob accepts the connection from Alice {peer_addr}")

    try:
        while True:
            rbytes = conn.recv(4096)
            if not rbytes:
                logging.info(f"[*] Connection from Alice{peer_addr} closed")
                break
            try:
                rjs = rbytes.decode("ascii")
                rmsg = json.loads(rjs)
                logging.info(f"[*] Received: {rmsg}")
            except Exception as e:
                logging.error(f"[*] Error: {e}")
                continue

            smsg = None
            if rmsg.get("opcode") == 0 and rmsg.get("type") == "RSA":
                n, e, d = p2.generate_rsa_keypair()
                my_private_key = {'d': d, 'n': n}
                logging.info(f"[*] Generated RSA key")
                smsg = {"opcode": 1, "type": "RSA", "public": e, "parameter": {"n": n}}
            elif rmsg.get("opcode") == 2 and rmsg.get("type") == "RSA":
                enc_key_list = rmsg.get("encryption")
                if not my_private_key:
                    logging.error(f"[*] No RSA key generated")
                    break
                if enc_key_list:
                    d = my_private_key['d']
                    n = my_private_key['n']
                    key_chars = []
                    for enc_code in enc_key_list:
                        dec_code = p2.rsa_decrypt(enc_code, d, n)
                        key_chars.append(chr(dec_code))
                    
                    rec_key_str = "".join(key_chars)
                    rec_aes_key = rec_key_str.encode("utf-8")
                    logging.info(f"[*] Received AES key: {rec_aes_key}")
                else:
                    logging.error(f"[*] No AES key received")
                continue
            elif rmsg.get("opcode") == 2 and rmsg.get("type") == "AES":
                enc_hello = rmsg.get("encryption")
                if not rec_aes_key:
                    logging.error(f"[*] No AES key received")
                    break
                if enc_hello:
                    key_bytes = rec_aes_key
                    try:
                        dec_hello = aes.aes_decrypt_b64(key_bytes, enc_hello)
                        logging.info(f"[*] Decrypted from Alice: {dec_hello}")
                        if dec_hello == "hello":
                            enc_world = aes.aes_encrypt_b64(key_bytes, "world")
                            smsg = {"opcode": 2, "type": "AES", "encryption": enc_world}
                        else:
                            break
                    except Exception as e:
                        logging.error(f"[*] Error: {e}")
                        break
                else:
                    logging.error(f"[*] No AES message received")
                    break

    except ConnectionResetError:
        logging.info(f"[*] Connection from Alice{peer_addr} closed")
    except Exception as e:
        logging.error(f"[*] Error: {e}")
    finally:
        conn.close()
        logging.info(f"[*] Connection from Alice{peer_addr} closed")


def run(addr, port):
    bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob.bind((addr, port))

    bob.listen(10)
    logging.info("[*] Bob is listening on {}:{}".format(addr, port))

    while True:
        conn, info = bob.accept()

        logging.info("[*] Bob accepts the connection from {}:{}".format(info[0], info[1]))

        conn_handle = threading.Thread(target=handler, args=(conn,))
        conn_handle.start()

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's IP address>", help="Bob's IP address", type=str, default="0.0.0.0")
    parser.add_argument("-p", "--port", metavar="<bob's open port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    run(args.addr, args.port)

if __name__ == "__main__":
    main()