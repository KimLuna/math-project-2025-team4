import p2
import socket
import threading
import argparse
import logging
import json
import os
import sys
import traceback
import base64
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aes
from functions import (
    is_prime,
    find_prime_400_500
)
from typing import List, Tuple

def handler(conn):
    my_private_key = None
    rec_aes_key = None

    peer_addr = conn.getpeername()
    logging.info(f"[*] Bob accepts the connection from Alice {peer_addr}")

    try:
        rbytes = conn.recv(4096)
        if not rbytes:
            logging.info(f"[*] 구간 0: Connection from Alice{peer_addr} closed")
            return
        rmsg = json.loads(rbytes.decode("ascii"))
        logging.info(f"[*] Received: {rmsg}")
        if not(rmsg.get("opcode") == 0 and rmsg.get("type") == "RSA"):
            logging.error("[*] 구간 0: Invalid Input.")
            return
            
        """1 RSA Keypair 생성"""
        smsg = None
        n, e, d = p2.generate_rsa_keypair()
        my_private_key = {'d': d, 'n': n}
        logging.info(f"[*] 구간 1: Generated RSA key")
        smsg = {"opcode": 1, "type": "RSA", "public": e, "parameter": {"n": n}}
        conn.sendall(json.dumps(smsg).encode("ascii"))
        logging.info(f"[*] 구간 1: Sent RSA key: {smsg}")

        """2 Encrypted key 받음"""
        data = conn.recv(4096)
        if not data:
            logging.error("[*] 구간 2: No Key received")
            return
        rmsg = json.loads(data.decode("ascii"))

        if not(rmsg.get("opcode") == 2 and rmsg.get("type") == "RSA"):
            logging.error("[*] 구간 2: Invalid Input.")
            return
    
        enc_key_list = rmsg.get("encrypted_key")
        if not enc_key_list:
            logging.error("[*]구간 2: No encrypted key field found.")
            return

        key_chars = []
        for enc_code in enc_key_list:
            dec_code = p2.rsa_decrypt(enc_code, my_private_key["d"], my_private_key["n"])
            key_chars.append(dec_code)
        rec_aes_key = bytes(key_chars)
        logging.info(f"[*] 구간 2: Encoded to AES (len={len(rec_aes_key)})")
        """2-1. encrypted_key에서 encryption으로 써줘야함"""
        input_msg = input("[*] 구간 2: Bob input: ")
        enc_input = aes.aes_encrypt_b64(rec_aes_key, input_msg)
        smsg = {"opcode": 2, "type": "AES", "encryption": enc_input}
        conn.sendall(json.dumps(smsg).encode("ascii"))
        logging.info(f"[*] 구간 2: Sent encrypted input to Alice.")

        """3. AES 메시지 decode"""
        data = conn.recv(4096)
        if not data:
            logging.error("[*] 구간 3: Invalid Input.")
            return
        rmsg = json.loads(data.decode("ascii"))

        if not(rmsg.get("opcode") == 2 and rmsg.get("type") == "AES"):
            logging.error("[*] 구간 3: Invalid Input.")
            return
        
        enc_response = rmsg["encryption"]
        response = aes.aes_decrypt_b64(rec_aes_key, enc_response)
        logging.info(f"[*] 구간 3: Received: {response}.")
    except json.JSONDecodeError:
        logging.error("[*] Failed to decode JSON (client likely disconnected)")
    except ConnectionResetError:
        logging.info(f"[*] Connection from Alice{peer_addr} closed")
    except Exception as e:
        logging.error(f"[*] Error: {e}", exc_info = True)
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