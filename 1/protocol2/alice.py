import p2
import socket
import argparse
import logging
import json
import random
import string
import os
import base64
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aes

def send_message(sock, msgdict):
    sjs = json.dumps(msgdict)
    sbytes = sjs.encode("ascii")
    sock.sendall(sbytes)
    logging.info(f"[*] Sent: {sjs}")

def receive_message(sock):
    rbytes = sock.recv(4096)
    if not rbytes:
        logging.warning("[*] Server closed connection.")
        return None
    rjs = rbytes.decode("ascii")
    rmsg = json.loads(rjs)
    logging.info(f"[*] Received: {rjs}")
    return rmsg

def run(addr, port):
    bob_public_key = None
    my_aes_key_str = None
    my_aes_key_byte = None

    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((addr, port))
    logging.info("Alice is connected to {}:{}".format(addr, port))

    try:
        msg1 = {"opcode": 0, "type": "RSA"}
        send_message(conn, msg1)
        """B: n, e 받고 키 생성"""
        rmsg1 = receive_message(conn)
        if not (rmsg1 and rmsg1.get("opcode") == 1 and rmsg1.get("type") == "RSA"):
            logging.error("[*] Cannnot receive RSA key response.")
            return

        bob_public_key = {"n": rmsg1["parameter"]["n"], "e": rmsg1["public"]}
        logging.info("[*] B 구간: Received RSA key.")

        my_aes_key_str = "".join(random.choices(string.ascii_letters + string.digits, k = 32))
        my_aes_key_byte = my_aes_key_str.encode("utf-8")

        enc_key_list = []
        n, e = bob_public_key["n"], bob_public_key["e"]
        for char in my_aes_key_str:
            char_code = ord(char)
            enc_code = p2.rsa_encrypt(char_code, n, e)
            enc_key_list.append(enc_code)
        
        msg2 = {"opcode": 2, "type": "RSA", "encryption": enc_key_list}
        send_message(conn, msg2)

        """C. 받은 메시지 decode"""

        enc_hello = aes.aes_encrypt_b64(my_aes_key_byte, "hello")
        msg3 = {"opcode": 2, "type": "AES", "encryption": enc_hello}
        send_message(conn, msg3)
        logging.info("[*] Sent.")

        rmsg2 = receive_message(conn)
        if not(rmsg2 and rmsg2.get("opcode") == 2 and rmsg2.get("type") == "AES"):
            logging.error("[*] No response received")
            return
        
        enc_world = rmsg2.get("encryption")
        if not enc_world:
            logging.error("[*] No encryption field in response.")
            return
        
        dec_world = aes.aes_decrypt_b64(my_aes_key_byte, enc_world)
        if dec_world == "world":
            logging.info(f"[*] Success.")
        else:
            logging.error("[*] Failed.")

    except ConnectionResetError:
        logging.info(f"[*] Connection from Bob({addr}:{port}) closed")
    except Exception as e:
        logging.error(f"[*] Error: {e}", exc_info = True)
    finally:
        conn.close()
        logging.info(f"[*] Connection from Bob({addr}:{port}) closed")



def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's address>", help="Bob's address", type=str, required=True)
    parser.add_argument("-p", "--port", metavar="<bob's port>", help="Bob's port", type=int, required=True)
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
