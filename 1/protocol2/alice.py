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
    sock.sendall(sjs.encode("ascii"))

def receive_message(sock):
    rbytes = sock.recv(4096)
    if not rbytes:
        logging.warning("[*] Server closed connection.")
        return None
    rjs = rbytes.decode("ascii")
    rmsg = json.loads(rjs)
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
        logging.info("[*] 구간 A: Sent.")
        """B: n, e 받고 키 생성"""
        rmsg1 = receive_message(conn)
        if not (rmsg1 and rmsg1.get("opcode") == 1 and rmsg1.get("type") == "RSA"):
            logging.error("[*] B 구간: Cannnot receive RSA key response.")
            return

        bob_public_key = {"n": rmsg1["parameter"]["n"], "e": rmsg1["public"]}
        logging.info(f"[*] B 구간: Received RSA key: {rmsg1}.")

        my_aes_key_str = "".join(random.choices(string.ascii_letters + string.digits, k = 32))
        my_aes_key_byte = my_aes_key_str.encode("ascii")

        enc_key_list = []
        n, e = bob_public_key["n"], bob_public_key["e"]
        for char in my_aes_key_str:
            char_code = ord(char)
            enc_code = p2.rsa_encrypt(char_code, n, e)
            enc_key_list.append(enc_code)

        msg2 = {"opcode": 2, "type": "RSA", "encrypted_key": enc_key_list}
        send_message(conn, msg2)
        logging.info(f"[*] B 구간: Sent (items = {len(enc_key_list)}).")

        """C. 받은 메시지 decode (encryption 써야 키에러 안 남)"""
        #여기서 bob 구간 2에서 보낸 메시지 받고 decode 해야 할 것 같은데?
        rmsg22 = receive_message(conn)

        logging.warning(f"[DEBUG] 학교 서버가 보낸 메시지: {rmsg22}")

        if not(rmsg22 and rmsg22.get("opcode") == 2 and rmsg22.get("type") == "AES"):
            logging.error("[*] C 구간: No AES key received.")
            return
        logging.info("[*] C 구간: Received AES key.")
        enc_message = rmsg22["encryption"]

        try:
            msg_bob = aes.aes_decrypt_b64(my_aes_key_byte, enc_message)
            logging.info(f"[*] 구간 C: Decrypted from Bob: {msg_bob}")
        except Exception as e:
            logging.error(f"[*] 구간 C: Failed to decrypt: {e}")
            return
        
        user_input = input("[*] 구간 C: Alice input: ")
        enc_input = aes.aes_encrypt_b64(my_aes_key_byte, user_input)
        msg3 = {"opcode": 2, "type": "AES", "encryption": enc_input}
        send_message(conn, msg3)
        logging.info("[*] C 구간: Sent.")
    except json.JSONDecodeError:
        logging.error("[*] Failed to decode JSON (client likely disconnected)")
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
