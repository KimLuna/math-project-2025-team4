import socket
import argparse
import logging
import json

from aes import aes_encrypt_b64, aes_decrypt_b64
from dh import (
    is_prime,
    find_prime_400_500,
    is_generator,
    make_private_key,
    make_public_key,
    make_shared_secret,
    derive_aes_key,
)


def run(addr, port):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((addr, port))
    logging.info("Alice is connected to {}:{}".format(addr, port))

    # sending DH message request
    req = {"opcode": 0, "type": "DH"}
    msg = json.dumps(req).encode("ascii")
    conn.sendall(msg)
    logging.info(f"[*] Sent DH request: {req}")

    # receive DH parameter from Bob
    rbytes = conn.recv(4096)
    rjs = rbytes.decode("ascii")
    resp = json.loads(rjs)
    logging.info(f"[*] Received: {resp}")

    # message form: {"opcode":1,"type":"DH","public":B,"parameter":{"p":p,"g":g}}
    p = resp["parameter"]["p"]
    g = resp["parameter"]["g"]
    B = resp["public"]

    # verify p, q
    if not is_prime(p):
        logging.error("Bob's p is not prime. Aborting.")
        err_msg = {"opcode": 3, "error": "incorrect prime number"}
        conn.sendall(json.dumps(err_msg).encode("ascii"))
        conn.close()
        return

    if not is_generator(g, p):
        logging.warning("Bob's g is not a generator. Aborting.")
        err_msg = {"opcode": 3, "error": "incorrect generator"}
        conn.sendall(json.dumps(err_msg).encode("ascii"))
        conn.close()
        return
    logging.info("p and g are valid.")

    # generate Alice keys(public, private)
    a = make_private_key(p)
    A = make_public_key(g, a, p)
    logging.info(f"Alice private a={a}, public A={A}")

    # send A to Bob
    send_msg = {"opcode": 1, "type": "DH", "public": A}
    conn.sendall(json.dumps(send_msg).encode("ascii"))
    logging.info(f"[*] Sent A: {send_msg}")

    # calculate shared secret
    s = make_shared_secret(B, a, p)
    key = derive_aes_key(s)
    logging.info(f"Derived shared secret and AES key (len={len(key)})")

    # encrypt message & send
    enc_msg = aes_encrypt_b64(key, "hello")
    send_enc = {"opcode": 2, "type": "AES", "encryption": enc_msg}
    conn.sendall(json.dumps(send_enc).encode("ascii"))
    logging.info(f"[*] Sent encrypted message: {send_enc}")

    # Decrypt Bob's response
    rbytes = conn.recv(4096)
    rjs = rbytes.decode("ascii")
    resp = json.loads(rjs)
    logging.info(f"[*] Received AES from Bob: {resp}")

    enc_world = resp["encryption"]
    world = aes_decrypt_b64(key, enc_world)
    logging.info(f"[*] Decrypted from Bob: {world}")

    conn.close()


def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-a",
        "--addr",
        metavar="<bob's address>",
        help="Bob's address",
        type=str,
        required=True,
    )
    parser.add_argument(
        "-p",
        "--port",
        metavar="<bob's port>",
        help="Bob's port",
        type=int,
        required=True,
    )
    parser.add_argument(
        "-l",
        "--log",
        metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>",
        help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)",
        type=str,
        default="INFO",
    )
    args = parser.parse_args()
    return args


def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    run(args.addr, args.port)


if __name__ == "__main__":
    main()
