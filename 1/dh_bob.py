import socket
import threading
import argparse
import logging
import json

from dh import find_prime_400_500, find_generator, make_private_key, make_public_key


def handler(sock):
    # receive request
    rbytes = sock.recv(4096)
    rjs = rbytes.decode("ascii")
    req = json.loads(rjs)
    logging.info(f"[*] Received: {req}")

    if req["opcode"] == 0 and req["type"] == "DH":
        # generate DH parameters
        p = find_prime_400_500()
        g = find_generator(p)
        b = make_private_key(p)
        B = make_public_key(g, b, p)
        logging.info(f"Generated p={p}, g={g}, b={b}, B={B}")

        # send response
        resp = {
            "opcode": 1,
            "type": "DH",
            "public": B,
            "parameter": {"p": p, "g": g}
        }
        sock.sendall(json.dumps(resp).encode("ascii"))
        logging.info(f"[*] Sent DH parameters: {resp}")

    sock.close()

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
