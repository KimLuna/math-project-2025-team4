import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from functions import find_prime_400_500
from typing import Tuple


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def mod_inverse(e, phi):
    d, new_d = 0, 1
    r, new_r = phi, e

    while new_r != 0:
        quotient = r // new_r
        d, new_d = new_d, d - quotient * new_d
        r, new_r = new_r, r - quotient * new_r

    if r > 1:
        raise ValueError("mod_inverse: inverse does not exist")

    if d < 0:
        d = d + phi  # d가 음수이면 양수로 변환

    return d


def generate_rsa_keypair() -> Tuple[int, int, int]:
    """RSA 키 쌍 생성 (e=17로 고정)"""
    p = find_prime_400_500()
    q = find_prime_400_500()
    while p == q:
        q = find_prime_400_500()

    n = p * q
    phi_n = (p - 1) * (q - 1)

    e = 17
    while gcd(e, phi_n) != 1:
        e += 2

    d = mod_inverse(e, phi_n)

    return (n, e, d)


def rsa_encrypt(msg_int: int, n: int, e: int) -> int:
    """RSA 암호화"""
    return pow(msg_int, e, n)


def rsa_decrypt(cipher_int: int, d: int, n: int) -> int:
    """RSA 복호화"""
    return pow(cipher_int, d, n)
