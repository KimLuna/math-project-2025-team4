
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from functions import (
    find_prime_400_500
)
from typing import Tuple

def gcd(a, b):
    """유클리드 호제법 (최대공약수)"""
    while b:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    """확장 유클리드 호제법 (모듈러 역원 d 계산)"""
    # (참고: 이 함수는 python 3.8+의 pow(e, -1, phi)로 대체 가능)
    d = 0
    x1, x2 = 0, 1
    temp_phi = phi
    
    while e > 0:
        temp1 = temp_phi // e
        temp2 = temp_phi - temp1 * e
        temp_phi, e = e, temp2
        
        x = x2 - temp1 * x1
        x2, x1 = x1, x
    
    if temp_phi == 1:
        d = x2 + phi
    
    return d % phi

def generate_rsa_keypair() -> Tuple[int, int, int]:
    """RSA 키 쌍 (n, e, d)를 생성합니다. (e=17로 고정)"""
    
    # 1. p, q 선택 (제공된 함수 사용)
    p = find_prime_400_500()
    q = find_prime_400_500()
    while p == q:
        q = find_prime_400_500()

    # 2. n, phi(n) 계산
    n = p * q
    phi_n = (p - 1) * (q - 1)

    # 3. e 선택 (1 < e < phi_n 이고, phi_n과 서로소)
    #    p, q가 400~500 범위이므로 phi_n은 20만 근처입니다.
    #    e=17은 이 조건을 만족합니다.
    e = 17 
    while gcd(e, phi_n) != 1:
        # (혹시 모르니 e를 바꿔가며 찾기)
        e += 2 
    
    # 4. d 계산 (모듈러 역원)
    d = mod_inverse(e, phi_n)
    
    # 공개키 (n, e), 개인키 (d) 반환
    return (n, e, d)

def rsa_encrypt(msg_int: int, n: int, e: int) -> int:
    """RSA 암호화: C = P^e mod n"""
    # msg_int는 암호화할 문자의 아스키코드(정수)여야 합니다.
    return pow(msg_int, e, n)

def rsa_decrypt(cipher_int: int, d: int, n: int) -> int:
    """RSA 복호화: P = C^d mod n"""
    # cipher_int는 수신한 암호문(정수)여야 합니다.
    return pow(cipher_int, d, n)