import random
import math


def pqgen():

    while True:

        p = random.randint(400, 500)
        q = random.randint(400, 500)

        if p != q:
            if primality_test(p) == True:
                if primality_test(q) == True:
                    ETFn = (p-1)*(q-1)
                    return (p, q, ETFn)

# func for right p, q


def primality_test(p):
    for i in range(2, p-1):

        if p % i == 0:
            return False
        else:
            pass

    return True

# func to choose correct e


def relprime_test(e, ETFn):

    while True:
        a = max(e, ETFn)
        b = min(e, ETFn)

        e = a % b
        ETFn = b

        if e == 1:
            return True
        elif e == 0:
            return False


def relprime_gen(ETFn):
    while True:
        e = random.randint(1, ETFn)
        if relprime_test(e, ETFn) == True:
            return e


# func to find d(modular inverse of e)


def modinv_pow(e, ETFn):
    try:
        return pow(e, -1, ETFn)
    except ValueError:
        raise ValueError(f"No modular inverse: gcd({e}, {ETFn}) != 1")