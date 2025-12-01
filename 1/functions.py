import random
import math

def is_prime(n: int) -> bool:
    """Check if n is a prime number."""
    if n < 2:
        return False

    if n == 2:
        return True

    if n % 2 == 0:
        return False

    limit = int(n ** 0.5) + 1
    for i in range(3, limit, 2):
        if n % i == 0:
            return False

    return True

def find_prime_400_500() -> int:
    """Generate a random prime number (400 <= p <= 500)."""
    while True:
        p = random.randint(400, 500)
        if is_prime(p):
            return p

def factorize(n: int):
    """Return all prime factors of n."""
    factors = []
    i = 2
    while i * i <= n:
        if n % i == 0:
            factors.append(i)
            while n % i == 0:
                n //= i
        i += 1
    if n > 1:
        factors.append(n)
    return factors

def is_generator(g: int, p: int) -> bool:
    """Check whether g is a generator of Z_p*."""
    if g <= 1 or g >= p:
        return False

    factors = factorize(p - 1)
    for q in factors:
        if pow(g, (p - 1) // q, p) == 1:
            return False
    return True

def find_generator(p: int) -> int:
    """Find a generator g for given prime p."""
    while True:
        g = random.randint(2, p - 2)
        if is_generator(g, p):
            return g

def make_private_key(p: int) -> int:
    """Generate a random private key for DH (2 <= a <= p-2)."""
    return random.randint(2, p - 2)

def make_public_key(g: int, a: int, p: int) -> int:
    """Compute public key A = g^a mod p."""
    return pow(g, a, p)

def make_shared_secret(peer_public: int, my_private: int, p: int) -> int:
    """Compute shared secret s = peer_public^my_private mod p."""
    return pow(peer_public, my_private, p)

def derive_aes_key(shared: int) -> bytes:
    """Derive a 32-byte AES key from the shared secret."""
    # shared secret -> 2-byte big-endian
    s_bytes = shared.to_bytes(2, 'big', signed=False)
    # generate 32-byte key
    return s_bytes * 16
