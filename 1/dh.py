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
    """Generate a random prime number (400 < p < 500)."""
    while True:
        p = random.randint(400, 500)
        if is_prime(p):
            return p
