from dataclasses import dataclass
from random import randint

from math import sqrt
from primes import PRIMES
from sha3_hash import Sha3_512_encoder

FERMAT_NUMBERS = [17, 257, 65537]

RABIN_MILLER_ATTEMPTS = 50

@dataclass
class Key:
    exponent: int
    modulo: int

@dataclass
class KeyPair:
    private_key: Key
    public_key: Key

# Binary Exponentiation
def power(x, y, p=1):
    # Initialize result
    res = 1; 
    x = x % p; 
    while (y > 0):
        if (y & 0b1):
            res = (res * x) % p

        y = y>>1
        x = (x * x) % p
     
    return res

def extened_ea(a: int, b: int) -> (int, int):
    q, r = 0, 0

    x_prev, x_cur, x_new = 1, 0, 0
    y_prev, y_cur, y_new = 0, 1, 0

    while b != 0:
        # main euclidian cycle
        q = a // b
        r = a % b

        a = b
        b = r

        # extension
        x_new = x_prev - q * x_cur
        y_new = y_prev - q * y_cur
        
        x_prev = x_cur
        y_prev = y_cur
        x_cur = x_new
        y_cur = y_new

    return x_prev, y_prev

# a must be less than modulo AND gcd(a, modulo) must be 1
def reverse_mod(a: int, modulo: int) -> int:
    rev = extened_ea(a, modulo)[0]

    if rev < 0:
        rev = rev + modulo
    return rev

class rsa_cipher:
    __hasher: Sha3_512_encoder = Sha3_512_encoder()
    __d: int

    def __miller_iteration(self, number: int, d: int, r: int) -> bool:
        a = randint(2, number-1) # a in [2, n-2]

        # x = a**d % number
        x = power(a, d, number)

        if (x == 1 or x == number-1):
            return True
        
        for _ in range(r):
            x = (x * x) % number
            if (x == 1):
                return False
            if (x == number - 1):
                return True
 
        return False; 

# Rabin-miller test - O(k log3 n)
    def rabin_miller_test(self, number: int) -> bool:
        s, r = number - 1, 0
        while s % 2 == 0:
            r += 1 # calculate the power of 2 in s factorization
            s //= 2 # then (number-1) = s * 2**r

        for _ in range(RABIN_MILLER_ATTEMPTS):
            if(self.__miller_iteration(number, s, r) == False):
                return False

        return True 

    def test_prime_table(self, number: int) -> bool:
        return all([ number % prime != 0 for prime in PRIMES ])
    
    def generate_prime(self, bits: int) -> int:
        while True:
            prime_candidate = randint(sqrt(2) * ((0b1<<bits)+1), 0b1<<(bits+1)) # generate integer in [sqrt(2) * 2**bits+1, 2**(bits+1)-1]

            if prime_candidate % 2 != 0 \
                and self.test_prime_table(prime_candidate) \
                and self.rabin_miller_test(prime_candidate):
                break

        return prime_candidate

    def generate_primes(self, size: int) -> (int, int):
        while True:
            p1, p2 = self.generate_prime(size), self.generate_prime(size)
            if p1 != p2 and abs(p1 - p2) > power(2, size-100):
                break

        return p1, p2

    def generate_keys(self, size: int) -> KeyPair:
        p, q = self.generate_primes(size // 2) # // 2 because key is product of two prime numbers
        print("Primes:",p,q)

        n = p * q
        phi_n = (p - 1) * (q - 1)
        print("phi:",phi_n)
        e = FERMAT_NUMBERS[2]
        d = reverse_mod(e, phi_n)
        self.__d = d

        return KeyPair(
            private_key=Key(d, n),
            public_key=Key(e, n)
        )

    def __apply_cipher(self, data: bytes, key: Key) -> bytes:
        number = int.from_bytes(data)
        # (number ^ key.exponent) % key.modulo
        c_number = power(number, key.exponent, key.modulo)

        size_bytes = c_number.bit_length() // 8
        if c_number.bit_length() % 8 != 0:
            size_bytes += 1
        return int.to_bytes(c_number, length=size_bytes)

    def encrypt(self, data: bytes, public_key: Key) -> bytes:
        return self.__apply_cipher(data, public_key)        

    def decrypt(self, data: bytes, private_key: Key) -> bytes:
        return self.__apply_cipher(data, private_key)

    def sign(self, data: bytes, private_key: Key) -> bytes:
        hash = self.__hasher.get_bytes_hash(data)
        return self.__apply_cipher(hash, private_key)

    def verify(self, data: bytes, signature: bytes, public_key: Key) -> bool:
        decrypted_hash = self.__apply_cipher(signature, public_key)
        hash = self.__hasher.get_bytes_hash(data)
        return hash == decrypted_hash
