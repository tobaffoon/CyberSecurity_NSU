from sha3_hash import Sha3_512_encoder
from rsa import rsa_cipher
from primes import PRIMES

def print_bytes(data: bytes):
    print(''.join([f"{x:02x}" for x in data])) # print in hex

def main():
    print(len(PRIMES))
    key_bytes = 512
    rsa = rsa_cipher()
    key_pair = rsa.generate_keys(key_bytes)
    print("Public key: ", key_pair.public_key)
    print("Private key: ", key_pair.private_key)

    print("Small test results:")
    small_message = "small_message"
    small_message_bytes = small_message.encode()

    c_bytes = rsa.encrypt(small_message_bytes, key_pair.public_key)
    d_bytes = rsa.decrypt(c_bytes, key_pair.private_key)

    print("Original bytes: ")
    print_bytes(small_message_bytes)
    print("Encrypted bytes: ")
    print_bytes(c_bytes)
    print("Decrypted bytes: ")
    print_bytes(d_bytes)
    print("Result: ", end='')
    print(small_message_bytes == d_bytes)

    print("\n\nBig test results:")
    big_text = open('shinel.txt', 'rb')
    big_message_bytes = big_text.read()

    signature = rsa.sign(big_message_bytes, key_pair.private_key)
    proto = rsa.verify(big_message_bytes, signature, key_pair.public_key)

    test_hasher = Sha3_512_encoder()
    print("Hash: ")
    print_bytes(test_hasher.get_bytes_hash(big_message_bytes))
    print("Privately encrypted hash: ")
    print_bytes(signature)
    print("Publicly decrypted hash: ")
    print_bytes(rsa.decrypt(signature, key_pair.public_key))
    
    print(f"Big signing test: {proto}")
    big_text.close()

if __name__ == "__main__":
    main()