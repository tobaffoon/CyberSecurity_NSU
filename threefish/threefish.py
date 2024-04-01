from numpy import uint64, ndarray, array, append, left_shift, right_shift, bitwise_or, bitwise_xor
import numpy.typing as npt
from warnings import catch_warnings, filterwarnings
from skein import threefish
import time

def del_trail_zeros(barr: bytearray) -> bytearray:
    end_id = len(barr) - 1
    while barr[end_id] == 0 and end_id >= 0:
        end_id = end_id - 1
    
    return barr[:end_id+1]

class threefish_512_cipher: 
#----------CONSTANTS----------
# BTW ctext is for cipher text (after encoding); ptext is for plain text (before encoding)
    k_bytes = 64 # number of bytes of keys (and blocks)
    n = k_bytes // 8 # number of words in one block
    rounds = 72 # number of rounds
    subkeys = ndarray((rounds // 4 + 1, n), uint64) # r/4 + 1 subkeys, each the same size as a block (n 64-bit words)

    # permutation array
    pi = [2, 1, 4, 7, 6, 5, 0, 3]
    
    # rotation matrix
    rot = array([[46, 36, 19, 37],
                 [33, 27, 14, 42],
                 [17, 49, 36, 39],
                 [44, 9,  54, 56],
                 [39, 30, 34, 24],
                 [13, 50, 10, 17],
                 [25, 29, 39, 43],
                 [8,  35, 56, 22]], uint64)
    
    c_240 = uint64(0x1BD11BDAA9FC1A22)

    def __init__(self, key: npt.NDArray[uint64], tweak: npt.NDArray[uint64]) -> None:
        self.gen_subkeys(key=key, tweak=tweak)

#----------UTILITY FUNCTIONS----------
    # left cyclic shift of an N-bit number a by 'shift' bits
    def lrotate(self, a: uint64, shift: uint64, N:uint64 = uint64(64)) -> uint64:
        shifted_bits = right_shift(a, (N - shift))
        a = left_shift(a, shift)
        a = bitwise_or(a, shifted_bits)
        return a
    
    # right cyclic shift of an N-bit number a by 'shift' bits
    def rrotate(self, a: uint64, shift: uint64, N:uint64 = uint64(64)) -> uint64:
        shifted_bits = left_shift(a, (N - shift))
        a = right_shift(a, shift)
        a = bitwise_or(a, shifted_bits)
        return a
    
#----------PRE-PROCESSING----------
# splits input data into 64-byte blocks and yields one at a time
    def split_blocks(self, data: bytearray) -> bytearray:
        n_bytes = len(data)
        n_blocks = n_bytes // self.k_bytes # number of whole blocks
        for i in range(0, n_blocks):  # yield whole blocks
            yield data[i*self.k_bytes : i*self.k_bytes + self.k_bytes]
            
        q = (self.k_bytes - n_bytes % self.k_bytes) % self.k_bytes # bytes needed for len(data) to be multiple of r
        if q == 0:
            pass
        else: # yield one not whole block
            last_block = data[-1 * (n_bytes % self.k_bytes):] # take last bytes
            last_block.extend([0 for _ in range(q)]) # add extra zeros

            yield last_block

# splits input 64-byte block into 64-bit words
    def split_words(self, data: bytearray) -> npt.NDArray[uint64]:
        return array([uint64(int.from_bytes(data[i*self.n : i*self.n + self.n], byteorder='little')) for i in range(0, self.n)])
    
#----------key schedule----------
    def gen_subkeys(self, key: npt.NDArray[uint64], tweak: npt.NDArray[uint64]):
        # add extra word to key
        k_n = self.c_240
        for word in key:
            k_n = bitwise_xor(k_n, word)
        key = append(key, k_n)

        # add extra word to tweak
        tweak = append(tweak, bitwise_xor(tweak[0], tweak[1]))

        for s in range(self.subkeys.shape[0]): # for every subkey
            for i in range(self.subkeys.shape[1]): # for every word in the subkey
                self.subkeys[s][i] = key[(s+i) % (self.n+1)]
            
            self.subkeys[s][self.n-3] = self.subkeys[s][self.n-3] + tweak[s % 3]
            self.subkeys[s][self.n-2] = self.subkeys[s][self.n-2] + tweak[(s+1) % 3]
            self.subkeys[s][self.n-1] = self.subkeys[s][self.n-1] + uint64(s)
    
#----------PROCESSING----------
#----------round----------
    # v is 512-bit state of algorithm
    # d is round's number
    def r(self, d: int, v: npt.NDArray[uint64]) -> npt.NDArray[uint64]:
        f = ndarray(self.n, uint64) # array of words for intermediate calculations

        if d % 4 == 0:
            e = v + self.subkeys[d // 4]
        else:
            e = v
        
        for j in range(self.n // 2):
            (f[2*j], f[2*j + 1]) = self.mix(e[2*j], e[2*j + 1], d, j)

        for i in range(self.n):
            v[i] = f[self.pi[i]]

        return v
    
    def de_r(self, d: int, v: npt.NDArray[uint64]) -> npt.NDArray[uint64]:
        e = ndarray(self.n, uint64) # array of words for intermediate calculations
        f = ndarray(self.n, uint64) # array of words for intermediate calculations

        for i in range(self.n):
            f[self.pi[i]] = v[i]

        for j in range(self.n // 2):
            (e[2*j], e[2*j + 1]) = self.de_mix(f[2*j], f[2*j + 1], d, j)

        if d % 4 == 0:
            v = e - self.subkeys[d // 4]
        else:
            v = e

        return v
    
    def mix(self, a:uint64, b:uint64, d: int, j:int) -> (uint64, uint64):
        a = a + b
        b = self.lrotate(b, self.rot[d%8][j])
        b = b ^ a
        return (a, b)
    
    def de_mix(self, a:uint64, b:uint64, d: int, j:int) -> (uint64, uint64):
        b = b ^ a
        b = self.rrotate(b, self.rot[d%8][j])
        a = a - b
        return (a, b)

#----------MAIN METHOD----------
    def encrypt(self, ptext: bytearray) -> bytearray:
        ctext = bytearray(len(ptext))
        block_id = 0
        for state in self.split_blocks(ptext):
            state = self.split_words(state)
            for i in range(0, self.rounds):
                state = self.r(i, state)

            state = state+self.subkeys[72//4] # key wasn't added after last round so we do it now
            ctext[block_id*self.k_bytes : block_id*self.k_bytes + self.k_bytes] = state.tobytes() 
            block_id = block_id + 1

        return ctext
    
    def decrypt(self, ctext: bytearray) -> bytearray:
        ptext = bytearray(len(ctext))
        block_id = 0
        for state in self.split_blocks(ctext):
            state = self.split_words(state)

            state = state-self.subkeys[72//4] # key wasn't subtracted after last round so we do it now
            for i in range(self.rounds-1, -1, -1): # undo our rounds in reverse order. Rounds are in interval (-1, rounds-1]
                state = self.de_r(i, state)
            
            ptext[block_id*self.k_bytes : block_id*self.k_bytes + self.k_bytes] = state.tobytes() 
            block_id = block_id + 1
        return del_trail_zeros(ptext)
    
with catch_warnings():
    filterwarnings('ignore', r'overflow encountered in scalar (add|subtract)') # numpy is used, it warns us about overflows which are integral part of MIX

    # my program
    file_in = open('small_data.txt', 'rb')
    file_encrypt = open('./out/encrypt_result.txt', 'wb')
    file_decrypt = open('./out/decrypt.txt', 'w')
    test_file_encrypt = open('./out/test-encrypt_result.txt', 'wb')
    test_file_decrypt = open('./out/test-decrypt.txt', 'w')
    bfile = bytearray(file_in.read())
    bkey = bytearray(b'\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00')
    key = array([uint64(1), uint64(1), uint64(1), uint64(1), uint64(1), uint64(1), uint64(1), uint64(1)])
    btweak = bytearray(b'\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00')
    tweak = array([uint64(1), uint64(1)])
    
    tf_cipher = threefish_512_cipher(key, tweak)

    start_time = time.time()

    encrypt_res = tf_cipher.encrypt(bfile)
    decrypt_res = tf_cipher.decrypt(encrypt_res)
    
    end_time = time.time()
    print("my time: " + str(end_time - start_time) + ' seconds')

    # print(hex(int.from_bytes(encrypt_res, byteorder='little')))
    file_encrypt.write(encrypt_res)
    file_decrypt.write(decrypt_res.decode())

    # lib program
    
    start_time = time.time()

    test_cipher = threefish(bkey, btweak)
    for block in tf_cipher.split_blocks(bfile):
        encrypt_res = test_cipher.encrypt_block(block)

        # print(hex(int.from_bytes(encrypt_res, byteorder='little')))
        test_file_encrypt.write(encrypt_res)

    test_file_encrypt.close()
    test_file_encrypt = open('./out/test-encrypt_result.txt', 'rb')
    test_bfile_encrypted = bytearray(test_file_encrypt.read())
    for block in tf_cipher.split_blocks(test_bfile_encrypted):
        decrypt_res = test_cipher.decrypt_block(block)
        test_file_decrypt.write(del_trail_zeros(decrypt_res).decode())

    end_time = time.time()
    print("lib time: " + str(end_time - start_time) + ' seconds')