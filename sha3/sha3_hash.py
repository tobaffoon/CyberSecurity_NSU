class Sha3_512_encoder:   
#----------CONSTANTS----------
    l = 6 
    b = 25 * 2**l           # state's length
    rounds = 12 + 2 * l     # 24 for sha-3
    r = 576                 # block size
    c = 1024                # capacity
    o = 512                 # output length

    # Round constants
    RC = [   
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
        0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008
    ]

    # Ro offsets
    ROT = [
        [0, 36, 3, 41, 18],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14]
    ]

#----------UTILITY FUNCTIONS----------
    # left cyclic shift of an N-bit number a by 'shift' bits. Bits on the right are 'shift' bits from overflowing the int
    def lshiftc(self, a, shift, N=64):
        shifted_bits = a >> (N - shift)
        a <<= shift
        a &= (1 << N) - 1   # clear all the shifted numbers after 0'th bit
        a |= shifted_bits
        return a
    
    def get_hash(self, data: bytearray) -> int:
        padded_data = self.pad(data)
        state = self.absorb(padded_data)
        return self.squeeze(state)
    
    def get_hash_byte(self, data: bytearray) -> bytes:
        int_hash = self.get_hash(data)
        
        int_size = (int_hash.bit_length() // 8 + 1)
        return int_hash.to_bytes(length=int_size)

#----------PRE-PROCESSING----------
    # Балабанов сказал, что append слишком тяжелая штука, так как вызывает realloc. Он рекомендовал использовать буффер нужной длины и в него вписывать data. Но у меня принял и так
    # Add padding (01 10*1) to the input
    def pad(self, data: bytearray) -> bytearray:
        byte_n = len(data)           # number of input bytes
        block_bytes = self.r // 8    # bytes in one block
        q = block_bytes - byte_n % block_bytes   # bytes needed for len(data) to be multiple of r

    # Про паддинг можно в спецификации почитать, там даже примеры есть в конце
        # if one is needed we add 0b01100001
        if q == 1:
            data.append(0x86)
        # if we need more, we add 0b01100000 at the start, 0b00000000 in between, 0b00000001 at the end
        if q >= 2:
            data.append(0x06)
            data.extend([0x00] * (q-2))
            data.append(0x80)
        return data

#----------ABSORBING----------
    def absorb(self, data: bytearray) -> bytearray:   
        state = [   [0, 0, 0, 0, 0],        # 2d-representation of state
                    [0, 0, 0, 0, 0],
                    [0, 0, 0, 0, 0],
                    [0, 0, 0, 0, 0],
                    [0, 0, 0, 0, 0]]

        bytes_in_block = self.r // 8
        blocks = [data[i:i + bytes_in_block] for i in range(0, len(data), bytes_in_block)] # разделение data на равные блоки
        for block in blocks:
            block2d = [ [0, 0, 0, 0, 0],             # 2d-array representation of block for xor with state
                        [0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0]]   

            # convert our bytes to int to perform bit operations faster
            for y in range(5):
                for x in range(5):
                    block2d[x][y] = int.from_bytes(block[(5 * y + x) * 8: (5 * y + x) * 8 + 8], byteorder='little') # здесь стандартное получение адреса в одномерном массиве из 2х координат 

            for x in range(5):
                for y in range(5):
                    state[x][y] ^= block2d[x][y]

            state = self.f(state)
        return state
    
    # Далее - просто повторение алгоритма из спецификации
    def f(self, A: list[list[int]]) -> list[list[int]]:
        for rnd in range(self.rounds):
            A = self.iota(self.rho_pi_chi(self.theta(A)), rnd)
        return A

    def theta(self, A: list[list[int]]) -> list[list[int]]:
        # θ
        C = [0, 0, 0, 0, 0]
        D = [0, 0, 0, 0, 0]
        for x in range(5):
            C[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4]
        for x in range(5):
            D[x] = C[(x - 1) % 5] ^ self.lshiftc(C[(x + 1) % 5], 1)
        for x in range(5):
            for y in range(5):
                A[x][y] ^= D[x]
        return A
    
    def rho_pi_chi(self, A: list[list[int]]) -> list[list[int]]:
        B = [[0, 0, 0, 0, 0],
             [0, 0, 0, 0, 0],
             [0, 0, 0, 0, 0],
             [0, 0, 0, 0, 0],
             [0, 0, 0, 0, 0]]                      # temporal state acquired from step rho
        
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = self.lshiftc(A[x][y], self.ROT[x][y]) # pi (permutations) and ro (rotations)
        for x in range(5):
            for y in range(5):
                A[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y])  # chi
        return A
    
    def iota(self, A: list[list[int]], rnd: int) -> list[list[int]]:
        A[0][0] ^= self.RC[rnd]
        return A

#----------SQUEEZING----------
    def squeeze(self, state: list[list[int]]) -> int:
        str_output = ''
        for i in range(5):
            for j in range(5):
                str_output += state[j][i].to_bytes(8, 'little').hex()
                # Останавливаемся, когда длина выходной строки (больше или) равна требуемой
                if len(str_output) >= self.o // 4:  # each char in str is heximal, thus represents 4 bits
                    return str_output

# encoder = Sha3_512_encoder()
# file = open('big data.txt', 'rb')
# bfile = bytearray(file.read())
# print(encoder.get_hash(bfile))