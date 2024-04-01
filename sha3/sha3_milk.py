class Sha3_256_encoder:
    r = 1088
    c = 512
    d = 256
    l = 6
    b = r + c
    S = '0' * b
    rounds = 12 + 2 * l
    w = 2 ** l

    RC = [0 for i in range(24)]
    RC[0] = 0x0000000000000001
    RC[1] = 0x0000000000008082
    RC[2] = 0x800000000000808A
    RC[3] = 0x8000000080008000
    RC[4] = 0x000000000000808B
    RC[5] = 0x0000000080000001
    RC[6] = 0x8000000080008081
    RC[7] = 0x8000000000008009
    RC[8] = 0x000000000000008A
    RC[9] = 0x0000000000000088
    RC[10] = 0x0000000080008009
    RC[11] = 0x000000008000000A
    RC[12] = 0x000000008000808B
    RC[13] = 0x800000000000008B
    RC[14] = 0x8000000000008089
    RC[15] = 0x8000000000008003
    RC[16] = 0x8000000000008002
    RC[17] = 0x8000000000000080
    RC[18] = 0x000000000000800A
    RC[19] = 0x800000008000000A
    RC[20] = 0x8000000080008081
    RC[21] = 0x8000000000008080
    RC[22] = 0x0000000080000001
    RC[23] = 0x8000000080008008

    rotmatrix = [[0, 36, 3, 41, 18],
                 [1, 44, 10, 45, 2],
                 [62, 6, 43, 15, 61],
                 [28, 55, 25, 21, 56],
                 [27, 20, 39, 8, 14]]

    def rot(self, a, shift, N=64):
        shifted_bits = a >> (N - shift)
        a <<= shift
        a &= (1 << N) - 1
        a |= shifted_bits
        return a

    def pad(self, data: bytearray):
        m = len(data)
        q = (self.r // 8) - (m % (self.r // 8))
        if q == 1:
            data.append(0x86)
        if q >= 2:
            data.append(0x06)
            for _ in range(q - 2):
                data.append(0x00)
            data.append(0x80)
        return data

    def get_hash(self, data):
        padded_data = self.pad(data)
        S = self.absorb(padded_data)
        result = self.squeeze(S)
        return result

    def absorb(self, data):
        bytes_in_block = self.r // 8
        blocks = [data[i:i + bytes_in_block] for i in range(0, len(data), bytes_in_block)]
        state = []
        for x in range(5):
            state.append([0, 0, 0, 0, 0])
        for block in blocks:
            block2d = []
            for x in range(5):
                block2d.append([0, 0, 0, 0, 0])
            for i in range(self.c // 8):
                block.append(0x00)
            for y in range(5):
                for x in range(5):
                    block2d[x][y] = int.from_bytes(block[(5 * y + x) * 8: (5 * y + x) * 8 + 8], byteorder='little')
            for x in range(5):
                for y in range(5):
                    state[x][y] ^= block2d[x][y]
            state = self.f(state)
        return state

    def squeeze(self, S):
        Z = ''.join([S[i][0].to_bytes(8, 'little').hex() for i in range(4)])
        return Z

    def f(self, A):
        for rnd in range(self.rounds):
            A = self.iota(self.rho_pi_chi(self.theta(A)), rnd)
        return A

    def theta(self, A):
        C = [0, 0, 0, 0, 0]
        D = [0, 0, 0, 0, 0]
        for x in range(5):
            C[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4]
        for x in range(5):
            D[x] = C[(x - 1) % 5] ^ self.rot(C[(x + 1) % 5], 1)
        for x in range(5):
            for y in range(5):
                A[x][y] ^= D[x]
        return A
    def rho_pi_chi(self, A):
        B = []
        for i in range(5):
            B.append([0, 0, 0, 0, 0])
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = self.rot(A[x][y], self.rotmatrix[x][y])
        for x in range(5):
            for y in range(5):
                A[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y])
        return A

    def iota(self, A, rnd):
        A[0][0] ^= self.RC[rnd]
        return A


encoder = Sha3_256_encoder()
file = open('big data.txt', 'rb')
bfile = bytearray(file.read())
print(encoder.get_hash(bfile))