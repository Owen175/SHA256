class SHA256:
    def __init__(self, entry):
        self.hash_values = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                            0x5be0cd19]
        self.k_values = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

        self.hashed = self.process(entry)

    def alpha_to_binary(self, entry):
        return ''.join(format(ord(x), 'b') for x in entry)

    def pre_processing_padding(self, binary_entry):
        original_length = len(binary_entry)
        binary_entry += '1'
        desired_length = ((len(binary_entry) + 64) // 512 + 1) * 512
        # Rounds to next 512 with space for 64 bits for size of initial message
        num_zeroes = desired_length - len(binary_entry) - 64
        for _ in range(num_zeroes):
            binary_entry += '0'
        bin_original_length = bin(original_length)[2:].zfill(64)
        binary_entry += bin_original_length
        return binary_entry, int(desired_length / 512)

    def get_w_values(self, blk):
        w_values = blk[:]
        for i in range(48):
            t1 = '0b' + self.sigma_one(w_values[i + 14])
            t2 = '0b' + w_values[i + 9]
            t3 = '0b' + self.sigma_zero(w_values[i + 1])
            t4 = '0b' + w_values[i]

            binary_value = bin(int(t1, 2) + int(t2, 2) + int(t3, 2) + int(t4, 2))[2:]
            if len(binary_value) < 32:
                binary_value = binary_value.zfill(32)
            elif len(binary_value) > 32:
                binary_value = binary_value[-32:]
            w_values.append(binary_value)
        return w_values


    def sigma_zero(self, x):
        right_seven = x[-7:] + x[:-7]
        right_eighteen = x[-18:] + x[:-18]
        bitwise_shift_3 = '000' + x[:-3]
        output = ''
        for s, e, t in zip(right_seven, right_eighteen, bitwise_shift_3):
            if (int(s) + int(e) + int(t)) % 2 == 1:
                output += '1'
            else:
                output += '0'
        return output

    def sigma_one(self, x):
        right_seventeen = x[-17:] + x[:-17]
        right_nineteen = x[-19:] + x[:-19]
        bitwise_shift_10 = '0000000000' + x[:-10]
        output = ''
        for s, n, t in zip(right_seventeen, right_nineteen, bitwise_shift_10):
            if (int(s) + int(n) + int(t)) % 2 == 1:
                output += '1'
            else:
                output += '0'
        return output

    def SIGMA_zero(self, x):
        right_two = x[-2:] + x[:-2]
        right_thirteen = x[-13:] + x[:-13]
        right_twenty_two = x[-22:] + x[:-22]
        output = ''
        for t, th, tt in zip(right_two, right_thirteen, right_twenty_two):
            if (int(t) + int(th) + int(tt)) % 2 == 1:
                output += '1'
            else:
                output += '0'
        return output

    def SIGMA_one(self, x):
        right_six = x[-6:] + x[:-6]
        right_eleven = x[-11:] + x[:-11]
        right_twenty_five = x[-25:] + x[:-25]
        output = ''
        for s, e, t in zip(right_six, right_eleven, right_twenty_five):
            if (int(s) + int(e) + int(t)) % 2 == 1:
                output += '1'
            else:
                output += '0'
        return output

    def Ch(self, e, f, g):
        output = ''
        for i, bit in enumerate(e):
            if bit == '1':
                output += f[i]
            elif bit == '0':
                output += g[i]
            else:
                print('Error')
        return output

    def Maj(self, a, b, c):
        # Gets the majority for each bit
        output = ''
        for a_bit, b_bit, c_bit in zip(a, b, c):
            if int(a_bit) + int(b_bit) + int(c_bit) >= 2:
                output += '1'
            else:
                output += '0'
        return output

    def process(self, entry):
        binary_entry = self.alpha_to_binary(entry)
        padded_binary_entry, n_blocks = self.pre_processing_padding(binary_entry)
        blocks = [padded_binary_entry[i * 512:(i + 1) * 512] for i in range(n_blocks)]
        split_blocks = []
        for blk in blocks:
            split_blocks.append([])
            for i in range(16):
                split_blocks[-1].append(blk[i * 32:(i + 1) * 32])

        for blk in split_blocks:
            w_values = self.get_w_values(blk)
            a, b, c, d, e, f, g, h = self.hash_values
            a = bin(a)[2:].zfill(32)
            b = bin(b)[2:].zfill(32)
            c = bin(c)[2:].zfill(32)
            d = bin(d)[2:].zfill(32)
            e = bin(e)[2:].zfill(32)
            f = bin(f)[2:].zfill(32)
            g = bin(g)[2:].zfill(32)
            h = bin(h)[2:].zfill(32)

            for i in range(64):
                T1 = bin(int(h, 2) + int(self.SIGMA_one(e), 2) + int(self.Ch(e, f, g), 2) + self.k_values[i] + int(w_values[i], 2))[2:]
                T2 = bin(int(self.SIGMA_zero(a), 2) + int(self.Maj(a, b, c), 2))[2:]
                if len(T1) < 32:
                    T1 = T1.zfill(32)
                elif len(T1) > 32:
                    T1 = T1[:32]
                if len(T2) < 32:
                    T2 = T2.zfill(32)
                elif len(T2) > 32:
                    T2 = T2[:32]
                h = g
                g = f
                f = e
                e = d + T1
                d = c
                c = b
                b = a
                a = T1 + T2


SHA256('RedBlockBlue')