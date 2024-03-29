import random

class SHA256:
    def __init__(self):
        self.__hash_values = ['01101010000010011110011001100111', '10111011011001111010111010000101',
                            '00111100011011101111001101110010', '10100101010011111111010100111010',
                            '01010001000011100101001001111111', '10011011000001010110100010001100',
                            '00011111100000111101100110101011', '01011011111000001100110100011001']
        self.__k_values = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]
        self.__pepper = '1001100010000011100000000110111111111101101001111010010111011100011011001001110111111111000101011010100000100010111111101111110110000101000010111101001010010011001001000001011110010000111010011111011011100010000001011110001011010101111100001111011010000110'
        
    def alpha_to_binary(self, entry):
        return ''.join(bin(ord(x))[2:].zfill(8) for x in entry)

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

    def process(self, entry, outputMode='bin', salt=False, pepper=False):
        binary_entry = self.alpha_to_binary(entry)
        if pepper:
            binary_entry += self.__pepper
        if salt:
            salt = ''
            for _ in range(256):
                salt += str(random.randint(0,1))
            binary_entry += salt
        padded_binary_entry, n_blocks = self.pre_processing_padding(binary_entry)
        blocks = [padded_binary_entry[i * 512:(i + 1) * 512] for i in range(n_blocks)]
        split_blocks = []
        for blk in blocks:
            split_blocks.append([])
            for i in range(16):
                split_blocks[-1].append(blk[i * 32:(i + 1) * 32])

        for blk in split_blocks:
            w_values = self.get_w_values(blk)
            a, b, c, d, e, f, g, h = self.__hash_values

            for i in range(64):
                T1 = bin(int(h, 2) + int(self.SIGMA_one(e), 2) + int(self.Ch(e, f, g), 2) + self.__k_values[i] + int(
                    w_values[i], 2))[2:]
                T2 = bin(int(self.SIGMA_zero(a), 2) + int(self.Maj(a, b, c), 2))[2:]
                if len(T1) < 32:
                    T1 = T1.zfill(32)
                elif len(T1) > 32:
                    T1 = T1[-32:]
                if len(T2) < 32:
                    T2 = T2.zfill(32)
                elif len(T2) > 32:
                    T2 = T2[-32:]
                h = g
                g = f
                f = e
                e = bin(int(d, 2) + int(T1, 2))[2:]
                if len(e) > 32:
                    e = e[-32:]
                elif len(e) < 32:
                    e = e.zfill(32)
                d = c
                c = b
                b = a
                a = bin(int(T1, 2) + int(T2, 2))[2:]
                if len(a) > 32:
                    a = a[-32:]
                elif len(a) < 32:
                    a = a.zfill(32)

            for i, letter in enumerate([a, b, c, d, e, f, g, h]):
                temp_letter = bin(int(self.__hash_values[i], 2) + int(letter, 2))[2:]
                if len(temp_letter) > 32:
                    temp_letter = temp_letter[-32:]
                elif len(temp_letter) < 32:
                    temp_letter = temp_letter.zfill(32)
                self.__hash_values[i] = temp_letter
        output = ''

        for h in self.__hash_values:
            output += h
        if outputMode == 'hex':
            if salt:
                return hex(int(output, 2))[2:], salt
            return hex(int(output, 2))[2:]
        else:
            if salt:
                return output, salt
            return output
sha=SHA256()
_hash, salt = sha.process('', salt=True, pepper=True, outputMode='hex')
print(_hash)
