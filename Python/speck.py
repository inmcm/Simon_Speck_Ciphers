from __future__ import print_function


class SpeckCipher:
    # valid cipher configurations stored:
    # block_size:{key_size:number_rounds}
    __valid_setups = {32: {64: 22},
                      48: {72: 22, 96: 23},
                      64: {96: 26, 128: 27},
                      96: {96: 28, 144: 29},
                      128: {128: 32, 192: 33, 256: 34}}

    __valid_modes = ['ECB', 'CTR', 'CBC', 'PCBC', 'CFB', 'OFB']

    def encrypt_round(self, x, y, k):
        """Complete One Round of Fiestal Operation"""
        rs_x = ((x << (self.word_size - self.alpha_shift)) + (x >> self.alpha_shift)) & self.mod_mask

        add_sxy = (rs_x + y) & self.mod_mask

        new_x = k ^ add_sxy

        ls_y = ((y >> (self.word_size - self.beta_shift)) + (y << self.beta_shift)) & self.mod_mask

        new_y = new_x ^ ls_y

        return new_x, new_y

    def decrypt_round(self, x, y, k):
        """Complete One Round of Inverse Fiestal Operation"""

        xor_xy = x ^ y

        new_y = ((xor_xy << (self.word_size - self.beta_shift)) + (xor_xy >> self.beta_shift)) & self.mod_mask

        xor_xk = x ^ k

        if xor_xk >= new_y:
            msub = xor_xk - new_y
        else:
            msub = ((xor_xk - new_y) % self.mod_mask) + 1

        new_x = ((msub >> (self.word_size - self.alpha_shift)) + (msub << self.alpha_shift)) & self.mod_mask

        return new_x, new_y

    def __init__(self, key, key_size=128, block_size=128, mode='ECB', init=0, counter=0):

        # Setup block/word size
        try:
            self.possible_setups = self.__valid_setups[block_size]
            self.word_size = block_size >> 1
        except KeyError:
            print('Invalid block size!')
            print('Please use one of the following block sizes:', [x for x in self.__valid_setups.keys()])
            raise

        # Setup Number of Rounds and Key Size
        try:
            self.rounds = self.possible_setups[key_size]
            self.key_size = key_size
        except KeyError:
            print('Invalid key size for selected block size!!')
            print('Please use one of the following key sizes:', [x for x in self.possible_setups.keys()])
            raise

        # Create Properly Sized bit mask for truncating addition and left shift outputs
        self.mod_mask = (2 ** self.word_size) - 1

        # Setup Circular Shift Parameters
        if block_size == 32:
            self.beta_shift = 2
            self.alpha_shift = 7
        else:
            self.beta_shift = 3
            self.alpha_shift = 8

        # Parse the given iv and truncate it to the block length
        try:
            self.iv = init & ((2 ** block_size) - 1)
        except (ValueError, TypeError):
            print('Invalid IV Value!')
            print('Please Provide IV as int')
            raise

        # Parse the given Counter and truncate it to the block length
        try:
            self.counter = counter & ((2 ** block_size) - 1)
        except (ValueError, TypeError):
            print('Invalid Counter Value!')
            print('Please Provide Counter as int')
            raise

        # Check Cipher Mode
        try:
            position = self.__valid_modes.index(mode)
            self.mode = self.__valid_modes[position]
        except ValueError:
            print('Invalid cipher mode!')
            print('Please use one of the following block cipher modes:', self.__valid_modes)
            raise

        # Parse the given key and truncate it to the key length
        try:
            self.key = key & ((2 ** self.key_size) - 1)
        except (ValueError, TypeError):
            print('Invalid Key Value!')
            print('Please Provide Key as int')
            raise

        # Pre-compile key schedule
        self.key_schedule = [self.key & self.mod_mask]
        l_schedule = [(self.key >> (x * self.word_size)) & self.mod_mask for x in
                      range(1, self.key_size // self.word_size)]

        for x in range(self.rounds - 1):
            new_l_k = self.encrypt_round(l_schedule[x], self.key_schedule[x], x)
            l_schedule.append(new_l_k[0])
            self.key_schedule.append(new_l_k[1])

    def encrypt(self, plaintext):
        try:
            b = plaintext >> self.word_size
            a = plaintext & self.mod_mask
        except TypeError:
            print('Invalid plaintext!')
            print('Please provide plaintext at int')
            raise

        if self.mode == 'ECB':
            for x in range(self.rounds):
                b, a = self.encrypt_round(b, a, self.key_schedule[x])

        elif self.mode == 'CTR':
            d = self.iv & self.mod_mask
            c = self.counter & self.mod_mask
            for x in range(self.rounds):
                d, c = self.encrypt_round(d, c, self.key_schedule[x])
            b ^= d
            a ^= c
            self.counter += 1

        elif self.mode == 'CBC':
            d = self.iv >> self.word_size
            c = self.iv & self.mod_mask
            b ^= d
            a ^= c
            for x in range(self.rounds):
                b, a = self.encrypt_round(b, a, self.key_schedule[x])

            self.iv = (b << self.word_size) + a

        elif self.mode == 'PCBC':
            d = self.iv >> self.word_size
            c = self.iv & self.mod_mask
            f, e = b, a
            b ^= d
            a ^= c
            for x in range(self.rounds):
                b, a = self.encrypt_round(b, a, self.key_schedule[x])

            self.iv = ((b ^ f) << self.word_size) + (a ^ e)

        elif self.mode == 'CFB':
            d = self.iv >> self.word_size
            c = self.iv & self.mod_mask
            for x in range(self.rounds):
                d, c = self.encrypt_round(d, c, self.key_schedule[x])
            b ^= d
            a ^= c
            self.iv = (b << self.word_size) + a

        elif self.mode == 'OFB':
            d = self.iv >> self.word_size
            c = self.iv & self.mod_mask
            for x in range(self.rounds):
                d, c = self.encrypt_round(d, c, self.key_schedule[x])

            self.iv = (d << self.word_size) + c

            b ^= d
            a ^= c

        ciphertext = (b << self.word_size) + a

        return ciphertext

    def decrypt(self, ciphertext):
        try:
            b = ciphertext >> self.word_size
            a = ciphertext & self.mod_mask
        except TypeError:
            print('Invalid plaintext!')
            print('Please provide plaintext at int')
            raise

        if self.mode == 'ECB':
            for x in range(self.rounds):
                b, a = self.decrypt_round(b, a, self.key_schedule[self.rounds - (x + 1)])

        elif self.mode == 'CTR':
            pass

        elif self.mode == 'CBC':
            pass

        elif self.mode == 'PCBC':
            pass

        elif self.mode == 'CFB':
            pass

        elif self.mode == 'OFB':
            pass

        plaintext = (b << self.word_size) + a

        return plaintext


if __name__ == "__main__":
    # y = SpeckCipher('0x11223344556677889900AABBCCDDEEFF')
    # y = SpeckCipher('0X11223344556677889900AABBCCDDEEFF')
    # y = SpeckCipher('ThekeyisPASSWORD')
    # y = SpeckCipher(1)
    # y = SpeckCipher(121423459234858293745823758932759823759823758932759263757623785623785)
    # u = bytearray(b'ThekeyisPASSWORD')
    # u = bytearray([12,34,56,78,89,0xAA,00,0x00,34])
    # y = SpeckCipher(u)
    # y = SpeckCipher(123)
    r = SpeckCipher(6.22, mode='ERT')