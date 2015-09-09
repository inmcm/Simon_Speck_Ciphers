import pytest
from random import randint
from speck import SpeckCipher
from simon import SimonCipher


# Official Test Vectors
class TestOfficialTestVectors:
    """
    Official Test Vector From the Original Paper
    "The SIMON and SPECK Families of Lightweight Block Ciphers"
    """
    # Speck Test Vectors
    def test_speck32_64(self):
        key = 0x1918111009080100
        plaintxt = 0x6574694c
        ciphertxt = 0xa86842f2
        block_size = 32
        key_size = 64
        c = SpeckCipher(key, key_size, block_size, 'ECB')
        assert c.encrypt(plaintxt) == ciphertxt
        assert c.decrypt(ciphertxt) == plaintxt

    def test_speck48_72(self):
        key = 0x1211100a0908020100
        plaintxt = 0x20796c6c6172
        ciphertxt = 0xc049a5385adc
        block_size = 48
        key_size = 72
        c = SpeckCipher(key, key_size, block_size, 'ECB')
        assert c.encrypt(plaintxt) == ciphertxt
        assert c.decrypt(ciphertxt) == plaintxt

    def test_speck48_96(self):
        key = 0x1a19181211100a0908020100
        plaintxt = 0x6d2073696874
        ciphertxt = 0x735e10b6445d
        block_size = 48
        key_size = 96
        c = SpeckCipher(key, key_size, block_size, 'ECB')
        assert c.encrypt(plaintxt) == ciphertxt
        assert c.decrypt(ciphertxt) == plaintxt

    def test_speck64_96(self):
        key = 0x131211100b0a090803020100
        plaintxt = 0x74614620736e6165
        ciphertxt = 0x9f7952ec4175946c
        block_size = 64
        key_size = 96
        c = SpeckCipher(key, key_size, block_size, 'ECB')
        assert c.encrypt(plaintxt) == ciphertxt
        assert c.decrypt(ciphertxt) == plaintxt

    def test_speck64_128(self):
        key = 0x1b1a1918131211100b0a090803020100
        plaintxt = 0x3b7265747475432d
        ciphertxt = 0x8c6fa548454e028b
        block_size = 64
        key_size = 128
        c = SpeckCipher(key, key_size, block_size, 'ECB')
        assert c.encrypt(plaintxt) == ciphertxt
        assert c.decrypt(ciphertxt) == plaintxt

    def test_speck96_96(self):
        key = 0x0d0c0b0a0908050403020100
        plaintxt = 0x65776f68202c656761737520
        ciphertxt = 0x9e4d09ab717862bdde8f79aa
        block_size = 96
        key_size = 96
        c = SpeckCipher(key, key_size, block_size, 'ECB')
        assert c.encrypt(plaintxt) == ciphertxt
        assert c.decrypt(ciphertxt) == plaintxt

    def test_speck96_144(self):
        key = 0x1514131211100d0c0b0a0908050403020100
        plaintxt = 0x656d6974206e69202c726576
        ciphertxt = 0x2bf31072228a7ae440252ee6
        block_size = 96
        key_size = 144
        c = SpeckCipher(key, key_size, block_size, 'ECB')
        assert c.encrypt(plaintxt) == ciphertxt
        assert c.decrypt(ciphertxt) == plaintxt

    def test_speck128_128(self):
        key = 0x0f0e0d0c0b0a09080706050403020100
        plaintxt = 0x6c617669757165207469206564616d20
        ciphertxt = 0xa65d9851797832657860fedf5c570d18
        block_size = 128
        key_size = 128
        c = SpeckCipher(key, key_size, block_size, 'ECB')
        assert c.encrypt(plaintxt) == ciphertxt
        assert c.decrypt(ciphertxt) == plaintxt

    def test_speck128_192(self):
        key = 0x17161514131211100f0e0d0c0b0a09080706050403020100
        plaintxt = 0x726148206665696843206f7420746e65
        ciphertxt = 0x1be4cf3a13135566f9bc185de03c1886
        block_size = 128
        key_size = 192
        c = SpeckCipher(key, key_size, block_size, 'ECB')
        assert c.encrypt(plaintxt) == ciphertxt
        assert c.decrypt(ciphertxt) == plaintxt

    def test_speck128_256(self):
        key = 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100
        plaintxt = 0x65736f6874206e49202e72656e6f6f70
        ciphertxt = 0x4109010405c0f53e4eeeb48d9c188f43
        block_size = 128
        key_size = 256
        c = SpeckCipher(key, key_size, block_size, 'ECB')
        assert c.encrypt(plaintxt) == ciphertxt
        assert c.decrypt(ciphertxt) == plaintxt

    # Simon Test Vectors
    def test_simon32_64(self):
        key = 0x1918111009080100
        plaintxt = 0x65656877
        ciphertxt = 0xc69be9bb
        block_size = 32
        key_size = 64
        c = SimonCipher(key, key_size, block_size, 'ECB')
        assert c.encrypt(plaintxt) == ciphertxt
        assert c.decrypt(ciphertxt) == plaintxt

    def test_simon48_72(self):
        key = 0x1211100a0908020100
        plaintxt = 0x6120676e696c
        ciphertxt = 0xdae5ac292cac
        block_size = 48
        key_size = 72
        c = SimonCipher(key, key_size, block_size, 'ECB')
        assert c.encrypt(plaintxt) == ciphertxt
        assert c.decrypt(ciphertxt) == plaintxt

    def test_simon48_96(self):
        key = 0x1a19181211100a0908020100
        plaintxt = 0x72696320646e
        ciphertxt = 0x6e06a5acf156
        block_size = 48
        key_size = 96
        c = SimonCipher(key, key_size, block_size, 'ECB')
        assert c.encrypt(plaintxt) == ciphertxt
        assert c.decrypt(ciphertxt) == plaintxt

    def test_simon64_96(self):
        key = 0x131211100b0a090803020100
        plaintxt = 0x6f7220676e696c63
        ciphertxt = 0x5ca2e27f111a8fc8
        block_size = 64
        key_size = 96
        c = SimonCipher(key, key_size, block_size, 'ECB')
        assert c.encrypt(plaintxt) == ciphertxt
        assert c.decrypt(ciphertxt) == plaintxt

    def test_simon64_128(self):
        key = 0x1b1a1918131211100b0a090803020100
        plaintxt = 0x656b696c20646e75
        ciphertxt = 0x44c8fc20b9dfa07a
        block_size = 64
        key_size = 128
        c = SimonCipher(key, key_size, block_size, 'ECB')
        assert c.encrypt(plaintxt) == ciphertxt
        assert c.decrypt(ciphertxt) == plaintxt

    def test_simon96_96(self):
        key = 0x0d0c0b0a0908050403020100
        plaintxt = 0x2072616c6c69702065687420
        ciphertxt = 0x602807a462b469063d8ff082
        block_size = 96
        key_size = 96
        c = SimonCipher(key, key_size, block_size, 'ECB')
        assert c.encrypt(plaintxt) == ciphertxt
        assert c.decrypt(ciphertxt) == plaintxt

    def test_simon96_144(self):
        key = 0x1514131211100d0c0b0a0908050403020100
        plaintxt = 0x74616874207473756420666f
        ciphertxt = 0xecad1c6c451e3f59c5db1ae9
        block_size = 96
        key_size = 144
        c = SimonCipher(key, key_size, block_size, 'ECB')
        assert c.encrypt(plaintxt) == ciphertxt
        assert c.decrypt(ciphertxt) == plaintxt

    def test_simon128_128(self):
        key = 0x0f0e0d0c0b0a09080706050403020100
        plaintxt = 0x63736564207372656c6c657661727420
        ciphertxt = 0x49681b1e1e54fe3f65aa832af84e0bbc
        block_size = 128
        key_size = 128
        c = SimonCipher(key, key_size, block_size, 'ECB')
        assert c.encrypt(plaintxt) == ciphertxt
        assert c.decrypt(ciphertxt) == plaintxt

    def test_simon128_192(self):
        key = 0x17161514131211100f0e0d0c0b0a09080706050403020100
        plaintxt = 0x206572656874206e6568772065626972
        ciphertxt = 0xc4ac61effcdc0d4f6c9c8d6e2597b85b
        block_size = 128
        key_size = 192
        c = SimonCipher(key, key_size, block_size, 'ECB')
        assert c.encrypt(plaintxt) == ciphertxt
        assert c.decrypt(ciphertxt) == plaintxt

    def test_simon128_256(self):
        key = 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100
        plaintxt = 0x74206e69206d6f6f6d69732061207369
        ciphertxt = 0x8d2b5579afc8a3a03bf72a87efe7b868
        block_size = 128
        key_size = 256
        c = SimonCipher(key, key_size, block_size, 'ECB')
        assert c.encrypt(plaintxt) == ciphertxt
        assert c.decrypt(ciphertxt) == plaintxt


class TestRandomTestVectors:
    """
    Unofficial Test Vectors Randomly Generated
    Key/Plaintext are printed out with each test in case of failure
    """
    test_cnt = 500

    def test_speck32_64(self):
        block_size = 32
        key_size = 64
        for x in range(self.test_cnt):
            key = randint(0, (2**key_size) - 1)
            plaintxt = randint(0, (2**block_size) - 1)
            print(x, hex(key), hex(plaintxt))
            c = SpeckCipher(key, key_size, block_size, 'ECB')
            assert c.decrypt(c.encrypt(plaintxt)) == plaintxt

    def test_speck48_72(self):
        block_size = 48
        key_size = 72
        for x in range(self.test_cnt):
            key = randint(0, (2**key_size) - 1)
            plaintxt = randint(0, (2**block_size) - 1)
            print(x, hex(key), hex(plaintxt))
            c = SpeckCipher(key, key_size, block_size, 'ECB')
            assert c.decrypt(c.encrypt(plaintxt)) == plaintxt

    def test_speck48_96(self):
        block_size = 48
        key_size = 96
        for x in range(self.test_cnt):
            key = randint(0, (2**key_size) - 1)
            plaintxt = randint(0, (2**block_size) - 1)
            print(x, hex(key), hex(plaintxt))
            c = SpeckCipher(key, key_size, block_size, 'ECB')
            assert c.decrypt(c.encrypt(plaintxt)) == plaintxt

    def test_speck64_96(self):
        block_size = 64
        key_size = 96
        for x in range(self.test_cnt):
            key = randint(0, (2**key_size) - 1)
            plaintxt = randint(0, (2**block_size) - 1)
            print(x, hex(key), hex(plaintxt))
            c = SpeckCipher(key, key_size, block_size, 'ECB')
            assert c.decrypt(c.encrypt(plaintxt)) == plaintxt

    def test_speck64_128(self):
        block_size = 64
        key_size = 128
        for x in range(self.test_cnt):
            key = randint(0, (2**key_size) - 1)
            plaintxt = randint(0, (2**block_size) - 1)
            print(x, hex(key), hex(plaintxt))
            c = SpeckCipher(key, key_size, block_size, 'ECB')
            assert c.decrypt(c.encrypt(plaintxt)) == plaintxt

    def test_speck96_96(self):
        block_size = 96
        key_size = 96
        for x in range(self.test_cnt):
            key = randint(0, (2**key_size) - 1)
            plaintxt = randint(0, (2**block_size) - 1)
            print(x, hex(key), hex(plaintxt))
            c = SpeckCipher(key, key_size, block_size, 'ECB')
            assert c.decrypt(c.encrypt(plaintxt)) == plaintxt

    def test_speck96_144(self):
        block_size = 96
        key_size = 144
        for x in range(self.test_cnt):
            key = randint(0, (2**key_size) - 1)
            plaintxt = randint(0, (2**block_size) - 1)
            print(x, hex(key), hex(plaintxt))
            c = SpeckCipher(key, key_size, block_size, 'ECB')
            assert c.decrypt(c.encrypt(plaintxt)) == plaintxt

    def test_speck128_128(self):
        block_size = 128
        key_size = 128
        for x in range(self.test_cnt):
            key = randint(0, (2**key_size) - 1)
            plaintxt = randint(0, (2**block_size) - 1)
            print(x, hex(key), hex(plaintxt))
            c = SpeckCipher(key, key_size, block_size, 'ECB')
            assert c.decrypt(c.encrypt(plaintxt)) == plaintxt

    def test_speck128_192(self):
        block_size = 128
        key_size = 192
        for x in range(self.test_cnt):
            key = randint(0, (2**key_size) - 1)
            plaintxt = randint(0, (2**block_size) - 1)
            print(x, hex(key), hex(plaintxt))
            c = SpeckCipher(key, key_size, block_size, 'ECB')
            assert c.decrypt(c.encrypt(plaintxt)) == plaintxt

    def test_speck128_256(self):
        block_size = 128
        key_size = 256
        for x in range(self.test_cnt):
            key = randint(0, (2**key_size) - 1)
            plaintxt = randint(0, (2**block_size) - 1)
            print(x, hex(key), hex(plaintxt))
            c = SpeckCipher(key, key_size, block_size, 'ECB')
            assert c.decrypt(c.encrypt(plaintxt)) == plaintxt


class TestCipherInitialization:
    not_ints = [6.22, 'hello', bytearray(b'stuffandbytes'), bytearray([12, 34, 0xAA, 00, 0x00, 34]), '0x1234567']

    def test_bad_keys_speck(self):
        for bad_key in self.not_ints:
            with pytest.raises(TypeError):
                SpeckCipher(bad_key)

    def test_bad_keys_simon(self):
        for bad_key in self.not_ints:
            with pytest.raises(TypeError):
                SimonCipher(bad_key)

    def test_bad_counters_speck(self):
        for bad_counter in self.not_ints:
            with pytest.raises(TypeError):
                SpeckCipher(0, counter=bad_counter)

    def test_bad_counters_simon(self):
        for bad_counters in self.not_ints:
            with pytest.raises(TypeError):
                SimonCipher(0, counter=bad_counters)

    def test_bad_ivs_speck(self):
        for bad_iv in self.not_ints:
            with pytest.raises(TypeError):
                SpeckCipher(0, init=bad_iv)

    def test_bad_ivs_simon(self):
        for bad_iv in self.not_ints:
            with pytest.raises(TypeError):
                SimonCipher(0, init=bad_iv)

    not_block_modes = [7.1231, 'ERT', 11]

    def test_bad_modes_speck(self):
        for bad_mode in self.not_block_modes:
            with pytest.raises(ValueError):
                SpeckCipher(0, mode=bad_mode)

    def test_bad_modes_simon(self):
        for bad_mode in self.not_block_modes:
            with pytest.raises(ValueError):
                SimonCipher(0, mode=bad_mode)

    not_block_sizes = [10, 'steve', 11.8]

    def test_bad_blocksizes_speck(self):
        for bad_bsize in self.not_block_sizes:
            with pytest.raises(KeyError):
                SpeckCipher(0, block_size=bad_bsize)

    def test_bad_blocksizes_simon(self):
        for bad_bsize in self.not_block_sizes:
            with pytest.raises(KeyError):
                SimonCipher(0, block_size=bad_bsize)

    not_key_sizes = [100000, 'eve', 11.8, 127]

    def test_bad_keysize_speck(self):
        for bad_ksize in self.not_key_sizes:
            with pytest.raises(KeyError):
                SpeckCipher(0, key_size=bad_ksize)

    def test_bad_keysize_simon(self):
        for bad_ksize in self.not_key_sizes:
            with pytest.raises(KeyError):
                SimonCipher(0, key_size=bad_ksize)


class TestCipherModesSpeck:

    key = 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100
    plaintxt = 0x65736f6874206e49202e72656e6f6f70
    iv = 0x123456789ABCDEF0
    counter = 0x1
    block_size = 128
    key_size = 256

    def test_ctr_mode_equivalent(self):

        c = SpeckCipher(self.key, self.key_size, self.block_size, 'CTR', init=self.iv, counter=self.counter)
        ctr_out = c.encrypt(self.plaintxt)

        c = SpeckCipher(self.key, self.key_size, self.block_size, 'ECB')
        ecb_out = c.encrypt(self.iv + self.counter)
        ctr_equivalent = ecb_out ^ self.plaintxt
        assert ctr_out == ctr_equivalent

    def test_ctr_mode_single_cycle(self):

        self.counter = 0x01

        c = SpeckCipher(self.key, self.key_size, self.block_size, 'CTR', init=self.iv, counter=self.counter)
        ctr_out = c.encrypt(self.plaintxt)

        self.counter = 0x01

        c = SpeckCipher(self.key, self.key_size, self.block_size, 'CTR', init=self.iv, counter=self.counter)
        output_plaintext = c.decrypt(ctr_out)

        assert output_plaintext == self.plaintxt

    def test_ctr_mode_chain(self):

        c = SpeckCipher(self.key, self.key_size, self.block_size, 'CTR', init=self.iv, counter=self.counter)

        ctr_out = 0
        for x in range(1000):
            ctr_out = c.encrypt(self.plaintxt)
        c = SpeckCipher(self.key, self.key_size, self.block_size, 'ECB')

        ctr_equivalent = 0
        for x in range(1000):
            ecb_out = c.encrypt(self.iv + self.counter)
            self.counter += 1
            ctr_equivalent = ecb_out ^ self.plaintxt

        assert ctr_out == ctr_equivalent

    def test_cbc_mode_single(self):

        c = SpeckCipher(self.key, self.key_size, self.block_size, 'CBC', init=self.iv)
        cbc_out = c.encrypt(self.plaintxt)

        c = SpeckCipher(self.key, self.key_size, self.block_size, 'ECB')
        cbc_equivalent = c.encrypt(self.iv ^ self.plaintxt)
        assert cbc_out == cbc_equivalent

    def test_cbc_mode_chain(self):

        c = SpeckCipher(self.key, self.key_size, self.block_size, 'CBC', init=self.iv)

        cbc_out = 0
        for x in range(1000):
            cbc_out = c.encrypt(self.plaintxt)

        c = SpeckCipher(self.key, self.key_size, self.block_size, 'ECB')

        cbc_equivalent = self.iv
        for x in range(1000):
            cbc_input = self.plaintxt ^ cbc_equivalent
            cbc_equivalent = c.encrypt(cbc_input)

        assert cbc_out == cbc_equivalent

    def test_pcbc_mode_single(self):

        c = SpeckCipher(self.key, self.key_size, self.block_size, 'PCBC', init=self.iv)
        pcbc_out = c.encrypt(self.plaintxt)

        c = SpeckCipher(self.key, self.key_size, self.block_size, 'ECB')
        pcbc_equivalent = c.encrypt(self.iv ^ self.plaintxt)
        assert pcbc_out == pcbc_equivalent

    def test_pcbc_mode_chain(self):

        c = SpeckCipher(self.key, self.key_size, self.block_size, 'PCBC', init=self.iv)

        pcbc_out = 0
        for x in range(1000):
            pcbc_out = c.encrypt(self.plaintxt)

        c = SpeckCipher(self.key, self.key_size, self.block_size, 'ECB')

        pcbc_equivalent = 0
        for x in range(1000):
            pcbc_input = self.plaintxt ^ self.iv
            pcbc_equivalent = c.encrypt(pcbc_input)
            self.iv = pcbc_equivalent ^ self.plaintxt

        assert pcbc_out == pcbc_equivalent



    def test_cfb_mode_equivalent(self):
        c = SpeckCipher(self.key, self.key_size, self.block_size, 'CFB', init=self.iv)
        cfb_encrypt = c.encrypt(self.plaintxt)
        c = SpeckCipher(self.key, self.key_size, self.block_size, 'CFB', init=self.iv)
        cfb_decrypt = c.decrypt(cfb_encrypt)

        c = SpeckCipher(self.key, self.key_size, self.block_size, 'ECB')
        ecb_out = c.encrypt(self.iv)
        cfb_equivalent_encrypt = ecb_out ^ self.plaintxt
        cfb_equivalent_decrypt = ecb_out ^ cfb_equivalent_encrypt

        assert cfb_encrypt == cfb_equivalent_encrypt
        assert cfb_decrypt == cfb_equivalent_decrypt


    def test_cfb_mode_chain(self):
        plaintxts = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

        c = SpeckCipher(self.key, self.key_size, self.block_size, 'CFB', init=self.iv)
        ciphertexts = [c.encrypt(x) for x in plaintxts]
        c = SpeckCipher(self.key, self.key_size, self.block_size, 'CFB', init=self.iv)
        decryptexts = [c.decrypt(x) for x in ciphertexts]

        assert plaintxts == decryptexts


    def test_ofb_mode_equivalent(self):
        c = SpeckCipher(self.key, self.key_size, self.block_size, 'OFB', init=self.iv)
        ofb_encrypt = c.encrypt(self.plaintxt)
        c = SpeckCipher(self.key, self.key_size, self.block_size, 'OFB', init=self.iv)
        ofb_decrypt = c.decrypt(ofb_encrypt)

        c = SpeckCipher(self.key, self.key_size, self.block_size, 'ECB')
        ecb_out = c.encrypt(self.iv)
        ofb_equivalent_encrypt = ecb_out ^ self.plaintxt
        ofb_equivalent_decrypt = ecb_out ^ ofb_equivalent_encrypt

        assert ofb_encrypt == ofb_equivalent_encrypt
        assert ofb_decrypt == ofb_equivalent_decrypt

    def test_ofb_mode_chain(self):
        plaintxts = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

        c = SpeckCipher(self.key, self.key_size, self.block_size, 'OFB', init=self.iv)
        ciphertexts = [c.encrypt(x) for x in plaintxts]
        c = SpeckCipher(self.key, self.key_size, self.block_size, 'OFB', init=self.iv)
        decryptexts = [c.decrypt(x) for x in ciphertexts]

        assert plaintxts == decryptexts


class TestCipherModesSimon:

    key = 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100
    plaintxt = 0x65736f6874206e49202e72656e6f6f70
    iv = 0x123456789ABCDEF0
    counter = 0x1
    block_size = 128
    key_size = 256

    def test_ctr_mode_equivalent(self):

        c = SimonCipher(self.key, self.key_size, self.block_size, 'CTR', init=self.iv, counter=self.counter)
        ctr_out = c.encrypt(self.plaintxt)

        c = SimonCipher(self.key, self.key_size, self.block_size, 'ECB')
        ecb_out = c.encrypt(self.iv + self.counter)
        ctr_equivalent = ecb_out ^ self.plaintxt
        assert ctr_out == ctr_equivalent

    def test_ctr_mode_single_cycle(self):

        self.counter = 0x01

        c = SimonCipher(self.key, self.key_size, self.block_size, 'CTR', init=self.iv, counter=self.counter)
        ctr_out = c.encrypt(self.plaintxt)

        self.counter = 0x01

        c = SimonCipher(self.key, self.key_size, self.block_size, 'CTR', init=self.iv, counter=self.counter)
        output_plaintext = c.decrypt(ctr_out)

        assert output_plaintext == self.plaintxt

    def test_ctr_mode_chain(self):

        c = SimonCipher(self.key, self.key_size, self.block_size, 'CTR', init=self.iv, counter=self.counter)

        ctr_out = 0
        for x in range(1000):
            ctr_out = c.encrypt(self.plaintxt)
        c = SimonCipher(self.key, self.key_size, self.block_size, 'ECB')

        ctr_equivalent = 0
        for x in range(1000):
            ecb_out = c.encrypt(self.iv + self.counter)
            self.counter += 1
            ctr_equivalent = ecb_out ^ self.plaintxt

        assert ctr_out == ctr_equivalent

    def test_cbc_mode_single(self):

        c = SimonCipher(self.key, self.key_size, self.block_size, 'CBC', init=self.iv)
        cbc_out = c.encrypt(self.plaintxt)

        c = SimonCipher(self.key, self.key_size, self.block_size, 'ECB')
        cbc_equivalent = c.encrypt(self.iv ^ self.plaintxt)
        assert cbc_out == cbc_equivalent

    def test_cbc_mode_chain(self):

        c = SimonCipher(self.key, self.key_size, self.block_size, 'CBC', init=self.iv)

        cbc_out = 0
        for x in range(1000):
            cbc_out = c.encrypt(self.plaintxt)

        c = SimonCipher(self.key, self.key_size, self.block_size, 'ECB')

        cbc_equivalent = self.iv
        for x in range(1000):
            cbc_input = self.plaintxt ^ cbc_equivalent
            cbc_equivalent = c.encrypt(cbc_input)

        assert cbc_out == cbc_equivalent

    def test_pcbc_mode_single(self):

        c = SimonCipher(self.key, self.key_size, self.block_size, 'PCBC', init=self.iv)
        pcbc_out = c.encrypt(self.plaintxt)

        c = SimonCipher(self.key, self.key_size, self.block_size, 'ECB')
        pcbc_equivalent = c.encrypt(self.iv ^ self.plaintxt)
        assert pcbc_out == pcbc_equivalent

    def test_pcbc_mode_chain(self):

        c = SimonCipher(self.key, self.key_size, self.block_size, 'PCBC', init=self.iv)

        cbc_out = 0
        for x in range(1000):
            cbc_out = c.encrypt(self.plaintxt)

        c = SimonCipher(self.key, self.key_size, self.block_size, 'ECB')

        pcbc_equivalent = 0
        for x in range(1000):
            pcbc_input = self.plaintxt ^ self.iv
            pcbc_equivalent = c.encrypt(pcbc_input)
            self.iv = pcbc_equivalent ^ self.plaintxt

        assert cbc_out == pcbc_equivalent

    def test_cfb_mode_equivalent(self):
        c = SimonCipher(self.key, self.key_size, self.block_size, 'CFB', init=self.iv)
        cfb_encrypt = c.encrypt(self.plaintxt)
        c = SimonCipher(self.key, self.key_size, self.block_size, 'CFB', init=self.iv)
        cfb_decrypt = c.decrypt(cfb_encrypt)

        c = SimonCipher(self.key, self.key_size, self.block_size, 'ECB')
        ecb_out = c.encrypt(self.iv)
        cfb_equivalent_encrypt = ecb_out ^ self.plaintxt
        cfb_equivalent_decrypt = ecb_out ^ cfb_equivalent_encrypt

        assert cfb_encrypt == cfb_equivalent_encrypt
        assert cfb_decrypt == cfb_equivalent_decrypt


    def test_cfb_mode_chain(self):
        plaintxts = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

        c = SimonCipher(self.key, self.key_size, self.block_size, 'CFB', init=self.iv)
        ciphertexts = [c.encrypt(x) for x in plaintxts]
        c = SimonCipher(self.key, self.key_size, self.block_size, 'CFB', init=self.iv)
        decryptexts = [c.decrypt(x) for x in ciphertexts]

        assert plaintxts == decryptexts

    def test_ofb_mode_equivalent(self):
        c = SimonCipher(self.key, self.key_size, self.block_size, 'OFB', init=self.iv)
        ofb_encrypt = c.encrypt(self.plaintxt)
        c = SimonCipher(self.key, self.key_size, self.block_size, 'OFB', init=self.iv)
        ofb_decrypt = c.decrypt(ofb_encrypt)

        c = SimonCipher(self.key, self.key_size, self.block_size, 'ECB')
        ecb_out = c.encrypt(self.iv)
        ofb_equivalent_encrypt = ecb_out ^ self.plaintxt
        ofb_equivalent_decrypt = ecb_out ^ ofb_equivalent_encrypt

        assert ofb_encrypt == ofb_equivalent_encrypt
        assert ofb_decrypt == ofb_equivalent_decrypt

    def test_ofb_mode_chain(self):
        plaintxts = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

        c = SimonCipher(self.key, self.key_size, self.block_size, 'OFB', init=self.iv)
        ciphertexts = [c.encrypt(x) for x in plaintxts]
        c = SimonCipher(self.key, self.key_size, self.block_size, 'OFB', init=self.iv)
        decryptexts = [c.decrypt(x) for x in ciphertexts]

        assert plaintxts == decryptexts
