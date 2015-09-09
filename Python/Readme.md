# Simon & Speck Block Ciphers in Python 3.x/2.x

Pure python implementations of the [Simon and Speck] block ciphers. These are small ciphers designed by the [National Security Agency] for use in constrained hardware and software environments such as micro controllers or small ASICs/FPGAs.

**WARNING** The following implementations are for reference/research/entertainment only and should not be considered 100% free of bugs or side channel attacks. Use in a production environment is discouraged.

##  Basic Usage ##
Simon and Speck work identically. Once the code has been copied into your project, the ciphers can be imported:
```sh
>>> from speck import SpeckCipher
>>> from simon import SimonCipher
```

Once imported, a ciphers object that store the state of the cipher can be created. The only parameter required to initialize a cipher object is an encryption key.
```sh
>>> my_speck = SpeckCipher(0x123456789ABCDEF00FEDCBA987654321)
>>> my_simon = SimonCipher(0xABBAABBAABBAABBAABBAABBAABBAABBA)
```

Once initialized, the cipher can encrypt or decrypt provided plaintext or ciphertext values using the ```encrypt()``` and ```decrypt()``` methods. The object will continue to process encryption/decryption requests as long as the object exists.
```sh
>>> my_plaintext = 0xCCCCAAAA55553333
>>> speck_ciphertext = my_speck.encrypt(my_plaintext)
>>> speck_plaintext = my_speck.decrypt(speck_ciphertext)
>>> simon_ciphertext = my_simon.encrypt(0xFFFF0000EEEE1111)
>>> simon_plaintext = my_simon.decrypt(simon_ciphertext)
```
The encryption key may be read or updated by way of the ```key``` attribute
```sh
>>> hex(my_speck.key)
'0x123456789abcdef00fedcba987654321'
```

### Block and Key Size ###
All valid key and block sizes as described in the specification are supported as optional parameters. Valid block and key sizes in bits are:

| **block size** | **key sizes** |
|:--------------:|:-------------:|
|       32       |       64      |
|       48       |     72,96     |
|       64       |     96,128    |
|       96       |     96,144    |
|       128      |  128,192,256  |

If not supplied at initialization, both ciphers will default to 128-bit encryption keys and block sizes. If the defaults are not used, it is reccomended to specify both the key size and block explictly. 

```sh
>>> tiny_cipher = SpeckCipher(0x123456789ABCDEF0, key_size=64, block_size=32)
>>> big_cipher = SimonCipher(0x111122223333444455556666777788889999AAAABBBBCCCCDDDDEEEEFFFF0000, key_size=256, block_size=128)
>>> trunc_cipher = SimonCipher(0x111122223333444455556666777788889999, key_size=96, block_size=48)
>>> hex(trunc_cipher.key)
'0x444455556666777788889999'
```

All inputted values (keys, plaintexts, IVs, etc) will be truncated or padded with zeros to the bit size specified by the block and key sizes. The current key and block sizes can be accessed via the ```key_size``` and ```block_size``` attributes

### Block Modes ###
For convenience, both ciphers support the [most common modes] of block cipher operation. 

- Electronic Code Book ```ECB``` (Default mode for Speck/Simon)
- Counter ```CTR```
- Cipher Block Chaining ```CBC```
- Propagating Cipher Block Chaining ```PCBC```
- Cipher Feedback ```CFB```
- Output Feedback ```OFB```

These can be enabled at initialization using the ```mode``` optional argument or via the ```mode``` attribute after creation.
Other than ECB, these modes require an additional Initialization Vector (IV) and possibly a Counter. These values can be set at cipher creation using the ```init``` and ```counter``` optional arguments. 
The ciphers automatically update or increment the IV and counter values internal between encrypt and decrypt operations. There is no need to manual update them between operations.

```sh
>>> ofb_cipher = SpeckCipher(1234, mode='OFB', init=0x999999)
>>> ctr_cipher = SimonCipher(0x525354, mode='CTR', init=0xCABCABCAB, counter=1)
>>> ctr_cipher.counter
1
>>> ofb_cipher.update_iv()
10066329
```

The IV may be may also be altered or read anytime during the cipher objects life using the ```update_iv()``` method. If a new IV is provided, this method returns the current IV, otherwise, it returns the IV that was just updated. The ciphers internal counter value may be read and altered through the ```counter``` attribute.

### Data Types ###
Currently, both the Speck and Simon ciphers expect **int** inputs for keys, IVs, counters, plaintexts, and ciphertexts. Any value provided that does not match the bit size for keys, plaintexts, etc, will be truncated down or MSB padded with 0's up to the correct size. If your application requires strings or bytearrays, input and output values can be easily translated to and from ints.

```sh
>>> key_bytes = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00])
# For Python 3.x Only
>>> key_int = int.from_bytes(key_bytes, byteorder='big', signed='False')
# Python 2.x/3.x
>>> import binascii
>>> key_int = int(binascii.hexlify(key_bytes),16)
>>> hex(key_int)
'0x112233445566778899aabbccddeeff00'
>>> msg = 'ATTACK AT DAWN!!'
>>> msg_int = sum([ord(c) << (8 * x) for x, c in enumerate(reversed(msg))])
>>> hex(msg_int)
'0x41545441434b204154204441574e2121'
>>> new_cipher = SimonCipher(key_int, key_size=128, block_size=128)
>>> my_secret = new_cipher(msg_int)
>>> my_secret_bytes = bytearray.fromhex('{:032x}'.format(my_secret))
>>> my_secret_bytes
bytearray(b'HD\xbb\xe4\xa1\xed\x95\xd8>\x1bx<HOL[')
```

## Tests & Examples ##
A robust pytest suite is provided in ```tests.py```. Here all the official test vectors are exercised as well as random values. Exceptions are tested as well as block cipher modes. Refer to these tests for clean examples of how to use each mode.

[National Security Agency]:https://www.nsa.gov/
[Simon and Speck]:http://eprint.iacr.org/2013/404.pdf
[most common modes]:https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
