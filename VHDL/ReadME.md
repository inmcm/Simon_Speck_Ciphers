# Simon & Speck Block Ciphers in VHDL

Synthesizable VHDL implementations of the [Simon and Speck] block ciphers. These are small ciphers designed by the [National Security Agency] for use in constrained hardware and software environments such as micro controllers or small ASICs/FPGAs.

**WARNING** The following implementations are for reference/research/entertainment only and should not be considered 100% free of bugs or side channel attacks. Use in a production environment is discouraged.

##  Basic Usage ##
Simon and Speck work identically: simply declare and instaniate the modules into your large design and specify what key/block combination you want to use.
The ciphers have a simple operational flow that has two main sequnces: Key Schedule and Encryption/Decryption

#### For Key Schedule Generation ####

1. Set your cipher key on the `KEY` input bus
2. Set the `CONTROL` to `b01` to start the generation process
3. The `BUSY`signal  will assert while the key schedule is processed
4. Once `BUSY` deasserts, the cipher engine is ready to encrypt and decrypt with your chosen key; `KEY` will remain unused unless you wish to change the cipher key

#### To encipher or decipher data ####

1. Set your plaintext (if encrypting) or ciphertext (if decrypting) on the `BLOCK_INPUT` input bus
2. Set the `CONTROL` to `b11` to begin encrypting or `b10` to decrypt
3. `BUSY` will assert while the cipher is processed
4. Once `BUSY` deasserts, your new ciphertext or plaintext is available on `BLOCK_OUTPUT`. This ouput remains until a new encryption/decryption operation is completed

#### Additional Function Notes: ####
* `RST` hold the cipher in the a reset state that will not respond to inputs and outputs are undefined.
* When the cipher engine unused, `CONTROL` should be held at `b00`
* Encryption and Decryption Operations can be done back to back by simple holding CONTROL at `b10` or `b11` and changing `BLOCK_INPUT` anytime after `BUSY` is asserted
* No block cipher mode other than ECB are currently supported.

Declaration/Instaniation examples as well as functional timing diagrams for various operations are given below. 

### Simon  Declaration ###

```vhdl
COMPONENT SIMON_CIPHER
	 GENERIC(KEY_SIZE : integer range 0 to 256;
				BLOCK_SIZE : integer range 0 to 128;
				ROUND_LIMIT: integer range 0 to 72);
    PORT(
         SYS_CLK : IN  std_logic;
         RST : IN  std_logic;
         BUSY : OUT  std_logic;
         CONTROL : IN  std_logic_vector(1 downto 0);
         KEY : IN  std_logic_vector(KEY_SIZE - 1 downto 0);
         BLOCK_INPUT : IN  std_logic_vector(BLOCK_SIZE - 1 downto 0);
         BLOCK_OUTPUT : OUT  std_logic_vector(BLOCK_SIZE - 1 downto 0)
        );
    END COMPONENT;
```

### Simon Instaniation ###

```vhdl
uut_1: SIMON_CIPHER
	GENERIC MAP (KEY_SIZE => YOUR_KEY_SIZE,
			    BLOCK_SIZE => YOUR_BLOCK_SIZE,
				ROUND_LIMIT => Round_Count_Lookup(YOUR_KEY_SIZE, YOUR_BLOCK_SIZE))
	PORT MAP (
          SYS_CLK => your_clock_signal,
          RST => your_reset,
          BUSY => your_busy_signal_reader,
          CONTROL => your_cipher_control,
          KEY => your_key_input,
          BLOCK_INPUT => your_block_input,
          BLOCK_OUTPUT => your_output_reader
  );
```

### Speck Declaration ###

```vhdl
COMPONENT SPECK_CIPHER
	 GENERIC(KEY_SIZE : integer range 0 to 256;
				BLOCK_SIZE : integer range 0 to 128;
				ROUND_LIMIT: integer range 0 to 72);
    PORT(
         SYS_CLK : IN  std_logic;
         RST : IN  std_logic;
         BUSY : OUT  std_logic;
         CONTROL : IN  std_logic_vector(1 downto 0);
         KEY : IN  std_logic_vector(KEY_SIZE - 1 downto 0);
         BLOCK_INPUT : IN  std_logic_vector(BLOCK_SIZE - 1 downto 0);
         BLOCK_OUTPUT : OUT  std_logic_vector(BLOCK_SIZE - 1 downto 0)
        );
    END COMPONENT;
```

### Speck Instaniation ###

```vhdl
uut_1: SPECK_CIPHER
	GENERIC MAP (KEY_SIZE => YOUR_KEY_SIZE,
					 BLOCK_SIZE => YOUR_BLOCK_SIZE,
					 ROUND_LIMIT => Round_Count_Lookup(YOUR_KEY_SIZE, YOUR_BLOCK_SIZE))
	PORT MAP (
          SYS_CLK => your_clock_signal,
          RST => your_reset,
          BUSY => your_busy_signal_reader,
          CONTROL => your_cipher_control,
          KEY => your_key_input,
          BLOCK_INPUT => your_block_input,
          BLOCK_OUTPUT => your_output_reader
    );
```

### Signal Timing ###

![Key_Generation](http://i.imgur.com/9q1tPhK.png)
![Encryption](http://i.imgur.com/qZ4NwJa.png)
![Decryption](http://i.imgur.com/pcPImY8.png)
![Back to Back Encryption](http://i.imgur.com/sRvHRwP.png)


### Block and Key Size ###
All valid key and block sizes as described in the specification are supported as generics. Valid block and key sizes in bits are:

| **block size** | **key sizes** |
|:--------------:|:-------------:|
|       32       |       64      |
|       48       |     72,96     |
|       64       |     96,128    |
|       96       |     96,144    |
|       128      |  128,192,256  |

If not supplied at initialization, both ciphers will default to 256-bit encryption keys and 128-bit block sizes. If the defaults are not used, it is reccomended to specify both the key size and block explictly. 

## Tests Benches ##

A basic testbench for each cipher is included in SIMON_CIPHER_TB.vhd and SPECK_CIPHER_TB.vhd. These exercise key generation, encryption, and decryption for all key/block size combinations using the offical test vectors. These all serve as examples on instantiating the different cipher sizes. 

Waveform configuration files (.wcfg) are inclued for use under Xilinx ISim. 

[National Security Agency]:https://www.nsa.gov/
[Simon and Speck]:http://eprint.iacr.org/2013/404.pdf
