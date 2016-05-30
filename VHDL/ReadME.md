# Simon & Speck Block Ciphers in VHDL

Synthesizable VHDL implementations of the [Simon and Speck] block ciphers. These are small ciphers designed by the [National Security Agency] for use in constrained hardware and software environments such as micro controllers or small ASICs/FPGAs.

**WARNING** The following implementations are for reference/research/entertainment only and should not be considered 100% free of bugs or side channel attacks. Use in a production environment is discouraged.


##  Basic Usage ##
Simon and Speck work identically. Instaniate the each module while speci

![Key_Generation]:http://i.imgur.com/9q1tPhK.png
![Encryption]:http://i.imgur.com/qZ4NwJa.png
![Decryption]:http://i.imgur.com/pcPImY8.png
![Back to Back Encryption]:http://i.imgur.com/sRvHRwP.png


### Block and Key Size ###
All valid key and block sizes as described in the specification are supported as optional parameters. Valid block and key sizes in bits are:

| **block size** | **key sizes** |
|:--------------:|:-------------:|
|       32       |       64      |
|       48       |     72,96     |
|       64       |     96,128    |
|       96       |     96,144    |
|       128      |  128,192,256  |

If not supplied at initialization, both ciphers will default to 256-bit encryption keys and 128-bit block sizes. If the defaults are not used, it is reccomended to specify both the key size and block explictly. 


## Implementation Details ##


## Data Types ##


## Tests Benches ##


[National Security Agency]:https://www.nsa.gov/
[Simon and Speck]:http://eprint.iacr.org/2013/404.pdf
