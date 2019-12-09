# Conversion from L2 ciphertext to L1 by Re-Encryption protocol

# Support architecture

* x86-64 Windows + Visual Studio
* x86, x86-64 Linux/macOS + gcc/clang

# Installation Requirements

* [GMP](https://gmplib.org/)
```
apt install libgmp-dev
```

Create a working directory (e.g., work) and clone the following repositories.
```
mkdir work
cd work
git clone git://github.com/herumi/mcl
git clone git://github.com/herumi/l2-to-l1
cd l2-to-l1
make
```
# How to use

```
usage:bootstrap [opt]
  -h show this message
  -ip : ip address
  -p : port
  -m : message
  -bitN : message space bit
  -save-sec : save secretKey
```

sample test
- server
  - ./bootstrap -bitN 8
- client
  - ./bootstrap -ip `<server>` -bitN 8

# Reference
[Arbitrary Univariate Function Evaluation and Re-Encryption Protocols over Lifted-ElGamal Type Ciphertexts](https://eprint.iacr.org/2019/1233), Koji Nuida and Satsuya Ohata and Shigeo Mitsunari and Nuttapong Attrapadung


# Acknowledgements
Thanks to Masashi Horikoshi at Intel to provide Xeon SP environments to evaluate this protocol.

# Author

光成滋生 MITSUNARI Shigeo(herumi@nifty.com)
