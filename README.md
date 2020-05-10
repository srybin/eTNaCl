# eTNaCl
eTNaCl is TweetNaCl usage examples (https://tweetnacl.cr.yp.to/)

## Download, build and run
```bash
git clone git@github.com:srybin/eTNaCl.git
cd ./eTNaCl/src
clang crypto_box1.c -O3 -o eTNaCl1
clang crypto_box2.c -O3 -o eTNaCl2
clang crypto_onetimeauth3.c -O3 -o eTNaCl3
clang crypto_secretbox4.c -O3 -o eTNaCl4
clang crypto_sign5.c -O3 -o eTNaCl5
./eTNaCl1
./eTNaCl2
./eTNaCl3
./eTNaCl4
./eTNaCl5
```

## Examples:
1. [crypto_box1.c](src/crypto_box1.c) - Public-key authenticated encryption by using crypto_box()/crypto_box_open() to use only asymmetric keys: http://nacl.cr.yp.to/box.html.
2. [crypto_box2.c](src/crypto_box2.c) - Public-key authenticated encryption by using crypto_box_beforenm()/crypto_box_afternm()/crypto_box_open_afternm() to use symmetric key: http://nacl.cr.yp.to/box.html.
3. [crypto_onetimeauth3.c](src/crypto_onetimeauth3.c) - MAC (Poly1305): http://nacl.cr.yp.to/onetimeauth.html.
4. [crypto_secretbox4.c](src/crypto_secretbox4.c) - Symmetric-key authenticated encryption by using xsalsa20poly1305: http://nacl.cr.yp.to/secretbox.html.
5. [crypto_sign5.c](src/crypto_sign5.c) - Digital signage (Ed25519): http://nacl.cr.yp.to/sign.html.