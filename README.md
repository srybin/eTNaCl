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