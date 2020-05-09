#include <stdio.h>
#include <stdlib.h>
#include "tweetnacl.c"

//clang eNaCl.c -O3 -o eNaCl

void randombytes(u8* buf,u64 len) {
    srand( arc4random() );

    for (int i = 0; i < len; i++) {
        buf[i] = rand();
    }
}

void printhex(char* label, unsigned char* key, int len) {
    printf("%s", label);

    for (int i=0; i < len; i++) {
       printf("%02x",key[i]);
    }

    printf("\n");
}

void printtext(char* label, unsigned char* m, int skip, int len){
    printf("%s", label);

    for (int i = skip; i < len; i++) {
       printf("%c", m[i] );
    }

    printf("\n");
}

int main() {
    unsigned char device_secret_key[ crypto_box_SECRETKEYBYTES ];
    unsigned char device_public_key[ crypto_box_PUBLICKEYBYTES ];
    crypto_box_keypair( device_public_key, device_secret_key );

    unsigned char gateway_secret_key[ crypto_box_SECRETKEYBYTES ];
    unsigned char gateway_public_key[ crypto_box_PUBLICKEYBYTES ];
    crypto_box_keypair( gateway_public_key, gateway_secret_key );

    unsigned char nonce[ crypto_box_NONCEBYTES ];
    randombytes( nonce, crypto_box_NONCEBYTES );

    /*
    WARNING: Messages in the C NaCl API are 0-padded versions of messages in the C++ NaCl API. 
    Specifically: The caller must ensure, before calling the C NaCl crypto_box function, 
    that the first crypto_box_ZEROBYTES bytes of the message m are all 0. 
    Typical higher-level applications will work with the remaining bytes of the message; 
    note, however, that mlen counts all of the bytes, including the bytes required to be 0.

    Similarly, ciphertexts in the C NaCl API are 0-padded versions of messages in the C++ NaCl API. 
    Specifically: The crypto_box function ensures that the first crypto_box_BOXZEROBYTES bytes of the ciphertext c are all 0.
    */

    unsigned long long len = 35;
    unsigned char box[35] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    unsigned char message[35] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'C','0','3'};
    crypto_box( box, message, len, nonce, gateway_public_key, device_secret_key );

    //send |device_public_key, nonce, box|

    /*
    The caller must ensure, before calling the crypto_box_open function, 
    that the first crypto_box_BOXZEROBYTES bytes of the ciphertext c are all 0. 
    The crypto_box_open function ensures (in case of success) that the first crypto_box_ZEROBYTES bytes of the plaintext m are all 0.
    */

    unsigned char decripted_message[35] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    crypto_box_open( decripted_message, box, len, nonce, device_public_key, gateway_secret_key );

    printhex("Device's secret key: ", device_secret_key, crypto_box_SECRETKEYBYTES);
    printhex("Device's public key: ", device_public_key, crypto_box_PUBLICKEYBYTES);
    printtext("Message to encrypt: ", message, crypto_box_BOXZEROBYTES, len);
    printhex("Nonce: ", nonce, crypto_box_NONCEBYTES);
    printhex("Crypto box: ", box, len);
    printf("\n");
    
    printhex("Gateway's secret key: ", gateway_secret_key, crypto_box_SECRETKEYBYTES);
    printhex("Gateway's public key: ", gateway_public_key, crypto_box_PUBLICKEYBYTES);
    printtext("Opened crypto box: ", decripted_message, crypto_box_BOXZEROBYTES, len);

    return 0;
}
