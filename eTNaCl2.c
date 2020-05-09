#include <stdio.h>
#include <stdlib.h>
#include "tweetnacl.c"

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

    unsigned char device_symmetric_key[ crypto_box_BEFORENMBYTES ];
    crypto_box_beforenm( device_symmetric_key, gateway_public_key, device_secret_key );

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
    crypto_box_afternm( box, message, len, nonce, device_symmetric_key );

    //send |device_public_key, nonce, box|

    unsigned char gateway_symmetric_key[ crypto_box_BEFORENMBYTES ];
    crypto_box_beforenm( gateway_symmetric_key, device_public_key, gateway_secret_key );

    /*
    The caller must ensure, before calling the crypto_box_open function, 
    that the first crypto_box_BOXZEROBYTES bytes of the ciphertext c are all 0. 
    The crypto_box_open function ensures (in case of success) that the first crypto_box_ZEROBYTES bytes of the plaintext m are all 0.
    */

    unsigned char decripted_message[35] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    crypto_box_open_afternm( decripted_message, box, len, nonce, gateway_symmetric_key );

    printhex("Device's secret key: ", device_secret_key, crypto_box_SECRETKEYBYTES);
    printhex("Device's public key: ", device_public_key, crypto_box_PUBLICKEYBYTES);
    printhex("Device's symmetric key: ", device_symmetric_key, crypto_box_BEFORENMBYTES);
    printtext("Message to encrypt: ", message, crypto_box_BOXZEROBYTES, len);
    printhex("Nonce: ", nonce, crypto_box_NONCEBYTES);
    printhex("Crypto box: ", box, len);
    printf("\n");
    
    printhex("Gateway's private key: ", gateway_secret_key, crypto_box_SECRETKEYBYTES);
    printhex("Gateway's public key: ", gateway_public_key, crypto_box_PUBLICKEYBYTES);
    printhex("Gateway's symmetric key: ", gateway_symmetric_key, crypto_box_BEFORENMBYTES);
    printtext("Opened crypto box: ", decripted_message, crypto_box_BOXZEROBYTES, len);
    printf("\n");
    //--------------------------------------------------------------------
    unsigned char nonce2[ crypto_box_NONCEBYTES ];
    randombytes( nonce2, crypto_box_NONCEBYTES );

    unsigned char box2[35] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    unsigned char message2[35] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'C','0','2'};
    crypto_box_afternm( box2, message2, len, nonce2, device_symmetric_key );

    //send |nonce2, box2|

    unsigned char decripted_message2[35] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    crypto_box_open_afternm( decripted_message2, box2, len, nonce2, gateway_symmetric_key );
    
    printhex("Nonce: ", nonce2, crypto_box_NONCEBYTES);
    printhex("Crypto box: ", box2, len);
    printtext("Opened crypto box: ", decripted_message2, crypto_box_BOXZEROBYTES, len);

    return 0;
}