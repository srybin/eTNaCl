#include "etweetnacl.c"

int main() {
    unsigned char k[ crypto_secretbox_KEYBYTES ];
    randombytes( k, crypto_secretbox_KEYBYTES );

    /*
    WARNING: Messages in the C NaCl API are 0-padded versions of messages in the C++ NaCl API. 
    Specifically: The caller must ensure, before calling the C NaCl crypto_box function, 
    that the first crypto_box_ZEROBYTES bytes of the message m are all 0. 
    Typical higher-level applications will work with the remaining bytes of the message; 
    note, however, that mlen counts all of the bytes, including the bytes required to be 0.

    Similarly, ciphertexts in the C NaCl API are 0-padded versions of messages in the C++ NaCl API. 
    Specifically: The crypto_box function ensures that the first crypto_box_BOXZEROBYTES bytes of the ciphertext c are all 0.
    */

    unsigned char nonce[ crypto_secretbox_NONCEBYTES ];
    randombytes( nonce, crypto_secretbox_NONCEBYTES );
    
    unsigned long long len = crypto_secretbox_ZEROBYTES + 3; //32 zero bytes + 3 bytes of message
    unsigned char box[35] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    unsigned char message[35] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'C','0','3'};

    crypto_secretbox( box, message, len, nonce, k );

    //send |nonce, box|

    /*
    The caller must ensure, before calling the crypto_box_open function, 
    that the first crypto_box_BOXZEROBYTES bytes of the ciphertext c are all 0. 
    The crypto_box_open function ensures (in case of success) 
    that the first crypto_box_ZEROBYTES bytes of the plaintext m are all 0.
    */

    unsigned char unboxed_message[35] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    crypto_secretbox_open( unboxed_message, box, len, nonce, k );

    printhex("Symmetric key: ", k, crypto_secretbox_KEYBYTES);
    printhex("Nonce: ", nonce, crypto_secretbox_NONCEBYTES);
    printtext("Message to encrypt: ", message, crypto_secretbox_ZEROBYTES, len);
    printhex("Crypto box: ", box, len);
    printtext("Unboxed message: ", unboxed_message, crypto_secretbox_ZEROBYTES, len);

    return 0;
}