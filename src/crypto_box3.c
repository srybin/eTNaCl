#include "etweetnacl.c"

int main() {
    //--------------------------------------------------------------------
    //generate device`s X25519 keypair and gateway`s Ed25519 keypair
    //--------------------------------------------------------------------
    unsigned char device_secret_key[ crypto_box_SECRETKEYBYTES ];
    unsigned char device_public_key[ crypto_box_PUBLICKEYBYTES ];
    crypto_box_keypair( device_public_key, device_secret_key );
    
    unsigned char gateway_ed25519_secret_key[ crypto_sign_SECRETKEYBYTES ];
    unsigned char gateway_ed25519_public_key[ crypto_sign_PUBLICKEYBYTES ];
    crypto_sign_keypair( gateway_ed25519_public_key, gateway_ed25519_secret_key );
    //--------------------------------------------------------------------

    //--------------------------------------------------------------------
    //device use ECIES to box a message
    //--------------------------------------------------------------------
    unsigned char gateway_x25519_public_key[ crypto_box_PUBLICKEYBYTES ];
    crypto_ed25519_pk_to_x25519(gateway_x25519_public_key, gateway_ed25519_public_key);

    /*
    WARNING: Messages in the C NaCl API are 0-padded versions of messages in the C++ NaCl API. 
    Specifically: The caller must ensure, before calling the C NaCl crypto_box function, 
    that the first crypto_box_ZEROBYTES bytes of the message m are all 0. 
    Typical higher-level applications will work with the remaining bytes of the message; 
    note, however, that mlen counts all of the bytes, including the bytes required to be 0.

    Similarly, ciphertexts in the C NaCl API are 0-padded versions of messages in the C++ NaCl API. 
    Specifically: The crypto_box function ensures that the first crypto_box_BOXZEROBYTES bytes of the ciphertext c are all 0.
    */

    unsigned char nonce[ crypto_box_NONCEBYTES ];
    randombytes( nonce, crypto_box_NONCEBYTES );
    
    unsigned long long len = crypto_box_ZEROBYTES + 3; //32 zero bytes + 3 bytes of message
    unsigned char box[35] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    unsigned char message[35] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'C','0','3'};
    crypto_box( box, message, len, nonce, gateway_x25519_public_key, device_secret_key );
    //--------------------------------------------------------------------

    //send |device_public_key, nonce, box|

    //--------------------------------------------------------------------
    //device use ECIES to unbox a message
    //--------------------------------------------------------------------
    unsigned char gateway_x25519_secret_key[ crypto_box_SECRETKEYBYTES ];
    crypto_ed25519_sk_to_x25519(gateway_x25519_secret_key, gateway_ed25519_secret_key);

    /*
    The caller must ensure, before calling the crypto_box_open function, 
    that the first crypto_box_BOXZEROBYTES bytes of the ciphertext c are all 0. 
    The crypto_box_open function ensures (in case of success) that the first crypto_box_ZEROBYTES bytes of the plaintext m are all 0.
    */

    unsigned char unboxed_message[35] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    crypto_box_open( unboxed_message, box, len, nonce, device_public_key, gateway_x25519_secret_key );
    //--------------------------------------------------------------------

    printhex("Device's secret key: ", device_secret_key, crypto_box_SECRETKEYBYTES);
    printhex("Device's public key: ", device_public_key, crypto_box_PUBLICKEYBYTES);
    printtext("Message to encrypt: ", message, crypto_box_ZEROBYTES, len);
    printhex("Nonce: ", nonce, crypto_box_NONCEBYTES);
    printhex("Crypto box: ", box, len);
    printf("\n");

    printhex("Gateway's Ed25519 secret key: ", gateway_ed25519_secret_key, crypto_sign_SECRETKEYBYTES);
    printhex("Gateway's Ed25519 public key: ", gateway_ed25519_public_key, crypto_sign_PUBLICKEYBYTES);
    printhex("Gateway's X25519 secret key: ", gateway_x25519_secret_key, crypto_box_SECRETKEYBYTES);
    printhex("Gateway's X25519 public key: ", gateway_x25519_public_key, crypto_box_PUBLICKEYBYTES);
    
    printtext("Unboxed message: ", unboxed_message, crypto_box_ZEROBYTES, len);

    return 0;
}
