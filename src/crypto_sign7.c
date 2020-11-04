#include <string.h>
#include "etweetnacl.c"

int main() {
    unsigned char sk[ crypto_sign_SECRETKEYBYTES ];
    unsigned char pk[ crypto_sign_PUBLICKEYBYTES ];
    crypto_sign_keypair( pk, sk );

    /*
    The crypto_sign function signs a message m[0], ..., m[mlen-1] using 
    the signer's secret key sk[0], sk[1], ..., sk[crypto_sign_SECRETKEYBYTES-1], 
    puts the length of the signed message into smlen and puts the signed 
    message into sm[0], sm[1], ..., sm[smlen-1]. It then returns 0.

    The maximum possible length smlen is mlen+crypto_sign_BYTES. 
    The caller must allocate at least mlen+crypto_sign_BYTES bytes for sm.
    */

    unsigned long long mlen = 3;
    const unsigned char m[3] = "C03";

    unsigned long long smlen;
    unsigned char sm[mlen + crypto_sign_BYTES]; //signature (64 bytes) + message (3 bytes)
    crypto_sign( sm, &smlen, m, mlen, sk );

    /*
    The crypto_sign_open function verifies the signature in sm[0], ..., sm[smlen-1] using 
    the signer's public key pk[0], pk[1], ..., pk[crypto_sign_PUBLICKEYBYTES-1]. 
    The crypto_sign_open function puts the length of the message into mlen and 
    puts the message into m[0], m[1], ..., m[mlen-1]. It then returns 0.

    The maximum possible length mlen is smlen. The caller must allocate at least smlen bytes for m.
    If the signature fails verification, crypto_sign_open instead returns -1, possibly after modifying m[0], m[1], etc.
    */

    //--------------------------------------------------------------------
    //v1 must be 0
    //--------------------------------------------------------------------
    unsigned long long mlen2;
    unsigned char m2[smlen];
    int v1 = crypto_sign_open( m2, &mlen2, sm, smlen, pk );
    //--------------------------------------------------------------------

    //--------------------------------------------------------------------
    //change signed message, v2 must be -1
    //--------------------------------------------------------------------
    unsigned long long mlen3;
    unsigned char m3[smlen];
    unsigned char sm2[smlen];
    memcpy(sm2, sm, smlen);
    sm2[smlen - 1] = '2';
    int v2 = crypto_sign_open( m3, &mlen3, sm2, smlen, pk );
    //--------------------------------------------------------------------

    //--------------------------------------------------------------------
    //verify by using outher public key, v3 must be -1
    //--------------------------------------------------------------------
    unsigned char sk2[ crypto_sign_SECRETKEYBYTES ];
    unsigned char pk2[ crypto_sign_PUBLICKEYBYTES ];
    crypto_sign_keypair( pk2, sk2 );

    unsigned long long mlen4;
    unsigned char m4[smlen];
    unsigned char sm3[smlen];
    memcpy(sm3, sm, smlen);
    int v3 = crypto_sign_open( m4, &mlen4, sm3, smlen, pk2 );
    //--------------------------------------------------------------------

    printhex("Secret key: ", sk, crypto_sign_SECRETKEYBYTES);
    printhex("Public key: ", pk, crypto_sign_PUBLICKEYBYTES);
    printf("Message to sign: %s\n", m);
    printhex("Message to sign (hex): ", (unsigned char*) m, mlen);
    printhex("Signature: ", (unsigned char*) sm, smlen);
    printf("V1: %d\n", v1);
    printf("V2: %d\n", v2);
    printf("V2: %d\n", v3);

    return 0;
}