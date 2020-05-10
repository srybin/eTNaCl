#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    unsigned char k[ crypto_onetimeauth_KEYBYTES ];
    randombytes( k, crypto_onetimeauth_KEYBYTES );

    /*
    The sender must not use crypto_onetimeauth to authenticate more than one message under the same key. 
    Authenticators for two messages under the same key should be expected to reveal enough information 
    to allow forgeries of authenticators on other messages.
    */

    unsigned long long mlen = 3;
    const unsigned char m[3] = "C03";
    unsigned char a[ crypto_onetimeauth_BYTES ];
    crypto_onetimeauth( a, m, mlen, k );

    //--------------------------------------------------------------------
    //v1 must be 0
    //--------------------------------------------------------------------
    int v1 = crypto_onetimeauth_verify( a, m, mlen, k );
    //--------------------------------------------------------------------

    //--------------------------------------------------------------------
    //change authenticated message, v2 must be -1
    //--------------------------------------------------------------------    
    unsigned char m2[mlen];
    memcpy(m2, m, mlen);
    m2[mlen - 1] = '2';

    int v2 = crypto_onetimeauth_verify( a, m2, mlen, k );
    //--------------------------------------------------------------------

    //--------------------------------------------------------------------
    //Use diffrent MAC tag, v2 must be -1
    //--------------------------------------------------------------------
    unsigned char a2[ crypto_onetimeauth_BYTES ];
    randombytes( a2, crypto_onetimeauth_BYTES );

    int v3 = crypto_onetimeauth_verify( a2, m, mlen, k );
    //--------------------------------------------------------------------

    printhex("MAC key: ", k, crypto_onetimeauth_KEYBYTES);
    printf("Message to authenticate: %s\n", m);
    printhex("MAC tag: ", a, crypto_onetimeauth_BYTES);
    printf("V1: %d\n", v1);
    printf("V2: %d\n", v2);
    printf("V3: %d\n", v3);

    return 0;
}