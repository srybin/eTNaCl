#include <stdio.h>
#include <stdlib.h>
#include "tweetnacl.h"
#include "tweetnacl.c"

int crypto_ed25519_pk_to_x25519(u8 *z, u8 *ed25519pk) {
    gf q[4];
    gf a, b;
    
    if (unpackneg(q, ed25519pk)) return -1;
    
    A(a, gf1, q[1]);
    Z(b, gf1, q[1]);
    inv25519(b, b);
    M(a, a, b);
    
    pack25519(z, a);
    
    return 0;
}

int crypto_ed25519_sk_to_x25519(u8 *o, u8 *ed25519sk) {
    u8 d[64];
    int i;
    
    crypto_hash(d, ed25519sk, 32);
    
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;
    
    FOR(i,32) o[i] = d[i];
    FOR(i,64) d[i] = 0;
    
    return 0;
}

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