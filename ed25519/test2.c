//  https://github.com/orlp/ed25519.git
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* #define ED25519_DLL */
#include "src/ed25519.h"

#include "src/ge.h"
#include "src/sc.h"

/*
orlp - based on SUPERCOP ref10

https://github.com/novifinancial/ed25519-speccheck


?? nacl extractable -- interop woth openssl??

small sec BAD - NaCl / libsodium[26] 
CryptoNote cryptocurrency protocol
has64sec - wolfSSL[27] ---- compiling from source/github
    I2Pd has its own implementation of EdDSA[28]
    Minisign[29] and Minisign Miscellanea[30] for macOS
    Virgil PKI uses Ed25519 keys by default[31]
has64sec - Botan (openCL BSD TLS)
BAD-self - Dropbear SSH since 2013.61test[32]
BAD - OpenSSL 1.1.1[33]
Hashmap server and client (Go language and Javascript)
   * https://golang.org/pkg/crypto/ed25519/ 64sec
Libgcrypt

wolfssl-4.7.0.zip 

(SHA256: 59edfb6b70c17c82f2ef6126198549adf6cbccee8f013cfca88323590f8cbd43)
* */


void writehex(char *out, uint8_t *in, uint8_t len) {
	int i;
	for (i=0; i<len; i++) {
		char buf[3];
		//printf("writehex %d %02x\n", i, in[i]);
		sprintf(buf, "%02x", 0xff & in[i]);
		out[2*i] = buf[0];
		out[2*i+1] = buf[1];
	}
	out[2*len+1] = '\0';
}

void readhex(uint8_t *out0, char *in0) {
	uint8_t *out = out0;
	char *in = in0;
	char tmp[3];
	tmp[2] = '\0';
	int len = 0;


	while (*in != '\0') {
		len++;
		tmp[0] = in[0];
		tmp[1] = in[1];
		int byte;
		sscanf(tmp, "%02x", &byte);
		*out = byte;
		//printf("readhex %i str:%s %02x\n", len, tmp, *out);
		out++;
		in += 2;
	}
	
	if (0) {
		char *str = (char*)malloc(len+1);
		writehex(str, out0, len);
		printf("readhex %i %s\n", len, str);
		free(str);
	}
}

void gen() {
    unsigned char public_key[32], private_key[64], seed[32];

    /* create a random seed, and a keypair out of that seed */
    ed25519_create_seed(seed);
    ed25519_create_keypair(public_key, private_key, seed);
    
    char pubStr[65], secStr[129];
    writehex(pubStr, public_key, 32);
    writehex(secStr, private_key, 64);
	printf("pub %s\n", pubStr);
	printf("sec %s\n", secStr);
}
void sign(char *pub, char *sec, char *msg, char *out) {
    unsigned char public_key[32], private_key[64];
    unsigned char signature[64];
    
    readhex(public_key, pub);
    readhex(private_key, sec); 
    
    /* create signature on the message with the keypair */
    ed25519_sign(signature, msg, strlen(msg), public_key, private_key);

	if (out != NULL) {
		writehex(out, signature, 64);
		return;
	}
	char sigStr[129];
	writehex(sigStr, signature, 64);
	printf("sig %s\n", sigStr);
}
int verify(char *pub, char *sig, char *msg) {
    unsigned char signature[64], public_key[32];

	readhex(public_key, pub);
	readhex(signature, sig);

    /* verify the signature */
    if (ed25519_verify(signature, msg, strlen(msg), public_key)) {
        printf("valid signature\n");
        return 0;
    } else {
        printf("invalid signature\n");
    }
    return -1;
}
void test() {
	const char *pub="c2acd61aafc7ef8b7c98cf433289969a10af72f94f50ac5f28aaed3dab6429ca";
	const char *sec="3045a8208b908626b555ff4cf9af0a7c6bb1821560329c60a94ff52fd3f2955a5e874dd57f43dee016adfcbd9741e134162af86cc34ed084535936b17c6b5dbb";
	const char *msg="binky55";
	const char *gold="06468f4e23ff9450bf182b78b90e3458e40b1c13a2b591d488aa95698c50a1a9fde52b9602c6455ea47f51961fc70c0b35a7167591337efa3046af747bc95504";
	char sig[129];
	sig[128] = '\0';
	sign(pub, sec, msg, sig);

	int rv;
	rv = strcmp(gold, sig);
	printf("sig %s\n",(rv==0)?"good":"fail");

	rv = verify(pub, sig, msg);
	printf("verify %s\n",(rv==0)?"good":"fail");
	
	sig[0]='1';
	rv = verify(pub, sig, msg);
	printf("verifyNeg %s\n",(rv!=0)?"good":"fail");
}

int main(int argc, char **argv) {
	printf("begin main\n");
	if (argc == 1) {
		printf("give command\n");
	} else if (0 == strcmp(argv[1], "gen")) {
		gen();
	} else if (0 == strcmp(argv[1], "test")) {
		test();
	} else if (0 == strcmp(argv[1], "sign")) {
		sign(argv[2], argv[3], argv[4], NULL);
	} else if (0 == strcmp(argv[1], "verify")) {
		verify(argv[2], argv[3], argv[4]);
	}
	printf("end main\n");
}

