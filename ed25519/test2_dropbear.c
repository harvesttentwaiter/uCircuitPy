#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//gcc -o test2_dropbear test2_dropbear.c curve25519.c sha512.c  ; echo $? rv


#include "curve25519.h"

typedef u_int8_t uint8_t;


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

void sign(char *pub, char *secH, char *msg, char *out) {
    unsigned char public_key[32], private_key[64];
    unsigned char signature[64];
    
    readhex(public_key, pub);
    readhex(private_key, secH); 
    
    /* create signature on the message with the keypair */
    //ed25519_sign(signature, msg, strlen(msg), public_key, private_key);
	
	unsigned long slen=64;
	dropbear_ed25519_sign(msg, strlen(msg),
		signature, &slen,
		private_key, public_key);
	
	if (out != NULL) {
		writehex(out, signature, 64);
		return;
	}
	char sigStr[129];
	writehex(sigStr, signature, 64);
	printf("sig %s\n", sigStr);
}
int verify(char *pubH, char *sig, char *msg) {
    unsigned char signature[64], public_key[32];

	readhex(public_key, pubH);
	readhex(signature, sig);

    /* verify the signature */
    int rv = 0;
    //rv = ed25519_verify(signature, msg, strlen(msg), public_key);
    
	rv = dropbear_ed25519_verify(msg, strlen(msg), signature, 64, public_key);

    if (rv == 1) {
        printf("valid signature\n");
        return 0;
    } else {
        printf("invalid signature\n");
    }
    return -1;
}
void gen() {
	/*
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
	EVP_PKEY_keygen_init(pctx);
	EVP_PKEY_keygen(pctx, &pkey);
	EVP_PKEY_CTX_free(pctx);
	
	int rv;
	unsigned char buf[222];
	char hexbuf[445];
	size_t used=222;
	rv = EVP_PKEY_get_raw_private_key(pkey, buf, &used);
	if (rv != 1) printf("get raw pr fail\n");
	writehex(hexbuf, buf, used);
	hexbuf[2*used] = '\0';
	printf("sec %s\n", hexbuf);
	
	used=222;
	rv = EVP_PKEY_get_raw_public_key(pkey, buf, &used);
	if (rv != 1) printf("get raw pu fail\n");
	writehex(hexbuf, buf, used);
	hexbuf[2*used] = '\0';
	printf("pub %s\n", hexbuf); // */
}
void test() {
	/*
	const char *pub="c2acd61aafc7ef8b7c98cf433289969a10af72f94f50ac5f28aaed3dab6429ca";
	const char *sec="3045a8208b908626b555ff4cf9af0a7c6bb1821560329c60a94ff52fd3f2955a5e874dd57f43dee016adfcbd9741e134162af86cc34ed084535936b17c6b5dbb";
	const char *msg="binky55";
	const char *gold="06468f4e23ff9450bf182b78b90e3458e40b1c13a2b591d488aa95698c50a1a9fde52b9602c6455ea47f51961fc70c0b35a7167591337efa3046af747bc95504";
	// */
	const char *pub="799f88d1a2703d1811816be54d3e2ae800dd8cc63edf66d1b3c5b355b13f066f";
	const char *sec="b90988a1b0bdbb8625a5644c3b5d2140502520e6159b2de21e0e39c863969be8";
	const char *msg="Winky.19";
	const char *gold="a517b1a6e81eca859541bf9735a1da97f7a8d3e3ccc5c352996bf9c97d23cae2a5e01ca42ad5ea6c518e0e5e5e5d233b4cc06749cedfb69ff5efa9f598bcd605";

	char sig[129];
	sig[128] = '\0';
	sign(pub, sec, msg, sig);

	int rv;
	rv = strcmp(gold, sig);
	printf("test() sig %s\n",(rv==0)?"good":"fail");

	rv = verify(pub, gold, msg);
	printf("test() verify %s\n",(rv==0)?"good":"fail");
	
	sig[0]='1';
	rv = verify(pub, sig, msg);
	printf("test() verifyNeg %s\n",(rv!=0)?"good":"fail");
}
// gcc -o test2_openssl test2_openssl.c -lcrypto
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
		// pub sec msg optOut
	} else if (0 == strcmp(argv[1], "verify")) {
		verify(argv[2], argv[3], argv[4]);
		// pub sig msg
	}
	printf("end main\n");
}

