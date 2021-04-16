#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//#include "curve25519.h"
#include <openssl/evp.h>
#define CURVE25519_KEY_SIZE 32

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


#define PROT_VAL 0x6d30243e
void exchange(char *mySecStr, char *peerPubStr) {
	int prot1 = PROT_VAL;
	char mySec[CURVE25519_KEY_SIZE];
	int prot2 = PROT_VAL;
	readhex(mySec, mySecStr);
	char peerPub[CURVE25519_KEY_SIZE];
	int prot3 = PROT_VAL;
	readhex(peerPub, peerPubStr);
	char shared[CURVE25519_KEY_SIZE];
	int prot4 = PROT_VAL;

	//curve25519(shared, mySec, peerPub);

	// gcc -o chk_openssl chk_openssl.c -lcrypto
	/* 
	 * chk_openssl exchange 604fcd2580d18ec6e9391a8c1ca7f855a68e560633ec3e3ca10ce1a15a52f84c 5669be909a1522fb9891383d335b498f4ee79e6943c826b3538270ccb1e47f57 
	 * shared 00000000fb3c4e0f8a86c4d392c90b1bf0bcbce134d10330133de22a81cde42d
	 * chk exchange 604fcd2580d18ec6e9391a8c1ca7f855a68e560633ec3e3ca10ce1a15a52f84c 5669be909a1522fb9891383d335b498f4ee79e6943c826b3538270ccb1e47f57 
	 * chk exchange c892bb10a8bf3531fedb773cc650f5fb02294a27dc53ad441e791856bee82649 37dd28bd0a4f76d814cee9d67f3a533f71a1d55737cf593c11a0eaceddf9f471 
	 * shared 388b1d04fb3c4e0f8a86c4d392c90b1bf0bcbce134d10330133de22a81cde42d
	 */

	EVP_PKEY *mySecOS = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                        mySec, CURVE25519_KEY_SIZE);
	EVP_PKEY *peerPubOS = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                       peerPub, CURVE25519_KEY_SIZE);

	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(mySecOS, NULL);
	int rv;
	rv = EVP_PKEY_derive_init(pctx);
	if (rv != 1) printf("fail init\n");
	rv = EVP_PKEY_derive_set_peer(pctx, peerPubOS);
	if (rv != 1) printf("fail set peer\n");
	int keylen = CURVE25519_KEY_SIZE;
	rv = EVP_PKEY_derive(pctx, shared, &keylen);
	if (rv != 1) printf("fail derive\n");


	char sharedStr[2*CURVE25519_KEY_SIZE+1];
	int prot5 = PROT_VAL;	
	writehex(sharedStr, shared, CURVE25519_KEY_SIZE);
	printf("shared %s\n", sharedStr);
	if (prot1 != PROT_VAL) printf("prot1 corrupt\n");
	if (prot2 != PROT_VAL) printf("prot2 corrupt\n");
	if (prot3 != PROT_VAL) printf("prot3 corrupt\n");
	if (prot4 != PROT_VAL) printf("prot4 corrupt\n");
	if (prot5 != PROT_VAL) printf("prot5 corrupt\n");
}

char PROT_CH = 0xfc;
void testhex() {
	char prot1 = PROT_CH;
	int i;
	char prot2 = PROT_CH;
	char str[5];
	char prot3 = PROT_CH;
	str[4] = '\0';
	unsigned char bin00[2] = { 0x90, 0xae };
	char prot4 = PROT_CH;
	unsigned char bin0[2] = { 0x90, 0xae };
	char prot5 = PROT_CH;
	unsigned char bin[2] = { 0x90, 0xae };
	char prot6 = PROT_CH;
	unsigned char bin01[2] = { 0x90, 0xae };
	char prot7 = PROT_CH;
	for (i=0; i<2; i++) {
		printf("%i %02x\n", i, bin[i]);
	}
	writehex(str, bin, 2);
	printf("test %s\n", str);
	unsigned char bin2[2];
	char prot8 = PROT_CH;
	readhex(bin2, str);
	for (i=0; i<2; i++) {
		printf("%i %02x %s\n", i, bin2[i], (bin2[i] == bin0[i])?"good":"FAIL");
	}
	for (i=0; i<2; i++) {
		printf("%i %02x\n", i, bin0[i]);
	}
	if (prot1 != PROT_CH) printf("prot1 corrupt\n");
	if (prot2 != PROT_CH) printf("prot2 corrupt\n");
	if (prot3 != PROT_CH) printf("prot3 corrupt\n");
	if (prot4 != PROT_CH) printf("prot4 corrupt\n");
	if (prot5 != PROT_CH) printf("prot5 corrupt\n");
	if (prot6 != PROT_CH) printf("prot6 corrupt\n");
	if (prot7 != PROT_CH) printf("prot7 corrupt\n");
	if (prot8 != PROT_CH) printf("prot8 corrupt\n");
	printf("test done\n");
}

int main(int argc, char**argv) {
	printf("main start\n");
	if (argc == 1) {
		printf("provide command\n");
		return 0;
	} else if (0 == strcmp(argv[1], "testhex")) {
		testhex();
	} else if (0 == strcmp(argv[1], "exchange")) {
		exchange(argv[2], argv[3]);
	}
	printf("main done\n");
}
