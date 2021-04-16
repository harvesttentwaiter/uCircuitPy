#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "curve25519.h"


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
	FILE *fptr = fopen("/dev/urandom", "rb");
	char sec[CURVE25519_KEY_SIZE];
	fread(sec, CURVE25519_KEY_SIZE, 1, fptr);
	fclose(fptr);
	curve25519_clamp_secret(sec);
	
	char secStr[2*CURVE25519_KEY_SIZE+1];
	writehex(secStr, sec, CURVE25519_KEY_SIZE);
	printf("sec %s\n",secStr);
	
	char pub[CURVE25519_KEY_SIZE];
	curve25519_generate_public(pub, sec);
	char pubStr[2*CURVE25519_KEY_SIZE+1];
	writehex(pubStr, pub, CURVE25519_KEY_SIZE);
	printf("pub %s\n", pubStr);
}
#define PROT_VAL 0x6d30243e
void exchange(char *mySecStr, char *peerPubStr, char *out) {
	int prot1 = PROT_VAL;
	char mySec[CURVE25519_KEY_SIZE];
	int prot2 = PROT_VAL;
	readhex(mySec, mySecStr);
	char peerPub[CURVE25519_KEY_SIZE];
	int prot3 = PROT_VAL;
	readhex(peerPub, peerPubStr);
	char shared[CURVE25519_KEY_SIZE];
	int prot4 = PROT_VAL;
	curve25519(shared, mySec, peerPub);
	char sharedStr[2*CURVE25519_KEY_SIZE+1];
	if (out != NULL) {
		writehex(out, shared, CURVE25519_KEY_SIZE);
		return;
	}
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

void test() {
	char shared[65];
	shared[64]='\0';
	const char *a1 = "604fcd2580d18ec6e9391a8c1ca7f855a68e560633ec3e3ca10ce1a15a52f84c";
	const char *a2 = "5669be909a1522fb9891383d335b498f4ee79e6943c826b3538270ccb1e47f57";
	const char *b1 = "c892bb10a8bf3531fedb773cc650f5fb02294a27dc53ad441e791856bee82649";
	const char *b2 = "37dd28bd0a4f76d814cee9d67f3a533f71a1d55737cf593c11a0eaceddf9f471";
	const char *gold = "388b1d04fb3c4e0f8a86c4d392c90b1bf0bcbce134d10330133de22a81cde42d";
	exchange(a1, a2, shared);
	if (0 == strcmp(shared, gold)) {
		printf("set:a pass\n");
	} else {
		printf("set:a fail %s\n", shared);
	}
	exchange(b1, b2, shared);
	if (0 == strcmp(shared, gold)) {
		printf("set:b pass\n");
	} else {
		printf("set:b fail %s\n", shared);
	}
}

int main(int argc, char**argv) {
	printf("main start\n");
	if (argc == 1) {
		printf("provide command\n");
		return 0;
	} else if (0 == strcmp(argv[1], "testhex")) {
		testhex();
	} else if (0 == strcmp(argv[1], "test")) {
		test();
	} else if (0 == strcmp(argv[1], "gen")) {
		gen();
	} else if (0 == strcmp(argv[1], "exchange")) {
		exchange(argv[2], argv[3], NULL);
	}
	printf("main done\n");
}
