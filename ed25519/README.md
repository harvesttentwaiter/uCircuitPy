test2.c has the main candidate code. It's based on orlp's port of the 
supercop ref10 implementation. There doesn't seem to be wide
interoperability between ed25519 implementaitons.

compiled for esp32 and x64

test2_u.py and test2.c have the sample test code

orlp is from
https://github.com/orlp/ed25519.git
commit 7fa6712ef5d581a6981ec2b08ee623314cd1d1c4
Merge: 4d8b564 923d2b4
Author: Orson Peters <orsonpeters@gmail.com>
Date:   Fri Feb 10 20:47:44 2017 +0100

    Merge pull request #13 from radii/constify-ge_precomp
    
    constify ge_precomp

commit 923d2b4abc2edb1db85aac6ef83a02e1d46bebf8

with some minor modification
diff --git a/src/seed.c b/src/seed.c
index 11a2e3e..617865a 100644
--- a/src/seed.c
+++ b/src/seed.c
@@ -24,6 +24,7 @@ int ed25519_create_seed(unsigned char *seed) {
 
     CryptReleaseContext(prov, 0);
 #else
+/*
     FILE *f = fopen("/dev/urandom", "rb");
 
     if (f == NULL) {
@@ -31,7 +32,7 @@ int ed25519_create_seed(unsigned char *seed) {
     }
 
     fread(seed, 1, 32, f);
-    fclose(f);
+    fclose(f); // */
 #endif
 
     return 0;
