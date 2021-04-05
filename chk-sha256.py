# https://gist.github.com/prokls/41e82472bd4968720d1482f81235e0ac
# 20210404
import sha256

digest = sha256.SHA256()
digest.update(b"abc")
digest.update(b"123")
hashValNow=digest.digest()
hashVal=b'l\xa1=R\xcap\xc8\x83\xe0\xf0\xbb\x10\x1eBZ\x89\xe8bM\xe5\x1d\xb2\xd29%\x93\xafj\x84\x11\x80\x90'
print('hashVal',hashVal)
print('hashVal eq?', hashVal == hashValNow)

digest2 = sha256.SHA256()
digest2.update(b'sha256 uses 512-bit blocks or 64-Bytes, so this is a longer message to check multiblock')
hashVal2Now=digest2.digest()
print('hashVal2',hashVal2Now)
hashVal2=b'"\x17\xe50%\x9b\x8a\x14\t"\x06\x82\xa2X\xce\xe2\xba9XtC\xa7\xfb"\xae\xf0\xcf,\x12\xc1%\xda'
print('hashVal2 eq?', hashVal2 == hashVal2Now)
