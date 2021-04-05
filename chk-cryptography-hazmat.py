#import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
key = b'\x99\xb0F%h\xc2\xae\x89j\xaf\r\xbcD\xb4\x0f\x16\xd5f\x93v~\x9fR\xd8U:a\xf5\x02\xadBN' #os.urandom(32)
iv = b'\xd1\xb9\x90\x03\xc3\xa9C\xb4\xb6W8\xf6 /=\x7f' #os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
encryptor = cipher.encryptor()
pt=b"a secret message"
ctNow = encryptor.update(pt) + encryptor.finalize()
print('ct',ctNow)
ct=b'\x87\xf3\x93\x0b"\x83\x08\x9a\x02FO\xd2q\xe4\xfdn'
print('ct eq?',ct == ctNow)
decryptor = cipher.decryptor()
ptNow=decryptor.update(ct) + decryptor.finalize()
print('pt eq?',pt == ptNow)


from cryptography.hazmat.primitives import hashes
digest = hashes.Hash(hashes.SHA256())
digest.update(b"abc")
digest.update(b"123")
hashValNow=digest.finalize()
hashVal=b'l\xa1=R\xcap\xc8\x83\xe0\xf0\xbb\x10\x1eBZ\x89\xe8bM\xe5\x1d\xb2\xd29%\x93\xafj\x84\x11\x80\x90'
print('hashVal',hashVal)
print('hashVal eq?', hashVal == hashValNow)
digest2 = hashes.Hash(hashes.SHA256())
digest2.update(b'sha256 uses 512-bit blocks or 64-Bytes, so this is a longer message to check multiblock')
hashVal2Now=digest2.finalize()
print('hashVal2',hashVal2Now)
hashVal2=b'"\x17\xe50%\x9b\x8a\x14\t"\x06\x82\xa2X\xce\xe2\xba9XtC\xa7\xfb"\xae\xf0\xcf,\x12\xc1%\xda'
print('hashVal2 eq?', hashVal2 == hashVal2Now)
