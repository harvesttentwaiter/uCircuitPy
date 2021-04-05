import pyaes2 as aesPkg

key = b'\x99\xb0F%h\xc2\xae\x89j\xaf\r\xbcD\xb4\x0f\x16\xd5f\x93v~\x9fR\xd8U:a\xf5\x02\xadBN' #os.urandom(32)
iv = b'\xd1\xb9\x90\x03\xc3\xa9C\xb4\xb6W8\xf6 /=\x7f' #os.urandom(16)
keyedCipher  = aesPkg.AESModeOfOperationCBC(key, iv=iv)
keyedCipher2 = aesPkg.AESModeOfOperationCBC(key, iv=iv)

pt=b"a secret message"
ctNow=keyedCipher.encrypt(pt)

ct=b'\x87\xf3\x93\x0b"\x83\x08\x9a\x02FO\xd2q\xe4\xfdn'
print('ct eq?',ct == ctNow)

ptNow = keyedCipher2.decrypt(ct)
print('pt eq?',ct == ctNow)

##import os
#from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
#iv = b'\xd1\xb9\x90\x03\xc3\xa9C\xb4\xb6W8\xf6 /=\x7f' #os.urandom(16)
#cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
#encryptor = cipher.encryptor()
#pt=b"a secret message"
#ctNow = encryptor.update(pt) + encryptor.finalize()
#print('ct',ctNow)
#ct=b'\x87\xf3\x93\x0b"\x83\x08\x9a\x02FO\xd2q\xe4\xfdn'
#decryptor = cipher.decryptor()
#ptNow=decryptor.update(ct) + decryptor.finalize()
#print('pt eq?',pt == ptNow)
