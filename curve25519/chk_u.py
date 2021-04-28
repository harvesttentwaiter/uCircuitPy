import curve25519
import ubinascii
a1=ubinascii.unhexlify("604fcd2580d18ec6e9391a8c1ca7f855a68e560633ec3e3ca10ce1a15a52f84c")
a2=ubinascii.unhexlify("5669be909a1522fb9891383d335b498f4ee79e6943c826b3538270ccb1e47f57")
b1=ubinascii.unhexlify("c892bb10a8bf3531fedb773cc650f5fb02294a27dc53ad441e791856bee82649")
b2=ubinascii.unhexlify("37dd28bd0a4f76d814cee9d67f3a533f71a1d55737cf593c11a0eaceddf9f471")
gold=ubinascii.unhexlify("388b1d04fb3c4e0f8a86c4d392c90b1bf0bcbce134d10330133de22a81cde42d")

'''
clamp
	secret[0] &= 248;
	secret[31] = (secret[31] & 127) | 64;
'''

# a1[sec] => b2[pub]
pub=curve25519.genpub(b1)
print(pub)
if pub!= a2:
	print('b1 [sec] does not make a2 [pub]')

shared=curve25519.exchange(a1, a2);
print(shared)
if gold!=shared:
	print('fail')
else:
	print('good')
