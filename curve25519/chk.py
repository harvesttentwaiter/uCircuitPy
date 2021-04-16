#from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
#from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import binascii
#import bytearray
import sys
def main():
	if sys.argv[1] == 'exchange':
		exchange()

def exchange():
	mySec = X25519PrivateKey.from_private_bytes(bytearray.fromhex(sys.argv[2]))
	peerPub = X25519PublicKey.from_public_bytes(bytearray.fromhex(sys.argv[3]))
	shared = mySec.exchange(peerPub)
	print(binascii.hexlify(shared))
	

if __name__ == "__main__":
	main()
	
'''
Traceback (most recent call last):
  File "/home/binkyWinky/25519/chk.py", line 20, in <module>
    main()
  File "/home/binkyWinky/25519/chk.py", line 10, in main
    exchange()
  File "/home/binkyWinky/25519/chk.py", line 14, in exchange
    peerPub = X25519PublicKey.from_public_bytes(bytearray.fromhex(sys.argv[3]))
  File "/usr/lib64/python3.9/site-packages/cryptography/hazmat/primitives/asymmetric/x25519.py", line 26, in from_public_bytes
    return backend.x25519_load_public_bytes(data)
  File "/usr/lib64/python3.9/site-packages/cryptography/hazmat/backends/openssl/backend.py", line 2277, in x25519_load_public_bytes
    res = self._lib.EVP_PKEY_set1_tls_encodedpoint(
TypeError: initializer for ctype 'unsigned char *' must be a cdata pointer, not bytearray



# Generate a private key for use in the exchange.
private_key = X25519PrivateKey.generate()
# In a real handshake the peer_public_key will be received from the
# other party. For this example we'll generate another private key and
# get a public key from that. Note that in a DH handshake both peers
# must agree on a common set of parameters.
peer_public_key = X25519PrivateKey.generate().public_key()
shared_key = private_key.exchange(peer_public_key)
# Perform key derivation.
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
).derive(shared_key)
# For the next handshake we MUST generate another private key.
private_key_2 = X25519PrivateKey.generate()
peer_public_key_2 = X25519PrivateKey.generate().public_key()
shared_key_2 = private_key_2.exchange(peer_public_key_2)
derived_key_2 = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
).derive(shared_key_2)
'''
