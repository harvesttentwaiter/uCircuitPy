## Replace import copy
def _copy(a):
	out=[]
	for i in a:
		out.append(i)
	return out
	
# The MIT License (MIT)
#
# Copyright (c) 2014 Richard Moore
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# This is a pure-Python implementation of the AES algorithm and AES common
# modes of operation.

# See: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard

# Honestly, the best description of the modes of operations are the wonderful
# diagrams on Wikipedia. They explain in moments what my words could never
# achieve. Hence the inline documentation here is sparer than I'd prefer.
# See: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation

# Also useful, PyCrypto, a crypto library implemented in C with Python bindings:
# https://www.dlitz.net/software/pycrypto/


# Supported key sizes:
#   128-bit
#   192-bit
#   256-bit


# Supported modes of operation:
#   ECB - Electronic Codebook
#   CBC - Cipher-Block Chaining
#   CFB - Cipher Feedback
#   OFB - Output Feedback
#   CTR - Counter


# See the README.md for API details and general information.


##import copy
import struct

__all__ = ["AES", "AESModeOfOperationCTR", "AESModeOfOperationCBC", "AESModeOfOperationCFB",
           "AESModeOfOperationECB", "AESModeOfOperationOFB", "AESModesOfOperation", "Counter"]


def _compact_word(word):
    return (word[0] << 24) | (word[1] << 16) | (word[2] << 8) | word[3]

def _string_to_bytes(text):
    return list(ord(c) for c in text)

def _bytes_to_string(binary):
    return "".join(chr(b) for b in binary)

def _concat_list(a, b):
    return a + b


# Python 3 compatibility
try:
    xrange
except Exception:
    xrange = range

    # Python 3 supports bytes, which is already an array of integers
    def _string_to_bytes(text):
        if isinstance(text, bytes):
            return text
        return [ord(c) for c in text]

    # In Python 3, we return bytes
    def _bytes_to_string(binary):
        return bytes(binary)

    # Python 3 cannot concatenate a list onto a bytes, so we bytes-ify it first
    def _concat_list(a, b):
        return a + bytes(b)


# Based *largely* on the Rijndael implementation
# See: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf

## Moved tables to file
T1f=0;T2f=1;T3f=2;T4f=3 # Transformations for encryption
T5f=4;T6f=5;T7f=6;T8f=7 # Transformations for decryption
U1f=8;U2f=9;U3f=10;U4f=11 # Transformations for decryption key expansion
_vh=open('pyaes2.dat','rb')
def _v(tbl,idx):
	# TODO lock
    _vh.seek(256*4*tbl + 4*idx)
    out = struct.unpack('<I', _vh.read(4))[0]
    # TODO unlock
    return out

class AES(object):
    '''Encapsulates the AES block cipher.

    You generally should not need this. Use the AESModeOfOperation classes
    below instead.'''

    # Number of rounds by keysize
    number_of_rounds = {16: 10, 24: 12, 32: 14}

    # Round constant words
    rcon = [ 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91 ]

    # S-box and Inverse S-box (S is for Substitution)
    S = [ 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 ]
    Si =[ 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d ] 

		
    def __init__(self, key):
        if len(key) not in (16, 24, 32):
            raise ValueError('Invalid key size')

        rounds = self.number_of_rounds[len(key)]

        # Encryption round keys
        self._Ke = [[0] * 4 for i in xrange(rounds + 1)]

        # Decryption round keys
        self._Kd = [[0] * 4 for i in xrange(rounds + 1)]

        round_key_count = (rounds + 1) * 4
        KC = len(key) // 4

        # Convert the key into ints
        tk = [ struct.unpack('>i', key[i:i + 4])[0] for i in xrange(0, len(key), 4) ]

        # Copy values into round key arrays
        for i in xrange(0, KC):
            self._Ke[i // 4][i % 4] = tk[i]
            self._Kd[rounds - (i // 4)][i % 4] = tk[i]

        # Key expansion (fips-197 section 5.2)
        rconpointer = 0
        t = KC
        while t < round_key_count:

            tt = tk[KC - 1]
            tk[0] ^= ((self.S[(tt >> 16) & 0xFF] << 24) ^
                      (self.S[(tt >>  8) & 0xFF] << 16) ^
                      (self.S[ tt        & 0xFF] <<  8) ^
                       self.S[(tt >> 24) & 0xFF]        ^
                      (self.rcon[rconpointer] << 24))
            rconpointer += 1

            if KC != 8:
                for i in xrange(1, KC):
                    tk[i] ^= tk[i - 1]

            # Key expansion for 256-bit keys is "slightly different" (fips-197)
            else:
                for i in xrange(1, KC // 2):
                    tk[i] ^= tk[i - 1]
                tt = tk[KC // 2 - 1]

                tk[KC // 2] ^= (self.S[ tt        & 0xFF]        ^
                               (self.S[(tt >>  8) & 0xFF] <<  8) ^
                               (self.S[(tt >> 16) & 0xFF] << 16) ^
                               (self.S[(tt >> 24) & 0xFF] << 24))

                for i in xrange(KC // 2 + 1, KC):
                    tk[i] ^= tk[i - 1]

            # Copy values into round key arrays
            j = 0
            while j < KC and t < round_key_count:
                self._Ke[t // 4][t % 4] = tk[j]
                self._Kd[rounds - (t // 4)][t % 4] = tk[j]
                j += 1
                t += 1

        # Inverse-Cipher-ify the decryption round key (fips-197 section 5.3)
        for r in xrange(1, rounds):
            for j in xrange(0, 4):
                tt = self._Kd[r][j]
                self._Kd[r][j] = (_v(U1f,(tt >> 24) & 0xFF) ^
                                  _v(U2f,(tt >> 16) & 0xFF) ^
                                  _v(U3f,(tt >>  8) & 0xFF) ^
                                  _v(U4f, tt        & 0xFF))

    def encrypt(self, plaintext):
        'Encrypt a block of plain text using the AES block cipher.'

        if len(plaintext) != 16:
            raise ValueError('wrong block length')

        rounds = len(self._Ke) - 1
        (s1, s2, s3) = [1, 2, 3]
        a = [0, 0, 0, 0]

        # Convert plaintext to (ints ^ key)
        t = [(_compact_word(plaintext[4 * i:4 * i + 4]) ^ self._Ke[0][i]) for i in xrange(0, 4)]

        # Apply round transforms
        for r in xrange(1, rounds):
            for i in xrange(0, 4):
                a[i] = (_v(T1f,(t[ i          ] >> 24) & 0xFF) ^
                        _v(T2f,(t[(i + s1) % 4] >> 16) & 0xFF) ^
                        _v(T3f,(t[(i + s2) % 4] >>  8) & 0xFF) ^
                        _v(T4f, t[(i + s3) % 4]        & 0xFF) ^
                        self._Ke[r][i])
            t = _copy(a)

        # The last round is special
        result = [ ]
        for i in xrange(0, 4):
            tt = self._Ke[rounds][i]
            result.append((self.S[(t[ i           ] >> 24) & 0xFF] ^ (tt >> 24)) & 0xFF)
            result.append((self.S[(t[(i + s1) % 4] >> 16) & 0xFF] ^ (tt >> 16)) & 0xFF)
            result.append((self.S[(t[(i + s2) % 4] >>  8) & 0xFF] ^ (tt >>  8)) & 0xFF)
            result.append((self.S[ t[(i + s3) % 4]        & 0xFF] ^  tt       ) & 0xFF)

        return result

    def decrypt(self, ciphertext):
        'Decrypt a block of cipher text using the AES block cipher.'

        if len(ciphertext) != 16:
            raise ValueError('wrong block length')

        rounds = len(self._Kd) - 1
        (s1, s2, s3) = [3, 2, 1]
        a = [0, 0, 0, 0]

        # Convert ciphertext to (ints ^ key)
        t = [(_compact_word(ciphertext[4 * i:4 * i + 4]) ^ self._Kd[0][i]) for i in xrange(0, 4)]

        # Apply round transforms
        for r in xrange(1, rounds):
            for i in xrange(0, 4):
                a[i] = (_v(T5f,(t[ i          ] >> 24) & 0xFF) ^
                        _v(T6f,(t[(i + s1) % 4] >> 16) & 0xFF) ^
                        _v(T7f,(t[(i + s2) % 4] >>  8) & 0xFF) ^
                        _v(T8f, t[(i + s3) % 4]        & 0xFF) ^
                        self._Kd[r][i])
            t = _copy(a)

        # The last round is special
        result = [ ]
        for i in xrange(0, 4):
            tt = self._Kd[rounds][i]
            result.append((self.Si[(t[ i           ] >> 24) & 0xFF] ^ (tt >> 24)) & 0xFF)
            result.append((self.Si[(t[(i + s1) % 4] >> 16) & 0xFF] ^ (tt >> 16)) & 0xFF)
            result.append((self.Si[(t[(i + s2) % 4] >>  8) & 0xFF] ^ (tt >>  8)) & 0xFF)
            result.append((self.Si[ t[(i + s3) % 4]        & 0xFF] ^  tt       ) & 0xFF)

        return result


class Counter(object):
    '''A counter object for the Counter (CTR) mode of operation.

       To create a custom counter, you can usually just override the
       increment method.'''

    def __init__(self, initial_value = 1):

        # Convert the value into an array of bytes long
        self._counter = [ ((initial_value >> i) % 256) for i in xrange(128 - 8, -1, -8) ]

    value = property(lambda s: s._counter)

    def increment(self):
        '''Increment the counter (overflow rolls back to 0).'''

        for i in xrange(len(self._counter) - 1, -1, -1):
            self._counter[i] += 1

            if self._counter[i] < 256: break

            # Carry the one
            self._counter[i] = 0

        # Overflow
        else:
            self._counter = [ 0 ] * len(self._counter)


class AESBlockModeOfOperation(object):
    '''Super-class for AES modes of operation that require blocks.'''
    def __init__(self, key):
        self._aes = AES(key)

    def decrypt(self, ciphertext):
        raise Exception('not implemented')

    def encrypt(self, plaintext):
        raise Exception('not implemented')


class AESStreamModeOfOperation(AESBlockModeOfOperation):
    '''Super-class for AES modes of operation that are stream-ciphers.'''

class AESSegmentModeOfOperation(AESStreamModeOfOperation):
    '''Super-class for AES modes of operation that segment data.'''

    segment_bytes = 16



class AESModeOfOperationECB(AESBlockModeOfOperation):
    '''AES Electronic Codebook Mode of Operation.

       o Block-cipher, so data must be padded to 16 byte boundaries

   Security Notes:
       o This mode is not recommended
       o Any two identical blocks produce identical encrypted values,
         exposing data patterns. (See the image of Tux on wikipedia)

   Also see:
       o https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_.28ECB.29
       o See NIST SP800-38A (http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf); section 6.1'''


    name = "Electronic Codebook (ECB)"

    def encrypt(self, plaintext):
        if len(plaintext) != 16:
            raise ValueError('plaintext block must be 16 bytes')

        plaintext = _string_to_bytes(plaintext)
        return _bytes_to_string(self._aes.encrypt(plaintext))

    def decrypt(self, ciphertext):
        if len(ciphertext) != 16:
            raise ValueError('ciphertext block must be 16 bytes')

        ciphertext = _string_to_bytes(ciphertext)
        return _bytes_to_string(self._aes.decrypt(ciphertext))



class AESModeOfOperationCBC(AESBlockModeOfOperation):
    '''AES Cipher-Block Chaining Mode of Operation.

       o The Initialization Vector (IV)
       o Block-cipher, so data must be padded to 16 byte boundaries
       o An incorrect initialization vector will only cause the first
         block to be corrupt; all other blocks will be intact
       o A corrupt bit in the cipher text will cause a block to be
         corrupted, and the next block to be inverted, but all other
         blocks will be intact.

   Security Notes:
       o This method (and CTR) ARE recommended.

   Also see:
       o https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher-block_chaining_.28CBC.29
       o See NIST SP800-38A (http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf); section 6.2'''


    name = "Cipher-Block Chaining (CBC)"

    def __init__(self, key, iv = None):
        if iv is None:
            self._last_cipherblock = [ 0 ] * 16
        elif len(iv) != 16:
            raise ValueError('initialization vector must be 16 bytes')
        else:
            self._last_cipherblock = _string_to_bytes(iv)

        AESBlockModeOfOperation.__init__(self, key)

    def encrypt(self, plaintext):
        if len(plaintext) != 16:
            raise ValueError('plaintext block must be 16 bytes')

        plaintext = _string_to_bytes(plaintext)
        precipherblock = [ (p ^ l) for (p, l) in zip(plaintext, self._last_cipherblock) ]
        self._last_cipherblock = self._aes.encrypt(precipherblock)

        return _bytes_to_string(self._last_cipherblock)

    def decrypt(self, ciphertext):
        if len(ciphertext) != 16:
            raise ValueError('ciphertext block must be 16 bytes')

        cipherblock = _string_to_bytes(ciphertext)
        plaintext = [ (p ^ l) for (p, l) in zip(self._aes.decrypt(cipherblock), self._last_cipherblock) ]
        self._last_cipherblock = cipherblock

        return _bytes_to_string(plaintext)



class AESModeOfOperationCFB(AESSegmentModeOfOperation):
    '''AES Cipher Feedback Mode of Operation.

       o A stream-cipher, so input does not need to be padded to blocks,
         but does need to be padded to segment_size

    Also see:
       o https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_feedback_.28CFB.29
       o See NIST SP800-38A (http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf); section 6.3'''


    name = "Cipher Feedback (CFB)"

    def __init__(self, key, iv, segment_size = 1):
        if segment_size == 0: segment_size = 1

        if iv is None:
            self._shift_register = [ 0 ] * 16
        elif len(iv) != 16:
            raise ValueError('initialization vector must be 16 bytes')
        else:
          self._shift_register = _string_to_bytes(iv)

        self._segment_bytes = segment_size

        AESBlockModeOfOperation.__init__(self, key)

    segment_bytes = property(lambda s: s._segment_bytes)

    def encrypt(self, plaintext):
        if len(plaintext) % self._segment_bytes != 0:
            raise ValueError('plaintext block must be a multiple of segment_size')

        plaintext = _string_to_bytes(plaintext)

        # Break block into segments
        encrypted = [ ]
        for i in xrange(0, len(plaintext), self._segment_bytes):
            plaintext_segment = plaintext[i: i + self._segment_bytes]
            xor_segment = self._aes.encrypt(self._shift_register)[:len(plaintext_segment)]
            cipher_segment = [ (p ^ x) for (p, x) in zip(plaintext_segment, xor_segment) ]

            # Shift the top bits out and the ciphertext in
            self._shift_register = _concat_list(self._shift_register[len(cipher_segment):], cipher_segment)

            encrypted.extend(cipher_segment)

        return _bytes_to_string(encrypted)

    def decrypt(self, ciphertext):
        if len(ciphertext) % self._segment_bytes != 0:
            raise ValueError('ciphertext block must be a multiple of segment_size')

        ciphertext = _string_to_bytes(ciphertext)

        # Break block into segments
        decrypted = [ ]
        for i in xrange(0, len(ciphertext), self._segment_bytes):
            cipher_segment = ciphertext[i: i + self._segment_bytes]
            xor_segment = self._aes.encrypt(self._shift_register)[:len(cipher_segment)]
            plaintext_segment = [ (p ^ x) for (p, x) in zip(cipher_segment, xor_segment) ]

            # Shift the top bits out and the ciphertext in
            self._shift_register = _concat_list(self._shift_register[len(cipher_segment):], cipher_segment)

            decrypted.extend(plaintext_segment)

        return _bytes_to_string(decrypted)



class AESModeOfOperationOFB(AESStreamModeOfOperation):
    '''AES Output Feedback Mode of Operation.

       o A stream-cipher, so input does not need to be padded to blocks,
         allowing arbitrary length data.
       o A bit twiddled in the cipher text, twiddles the same bit in the
         same bit in the plain text, which can be useful for error
         correction techniques.

    Also see:
       o https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Output_feedback_.28OFB.29
       o See NIST SP800-38A (http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf); section 6.4'''


    name = "Output Feedback (OFB)"

    def __init__(self, key, iv = None):
        if iv is None:
            self._last_precipherblock = [ 0 ] * 16
        elif len(iv) != 16:
            raise ValueError('initialization vector must be 16 bytes')
        else:
          self._last_precipherblock = _string_to_bytes(iv)

        self._remaining_block = [ ]

        AESBlockModeOfOperation.__init__(self, key)

    def encrypt(self, plaintext):
        encrypted = [ ]
        for p in _string_to_bytes(plaintext):
            if len(self._remaining_block) == 0:
                self._remaining_block = self._aes.encrypt(self._last_precipherblock)
                self._last_precipherblock = [ ]
            precipherbyte = self._remaining_block.pop(0)
            self._last_precipherblock.append(precipherbyte)
            cipherbyte = p ^ precipherbyte
            encrypted.append(cipherbyte)

        return _bytes_to_string(encrypted)

    def decrypt(self, ciphertext):
        # AES-OFB is symetric
        return self.encrypt(ciphertext)



class AESModeOfOperationCTR(AESStreamModeOfOperation):
    '''AES Counter Mode of Operation.

       o A stream-cipher, so input does not need to be padded to blocks,
         allowing arbitrary length data.
       o The counter must be the same size as the key size (ie. len(key))
       o Each block independant of the other, so a corrupt byte will not
         damage future blocks.
       o Each block has a uniue counter value associated with it, which
         contributes to the encrypted value, so no data patterns are
         leaked.
       o Also known as: Counter Mode (CM), Integer Counter Mode (ICM) and
         Segmented Integer Counter (SIC

   Security Notes:
       o This method (and CBC) ARE recommended.
       o Each message block is associated with a counter value which must be
         unique for ALL messages with the same key. Otherwise security may be
         compromised.

    Also see:

       o https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_.28CTR.29
       o See NIST SP800-38A (http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf); section 6.5
         and Appendix B for managing the initial counter'''


    name = "Counter (CTR)"

    def __init__(self, key, counter = None):
        AESBlockModeOfOperation.__init__(self, key)

        if counter is None:
            counter = Counter()

        self._counter = counter
        self._remaining_counter = [ ]

    def encrypt(self, plaintext):
        while len(self._remaining_counter) < len(plaintext):
            self._remaining_counter += self._aes.encrypt(self._counter.value)
            self._counter.increment()

        plaintext = _string_to_bytes(plaintext)

        encrypted = [ (p ^ c) for (p, c) in zip(plaintext, self._remaining_counter) ]
        self._remaining_counter = self._remaining_counter[len(encrypted):]

        return _bytes_to_string(encrypted)

    def decrypt(self, crypttext):
        # AES-CTR is symetric
        return self.encrypt(crypttext)


# Simple lookup table for each mode
AESModesOfOperation = dict(
    ctr = AESModeOfOperationCTR,
    cbc = AESModeOfOperationCBC,
    cfb = AESModeOfOperationCFB,
    ecb = AESModeOfOperationECB,
    ofb = AESModeOfOperationOFB,
)
# The MIT License (MIT)
#
# Copyright (c) 2014 Richard Moore
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.


##from .aes import AESBlockModeOfOperation, AESSegmentModeOfOperation, AESStreamModeOfOperation
##from .util import append_PKCS7_padding, strip_PKCS7_padding, to_bufferable


# First we inject three functions to each of the modes of operations
#
#    _can_consume(size)
#       - Given a size, determine how many bytes could be consumed in
#         a single call to either the decrypt or encrypt method
#
#    _final_encrypt(data, padding = PADDING_DEFAULT)
#       - call and return encrypt on this (last) chunk of data,
#         padding as necessary; this will always be at least 16
#         bytes unless the total incoming input was less than 16
#         bytes
#
#    _final_decrypt(data, padding = PADDING_DEFAULT)
#       - same as _final_encrypt except for decrypt, for
#         stripping off padding
#

PADDING_NONE       = 'none'
PADDING_DEFAULT    = 'default'

# @TODO: Ciphertext stealing and explicit PKCS#7
# PADDING_CIPHERTEXT_STEALING
# PADDING_PKCS7

# ECB and CBC are block-only ciphers

def _block_can_consume(self, size):
    if size >= 16: return 16
    return 0

# After padding, we may have more than one block
def _block_final_encrypt(self, data, padding = PADDING_DEFAULT):
    if padding == PADDING_DEFAULT:
        data = append_PKCS7_padding(data)

    elif padding == PADDING_NONE:
        if len(data) != 16:
            raise Exception('invalid data length for final block')
    else:
        raise Exception('invalid padding option')

    if len(data) == 32:
        return self.encrypt(data[:16]) + self.encrypt(data[16:])

    return self.encrypt(data)


def _block_final_decrypt(self, data, padding = PADDING_DEFAULT):
    if padding == PADDING_DEFAULT:
        return strip_PKCS7_padding(self.decrypt(data))

    if padding == PADDING_NONE:
        if len(data) != 16:
            raise Exception('invalid data length for final block')
        return self.decrypt(data)

    raise Exception('invalid padding option')

AESBlockModeOfOperation._can_consume = _block_can_consume
AESBlockModeOfOperation._final_encrypt = _block_final_encrypt
AESBlockModeOfOperation._final_decrypt = _block_final_decrypt



# CFB is a segment cipher

def _segment_can_consume(self, size):
    return self.segment_bytes * int(size // self.segment_bytes)

# CFB can handle a non-segment-sized block at the end using the remaining cipherblock
def _segment_final_encrypt(self, data, padding = PADDING_DEFAULT):
    if padding != PADDING_DEFAULT:
        raise Exception('invalid padding option')

    faux_padding = (chr(0) * (self.segment_bytes - (len(data) % self.segment_bytes)))
    padded = data + to_bufferable(faux_padding)
    return self.encrypt(padded)[:len(data)]

# CFB can handle a non-segment-sized block at the end using the remaining cipherblock
def _segment_final_decrypt(self, data, padding = PADDING_DEFAULT):
    if padding != PADDING_DEFAULT:
        raise Exception('invalid padding option')

    faux_padding = (chr(0) * (self.segment_bytes - (len(data) % self.segment_bytes)))
    padded = data + to_bufferable(faux_padding)
    return self.decrypt(padded)[:len(data)]

AESSegmentModeOfOperation._can_consume = _segment_can_consume
AESSegmentModeOfOperation._final_encrypt = _segment_final_encrypt
AESSegmentModeOfOperation._final_decrypt = _segment_final_decrypt



# OFB and CTR are stream ciphers

def _stream_can_consume(self, size):
    return size

def _stream_final_encrypt(self, data, padding = PADDING_DEFAULT):
    if padding not in [PADDING_NONE, PADDING_DEFAULT]:
        raise Exception('invalid padding option')

    return self.encrypt(data)

def _stream_final_decrypt(self, data, padding = PADDING_DEFAULT):
    if padding not in [PADDING_NONE, PADDING_DEFAULT]:
        raise Exception('invalid padding option')

    return self.decrypt(data)

AESStreamModeOfOperation._can_consume = _stream_can_consume
AESStreamModeOfOperation._final_encrypt = _stream_final_encrypt
AESStreamModeOfOperation._final_decrypt = _stream_final_decrypt



class BlockFeeder(object):
    '''The super-class for objects to handle chunking a stream of bytes
       into the appropriate block size for the underlying mode of operation
       and applying (or stripping) padding, as necessary.'''

    def __init__(self, mode, feed, final, padding = PADDING_DEFAULT):
        self._mode = mode
        self._feed = feed
        self._final = final
        self._buffer = to_bufferable("")
        self._padding = padding

    def feed(self, data = None):
        '''Provide bytes to encrypt (or decrypt), returning any bytes
           possible from this or any previous calls to feed.

           Call with None or an empty string to flush the mode of
           operation and return any final bytes; no further calls to
           feed may be made.'''

        if self._buffer is None:
            raise ValueError('already finished feeder')

        # Finalize; process the spare bytes we were keeping
        if data is None:
            result = self._final(self._buffer, self._padding)
            self._buffer = None
            return result

        self._buffer += to_bufferable(data)

        # We keep 16 bytes around so we can determine padding
        result = to_bufferable('')
        while len(self._buffer) > 16:
            can_consume = self._mode._can_consume(len(self._buffer) - 16)
            if can_consume == 0: break
            result += self._feed(self._buffer[:can_consume])
            self._buffer = self._buffer[can_consume:]

        return result


class Encrypter(BlockFeeder):
    'Accepts bytes of plaintext and returns encrypted ciphertext.'

    def __init__(self, mode, padding = PADDING_DEFAULT):
        BlockFeeder.__init__(self, mode, mode.encrypt, mode._final_encrypt, padding)


class Decrypter(BlockFeeder):
    'Accepts bytes of ciphertext and returns decrypted plaintext.'

    def __init__(self, mode, padding = PADDING_DEFAULT):
        BlockFeeder.__init__(self, mode, mode.decrypt, mode._final_decrypt, padding)


# 8kb blocks
BLOCK_SIZE = (1 << 13)

def _feed_stream(feeder, in_stream, out_stream, block_size = BLOCK_SIZE):
    'Uses feeder to read and convert from in_stream and write to out_stream.'

    while True:
        chunk = in_stream.read(block_size)
        if not chunk:
            break
        converted = feeder.feed(chunk)
        out_stream.write(converted)
    converted = feeder.feed()
    out_stream.write(converted)


def encrypt_stream(mode, in_stream, out_stream, block_size = BLOCK_SIZE, padding = PADDING_DEFAULT):
    'Encrypts a stream of bytes from in_stream to out_stream using mode.'

    encrypter = Encrypter(mode, padding = padding)
    _feed_stream(encrypter, in_stream, out_stream, block_size)


def decrypt_stream(mode, in_stream, out_stream, block_size = BLOCK_SIZE, padding = PADDING_DEFAULT):
    'Decrypts a stream of bytes from in_stream to out_stream using mode.'

    decrypter = Decrypter(mode, padding = padding)
    _feed_stream(decrypter, in_stream, out_stream, block_size)
# The MIT License (MIT)
#
# Copyright (c) 2014 Richard Moore
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# Why to_bufferable?
# Python 3 is very different from Python 2.x when it comes to strings of text
# and strings of bytes; in Python 3, strings of bytes do not exist, instead to
# represent arbitrary binary data, we must use the "bytes" object. This method
# ensures the object behaves as we need it to.

def to_bufferable(binary):
    return binary

def _get_byte(c):
    return ord(c)

try:
    xrange
except:

    def to_bufferable(binary):
        if isinstance(binary, bytes):
            return binary
        return bytes(ord(b) for b in binary)

    def _get_byte(c):
        return c

def append_PKCS7_padding(data):
    pad = 16 - (len(data) % 16)
    return data + to_bufferable(chr(pad) * pad)

def strip_PKCS7_padding(data):
    if len(data) % 16 != 0:
        raise ValueError("invalid length")

    pad = _get_byte(data[-1])

    if pad > 16:
        raise ValueError("invalid padding byte")

    return data[:-pad]
