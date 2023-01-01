from Cryptodome.Util.number import getPrime, getRandomInteger, getRandomNBitInteger, inverse, long_to_bytes
import hmac

#Exponentiation by squaring
def expRapide(a, exposant, modulo) :
    res = 1
    while(exposant>0) :
        if((exposant%2)==1) :
            res = (res * a)%modulo
        exposant=exposant//2
        a = (a*a)%modulo
    return res

def kdf_sk(sk):
    #Use HKDF to derive the Shared Key into a 32 bytes shared key
    hkdf = hmac.HMAC(key=sk, msg=b'', digestmod='sha256')
    derived_key = hkdf.digest()
    return derived_key[:32]

def kdf_rk(rk, dh_out):
    # Use HKDF to derive two new keys
    hkdf = hmac.HMAC(key=rk, msg=dh_out, digestmod='sha512')
    derived_key = hkdf.digest()
    # Return the first 32 bytes as the root key and the second 32 bytes as the chain key
    return derived_key[:32], derived_key[32:64]

def kdf_ck(ck):
    # Use HKDF to derive two new key from the existing CK
    hkdf = hmac.HMAC(key=ck, msg=b'', digestmod='sha512')
    # Return the first 32 bytes of the derived key as the new CK and the second 32 bytes as the message key
    derived_key = hkdf.digest()
    return derived_key[:32], derived_key[32:64]

#Perform RC4 Encryption and Decryption
def rc4(key, data):
    # Initialize the state with the key
    state = [i for i in range(256)]
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) % 256
        state[i], state[j] = state[j], state[i]

    # Generate the keystream
    i = 0
    j = 0
    keystream = bytearray()
    for _ in range(len(data)):
        i = (i + 1) % 256
        j = (j + state[i]) % 256
        state[i], state[j] = state[j], state[i]
        t = (state[i] + state[j]) % 256
        keystream.append(state[t])

    # XOR the keystream with the data to encrypt or decrypt
    output = bytearray()
    for k, d in zip(keystream, data):
        output.append(k ^ d)

    return bytes(output)

#Generate new Diffie-Hellman key-pair
def GENERATE_DH(g, p):
    privKey = getRandomInteger(2048)
    pubKey = expRapide(g, privKey, p)
    return (privKey, pubKey)

#Diffie-Hellman Key Exchange
def DH(priv, pub, p):
    sharedKey = expRapide(pub, priv, p)
    return sharedKey

#Header class which contains Ratchet public key, previous number of messages and actual number of messages
class Header():
    def __init__(self,dh_pair, pn, n):
        self.dh = dh_pair[1]
        self.pn = pn
        self.n = n

#If the message corresponds to a skipped message key this function decrypts the message, deletes the message key, and returns.
def TrySkippedMessageKeys(state, header, ciphertext):
    if (header.dh, header.n) in state.MKSKIPPED:
        mk = state.MKSKIPPED[header.dh, header.n]
        del state.MKSKIPPED[header.dh, header.n]
        return rc4(mk, ciphertext)
    else:
        return None

def SkipMessageKeys(state, until):
    if state.Nr + 10 < until:   #MAX_SKIP = 10
        raise Error()
    if state.CKr != None:
        while state.Nr < until:
            state.CKr, mk = kdf_ck(state.CKr)
            state.MKSKIPPED[state.DHr, state.Nr] = mk
            state.Nr += 1

#Performs a symmetric-key ratchet step to derive the relevant message key and next chain key, and decrypts the message
def DHRatchet(state, header,g , p):
    state.PN = state.Ns
    state.Ns = 0
    state.Nr = 0
    state.DHr = header.dh
    state.RK, state.CKr = kdf_rk(state.RK, long_to_bytes(DH(state.DHs[0], state.DHr, p)))
    state.DHs = GENERATE_DH(g , p)
    state.RK, state.CKs = kdf_rk(state.RK, long_to_bytes(DH(state.DHs[0], state.DHr, p)))
