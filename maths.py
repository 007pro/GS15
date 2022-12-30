from Cryptodome.Util.number import getPrime, getRandomInteger, getRandomNBitInteger, inverse, long_to_bytes
import hmac

#Algorithme d'exponentiation rapide
def expRapide(a, exposant, modulo) :
    res = 1
    while(exposant>0) :
        if((exposant%2)==1) :
            res = (res * a)%modulo
        exposant=exposant//2
        a = (a*a)%modulo
    return res

def kdf_rk(rk, dh_out):
    # Use HKDF to derive two new keys from the concatenated bytes
    hkdf = hmac.HMAC(key=rk, msg=dh_out, digestmod='sha512')
    derived_key = hkdf.digest()
    # Return the first 32 bytes as the root key and the second 32 bytes
    # as the chain key
    return derived_key[:32], derived_key[32:64]

def kdf_ck(ck):
    # Use HKDF to derive a new key from the existing CK
    # using a secure hash function (e.g. SHA-256)
    hkdf = hmac.HMAC(key=ck, msg=b'', digestmod='sha512')
    # Return the first 32 bytes of the derived key as the new CK
    derived_key = hkdf.digest()
    return derived_key[:32], derived_key[32:64]


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

def GENERATE_DH(g, p):
    privKey = getRandomInteger(2048)
    pubKey = expRapide(g, privKey, p)
    return (privKey, pubKey)

#Diffie-Hellman Key Exchange
def DH(priv, pub, p):
    sharedKey = expRapide(pub, priv, p)
    return sharedKey

class Header():
    def __init__(self,dh_pair, pn, n):
        self.dh = dh_pair[1]
        self.pn = pn
        self.n = n


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

def DHRatchet(state, header,g , p):
    state.PN = state.Ns
    state.Ns = 0
    state.Nr = 0
    state.DHr = header.dh
    state.RK, state.CKr = kdf_rk(state.RK, long_to_bytes(DH(state.DHs[0], state.DHr, p)))
    state.DHs = GENERATE_DH(g , p)
    state.RK, state.CKs = kdf_rk(state.RK, long_to_bytes(DH(state.DHs[0], state.DHr, p)))