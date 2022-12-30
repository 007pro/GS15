from Cryptodome.Util.number import getPrime, getRandomInteger, getRandomNBitInteger, inverse

def expRapide(a, exposant, modulo) :
    res = 1
    while(exposant>0) :
        if((exposant%2)==1) :
            res = (res * a)%modulo
        exposant=exposant//2
        a = (a*a)%modulo
    return res

# Diffie-Hellman Key Exchange
def diffhell(privA, pubB, p):
    sharedKey = expRapide(pubB, privA, p)
    print(sharedKey)
    return sharedKey

def rsaParam() :
    # Choose two large prime numbers
    p = getPrime(1024)
    q = getPrime(1024)

    # Calculate n and phi
    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose a public exponent e
    e = 65537

    # Calculate the private exponent d
    d = inverse(e, phi)

    # Construct the public and private keys
    public_key = (n, e)
    private_key = (n, d)

    print(public_key)
    print(private_key)

def rsaSign() :
    a = 1

# f = open("keys.txt", "w")
# f.write(private_key)
# f.close()
