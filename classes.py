from Cryptodome.Util.number import getPrime, getRandomInteger, getRandomNBitInteger, inverse, long_to_bytes, bytes_to_long
from Cryptodome.Hash import SHA256
from maths import expRapide
from os.path import exists
from random import randint
import pickle

class User:

    def __init__(self, uid, g, p):
        self.uid = uid
        self.sharedKeys = {}
        self.generateKeys(g, p)

    def saveUser(self):
        pass

    def generateKeys(self, g, p):
        self.genereateIDKeys(g, p)
        self.generateSigPKeys(g, p)
        self.signKeys()
        self.generateEphKey(g, p)
        self.otPKeys = []
        for i in range(10) :
            self.otPKeys.append(self.generateOtPKeys(g, p))
        self.publishKeys()

    def publishKeys(self):
        with open("serverdata/keys/"+self.uid+".keys","wb") as keys_file :
            keys = {"IDPUB" : self.idpublic_keyDH, "SIGPKPUB" : self.sigpublic_key, "SIG" : self.signature, "OTPK" : self.otPKeys}
            pickle.dump(keys, keys_file)

    def genereateIDKeys(self, g, pDH):
        #RSA Key Pair
        # Choose two large prime numbers
        p = getPrime(2048)
        q = getPrime(2048)

        # Calculate n and phi
        n = p * q
        phi = (p - 1) * (q - 1)

        # Choose a public exponent e
        e = 65537

        # Calculate the private exponent d
        d = inverse(e, phi)

        # Construct the public and private keys
        self.idpublic_key = (n, e)
        self.idprivate_key = (n, d)
        self.idprivate_keyDH = d
        self.idpublic_keyDH = expRapide(g, self.idprivate_keyDH, pDH)
        print("Clé ID généré")

    def generateSigPKeys(self, g, p):
        self.sigprivate_key = getRandomInteger(2048)
        self.sigpublic_key = expRapide(g, self.sigprivate_key, p)
        print("Clé sig généré")

    def signKeys(self):
        hashed_message = bytes_to_long(SHA256.new(long_to_bytes(self.sigpublic_key)).digest())
        signature = expRapide(hashed_message, self.idprivate_key[1], self.idprivate_key[0])
        self.signature = signature

    def generateOtPKeys(self, g, p):
        privotPKey = getRandomInteger(2048)
        pubotPKey = expRapide(g, privotPKey, p)
        print("Clé OT généré")
        return (privotPKey, pubotPKey)

    def generateEphKey(self, g , p):
        self.privEphKey = getRandomInteger(2048)
        self.pubEphKey = expRapide(g, self.privEphKey, p)
        print("Clé eph généré")

    def verifySig(self, pubSigKey, signature, pubIDKey):
        hashed_message = bytes_to_long(SHA256.new(long_to_bytes(pubSigKey)).digest())
        decrypted_sig = expRapide(signature, pubIDKey[1], pubIDKey[0])
        if(decrypted_sig==hashed_message):
            print("Signature correcte")
            return 1
        else:
            print("Signature incorrecte")
            return 0

    def computeFirstSharedKey(self, p, sigPK, idK, otPK):
        dh1 = expRapide(sigPK, self.idprivate_keyDH, p)
        dh2 = expRapide(idK, self.privEphKey, p)
        dh3 = expRapide(sigPK, self.privEphKey, p)
        dh4 = expRapide(otPK, self.privEphKey, p)
        return int(str(dh1)+str(dh2)+str(dh3)+str(dh4))

    def computeSecondSharedKey(self, p, idK, ephK):
        dh1 = expRapide(idK, self.sigprivate_key, p)
        dh2 = expRapide(ephK, self.idprivate_keyDH, p)
        dh3 = expRapide(ephK, self.sigprivate_key, p)
        dh4 = expRapide(ephK, self.privotPKey, p)
        print(dh1,dh2,dh3,dh4,"\n end second")

    def askContact(self, target, g, p):
        self.generateEphKey(g, p)
        chosenNb = randint(0,9)
        req = {"IDPUB": self.idpublic_key, "EPHK": self.pubEphKey, "OTID": chosenNb}
        with open("serverdata/keys/"+target+".keys","rb") as key_file:
            targetKeys = pickle.load(key_file)
        if(self.verifySig(targetKeys["SIGPKPUB"],targetKeys["SIG"],targetKeys["IDPUB"])==1) :
            sk = self.computeFirstSharedKey(p, targetKeys["SIGPKPUB"], targetKeys["IDPUB"], targetKeys["OTPK"][chosenNb][1] )
            self.sharedKeys[target] = sk
            with open("serverdata/keys/"+target+"/"+self.uid+".ask","wb") as ask_file :
                pickle.dump(req, ask_file)
        else :
            print("Signatre incorrecte, abandon de la procédure")

    def acceptContact(self):
        #A FAIRE
        pass

    def __str__(self):
        print("This is user ", self.uid)


class Server :

    def __init__(self):
        self.name = "Server"
        self.chooseDHP()
        self.g = 5

        with open("serverdata/server.object","wb") as server_object_file :
            pickle.dump(self, server_object_file)

    def createUser(self, id):
        f = open("serverdata/users.txt","r")
        for line in f :
            if line==id :
                f.close()
                return None
        print("Creating new user ->", id,"<- ...")
        newUser = User(id, self.g, self.p)
        f = open("serverdata/users.txt", "a")
        f.write(id+"\n")
        f.close
        return newUser

    def logUser(self, id):

        return currentUser


    def chooseDHP(self):
        self.p = getPrime(2048)

    def __str__(self):
        print("This is", self.name, "the p parameter is p:",self.p)
""""
alice = User("alice")
bob = User("bob")
p = alice.chooseDHP()
g = 5
alice.genereateIDKeys(g, p)
bob.genereateIDKeys(g, p)
print("KEYS\n",alice.idprivate_keyDH,"\n", bob.idprivate_keyDH,"\n\n")
alice.generateSigPKeys(g, p)
bob.generateSigPKeys(g, p)
alice.signKeys()
alice.generateEphKeys(g, p)
bob.generateEphKeys(g, p)
alice.generateOtPKeys(g, p)
bob.generateOtPKeys(g, p)
bob.computeFirstSharedKey(p, alice.sigpublic_key, alice.idpublic_keyDH, alice.pubotPKey)
alice.computeSecondSharedKey(p, bob.idpublic_keyDH, bob.pubEphKey)
alice.verifySig(alice.sigpublic_key,alice.signature,alice.idpublic_key)
"""