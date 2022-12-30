from Cryptodome.Util.number import getPrime, getRandomInteger, getRandomNBitInteger, inverse, long_to_bytes, bytes_to_long
from Cryptodome.Hash import SHA256
from maths import expRapide, GENERATE_DH, DH, kdf_rk, kdf_ck, Header, rc4, TrySkippedMessageKeys, SkipMessageKeys, DHRatchet
from os.path import exists
from random import randint
import os
import pickle

class State:
    def __init__(self, uid):
        self.uid = uid
        pass


class User:

    def __init__(self, uid, g, p):
        self.uid = uid
        self.states = {}
        self.sharedKeys = {}
        self.ratchetKeys = {}
        self.generateKeys(g, p)
        self.saveUser()

    def saveUser(self):
        with open("usersdata/" + self.uid + ".object", "wb") as data_file:
            pickle.dump(self, data_file)

    def generateKeys(self, g, p):
        self.genereateIDKeys(g, p)
        self.generateSigPKeys(g, p)
        self.signKeys()
        self.generateEphKey(g, p)
        self.otPKeys = []
        for i in range(10) :
            self.otPKeys.append(self.generateOtPKeys(g, p))
        self.publishKeys()
        self.saveUser()

    def publishKeys(self):
        with open("serverdata/keys/"+self.uid+".keys","wb") as keys_file :
            keys = {"IDPUB" : self.idpublic_keyDH, "SIGPKPUB" : self.sigpublic_key, "SIG" : self.signature, "OTPK" : self.otPKeys, "PUBIDRSA" : self.idpublic_key, "RK" : self.ratchetKeys}
            pickle.dump(keys, keys_file)

    def generateRatchetPublicKey(self, g, p, target):
        self.ratchetKeys[target] = GENERATE_DH(g, p)

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

    def computeSecondSharedKey(self, p, idK, ephK, otid):
        dh1 = expRapide(idK, self.sigprivate_key, p)
        dh2 = expRapide(ephK, self.idprivate_keyDH, p)
        dh3 = expRapide(ephK, self.sigprivate_key, p)
        dh4 = expRapide(ephK, self.otPKeys[otid][0], p)
        return int(str(dh1)+str(dh2)+str(dh3)+str(dh4))

    def askContact(self, target, g, p):
        self.generateEphKey(g, p)
        chosenNb = randint(0,9)
        self.generateRatchetPublicKey(g, p, target)
        self.publishKeys()
        req = {"IDPUB": self.idpublic_keyDH, "EPHK": self.pubEphKey, "OTID": chosenNb, "IDPUBRSA" : self.idpublic_key}
        with open("serverdata/keys/"+target+".keys","rb") as key_file:
            targetKeys = pickle.load(key_file)
        #Verify signature
        if(self.verifySig(targetKeys["SIGPKPUB"],targetKeys["SIG"],targetKeys["PUBIDRSA"])==1) :
            sk = self.computeFirstSharedKey(p, targetKeys["SIGPKPUB"], targetKeys["IDPUB"], targetKeys["OTPK"][chosenNb][1] )
            self.sharedKeys[target] = sk
            print("Shared Key:", sk)
            os.makedirs(os.path.dirname("serverdata/contactRequests/"+target), exist_ok=True)
            #Save request for future confirmation
            with open("serverdata/contactRequests/"+target+"/"+self.uid+".ask","wb") as ask_file :
                pickle.dump(req, ask_file)
        else :
            print("Signatre incorrecte, abandon de la procédure")
        self.saveUser()

    def acceptContacts(self, g, p):
        os.makedirs("serverdata/contactRequests/" + self.uid, exist_ok=True)
        reqdir = os.listdir("serverdata/contactRequests/"+self.uid)
        if len(reqdir) == 0:
            print("No contact requests")
        else:
            for ask_filename in reqdir :
                target = ask_filename.rstrip(".ask")
                self.generateRatchetPublicKey(g, p, target)
                self.publishKeys()
                with open("serverdata/contactRequests/"+self.uid+"/"+ask_filename,"rb") as ask_file :
                    req = pickle.load(ask_file)
                with open("serverdata/keys/" + target + ".keys", "rb") as key_file:
                    targetKeys = pickle.load(key_file)
                if(self.verifySig(targetKeys["SIGPKPUB"],targetKeys["SIG"],targetKeys["PUBIDRSA"])==1) :
                    sk = self.computeSecondSharedKey(p, req["IDPUB"], req["EPHK"], req["OTID"])
                    self.sharedKeys[target] = sk
                    print("Shared Key:", sk)
                    os.remove("serverdata/contactRequests/"+self.uid+"/"+ask_filename)
                else:
                    print("Signatre incorrecte, abandon de la procédure")
                self.saveUser()

    def ratchetInitFirst(self, target, g, p):
        SK = self.sharedKeys[target]
        self.states[target] = State(target)
        state = self.states[target]
        with open("serverdata/keys/"+target+".keys","rb") as key_file:
            targetKeys = pickle.load(key_file)
        state.DHs = GENERATE_DH(g, p)
        state.DHr = targetKeys["RK"][self.uid][1]
        state.RK, state.CKs = kdf_rk(long_to_bytes(SK), long_to_bytes(DH(state.DHs[0], state.DHr,p)))
        state.CKr = None
        state.Ns = 0
        state.Nr = 0
        state.PN = 0
        state.MKSKIPPED = {}

    def ratchetInitSecond(self, target, g, p):
        self.states[target] = State(target)
        SK = self.sharedKeys[target]
        state = self.states[target]
        state.DHs = self.ratchetKeys[target]
        state.DHr = None
        state.RK = long_to_bytes(SK)
        state.CKs = None
        state.CKr = None
        state.Ns = 0
        state.Nr = 0
        state.PN = 0
        state.MKSKIPPED = {}

    def RatchetEncrypt(self, target, plaintext):
        state = self.states[target]
        state.CKs, mk = kdf_ck(state.CKs)
        header = Header(state.DHs, state.PN, state.Ns)
        state.Ns += 1
        return header, rc4(mk, plaintext)
#changer plaintext et ciphertext
    def RatchetDecrypt(self, target, header, ciphertext,g , p):
        state = self.states[target]
        plaintext = TrySkippedMessageKeys(state, header, ciphertext)
        if plaintext != None:
            return plaintext
        if header.dh != state.DHr:
            SkipMessageKeys(state, header.pn)
            DHRatchet(state, header,g, p)
        SkipMessageKeys(state, header.n)
        state.CKr, mk = kdf_ck(state.CKr)
        state.Nr += 1
        return rc4(mk, ciphertext)


    def __str__(self):
        print("This is user ", self.uid)
        print("Shared Keys :", self.sharedKeys)


class Server :

    def __init__(self):
        self.name = "Server"
        self.chooseDHP()
        self.g = 5

        with open("serverdata/server.object","wb") as server_object_file :
            pickle.dump(self, server_object_file)

    def createUser(self, id):
        print("Creating new user ->", id,"<- ...")
        newUser = User(id, self.g, self.p)
        f = open("serverdata/users.txt", "a")
        f.write(id+"\n")
        f.close
        return newUser

    def loadUser(self, id):
        with open("usersdata/" + id + ".object", "rb") as userdata_file:
            currentUser = pickle.load(userdata_file)
        return currentUser

    def verifyUserExistence(self, id):
        f = open("serverdata/users.txt", "r")
        for line in f:
            if line.rstrip('\n') == id:
                f.close()
                return 1
        return 0

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