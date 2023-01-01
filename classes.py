from Cryptodome.Util.number import getPrime, getRandomInteger, getRandomNBitInteger, inverse, long_to_bytes, bytes_to_long
from sha256 import sha256
from aes import aes_decrypt,aes_encrypt
from maths import expRapide, GENERATE_DH, DH, kdf_rk, kdf_ck, Header, rc4, TrySkippedMessageKeys, SkipMessageKeys, DHRatchet, kdf_sk
from os.path import exists
from random import randint
import os
import pickle

#State class as described and used in Signal's double ratchet documentation
class State:
    def __init__(self, uid):
        self.uid = uid
        pass

#A user class used to define users of the application. They carry their key-pairs and interract with the client and the server through their methods
class User:

    #User creation, keys needed for X3DH are created and published to the server
    def __init__(self, uid, g, p):
        self.uid = uid
        self.states = {}
        self.sharedKeys = {}
        self.ratchetKeys = {}
        self.generateKeys(g, p)
        self.saveUser()

    #Method which saves the user data on it's machine
    def saveUser(self):
        with open("usersdata/" + self.uid + ".object", "wb") as data_file:
            pickle.dump(self, data_file)

    #Global method that generates the keys for X3DH
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

    #Method that publishes the keys to the server
    def publishKeys(self):
        with open("serverdata/keys/"+self.uid+".keys","wb") as keys_file :
            keys = {"IDPUB" : self.idpublic_keyDH, "SIGPKPUB" : self.sigpublic_key, "SIG" : self.signature, "OTPK" : self.otPKeys, "PUBIDRSA" : self.idpublic_key, "RK" : self.ratchetKeys}
            pickle.dump(keys, keys_file)

    #Ratchet public key generation
    def generateRatchetPublicKey(self, g, p, target):
        self.ratchetKeys[target] = GENERATE_DH(g, p)

    #ID key-pairs generation
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
        # Build DH key-pair from RSA private key
        self.idprivate_keyDH = d
        self.idpublic_keyDH = expRapide(g, self.idprivate_keyDH, pDH)
        print("Generating keys")

    #Signed Pre-Keys generation
    def generateSigPKeys(self, g, p):
        self.sigprivate_key = getRandomInteger(2048)
        self.sigpublic_key = expRapide(g, self.sigprivate_key, p)
        #print("Clé sig généré")

    #Performs RSA with SHA-256 to sign pre-keys
    def signKeys(self):
        hashed_message = bytes_to_long(sha256(long_to_bytes(self.sigpublic_key)))
        signature = expRapide(hashed_message, self.idprivate_key[1], self.idprivate_key[0])
        self.signature = signature

    #One-time pre-keys generation
    def generateOtPKeys(self, g, p):
        privotPKey = getRandomInteger(2048)
        pubotPKey = expRapide(g, privotPKey, p)
        #print("Clé OT généré")
        return (privotPKey, pubotPKey)

    #Ephemeral keys generation
    def generateEphKey(self, g , p):
        self.privEphKey = getRandomInteger(2048)
        self.pubEphKey = expRapide(g, self.privEphKey, p)
        #print("Clé eph généré")

    #Performs RSA signature verification
    def verifySig(self, pubSigKey, signature, pubIDKey):
        hashed_message = bytes_to_long(sha256(long_to_bytes(pubSigKey)))
        decrypted_sig = expRapide(signature, pubIDKey[1], pubIDKey[0])
        if(decrypted_sig==hashed_message):
            #print("Signature correcte")
            return 1
        else:
            #print("Signature incorrecte")
            return 0

    #Performs X3DH Key Agreement / Key computing for initial message
    def computeFirstSharedKey(self, p, sigPK, idK, otPK):
        dh1 = expRapide(sigPK, self.idprivate_keyDH, p)
        dh2 = expRapide(idK, self.privEphKey, p)
        dh3 = expRapide(sigPK, self.privEphKey, p)
        dh4 = expRapide(otPK, self.privEphKey, p)
        return int(str(dh1)+str(dh2)+str(dh3)+str(dh4))

    # Performs X3DH Key Agreement / Key computing for response message
    def computeSecondSharedKey(self, p, idK, ephK, otid):
        dh1 = expRapide(idK, self.sigprivate_key, p)
        dh2 = expRapide(ephK, self.idprivate_keyDH, p)
        dh3 = expRapide(ephK, self.sigprivate_key, p)
        dh4 = expRapide(ephK, self.otPKeys[otid][0], p)
        return int(str(dh1)+str(dh2)+str(dh3)+str(dh4))

    # Sends X3DH initial message and compute shared key
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
            sk = kdf_sk(long_to_bytes(sk))
            self.sharedKeys[target] = sk
            #print("Shared Key:", sk)
            os.makedirs("serverdata/contactRequests/"+target, exist_ok=True)
            #Save request for future confirmation
            with open("serverdata/contactRequests/"+target+"/"+self.uid+".ask","wb") as ask_file :
                pickle.dump(req, ask_file)
        else :
            print("Incorrect signature")
        self.saveUser()

    #Accept all X3DH initial messages and compute shared keys
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
                    sk = kdf_sk(long_to_bytes(sk))
                    self.sharedKeys[target] = sk
                    #print("Shared Key:", sk)
                    os.remove("serverdata/contactRequests/"+self.uid+"/"+ask_filename)
                    print("Accepted "+target+"'s request")
                else:
                    print("Incorrect signature")
                self.saveUser()

    #Double Ratchet Initialisation for the one who's sending the first message
    def ratchetInitFirst(self, target, g, p):
        os.makedirs("serverdata/messages/" + target + "/" + self.uid, exist_ok=True)
        SK = self.sharedKeys[target]
        self.states[target] = State(target)
        state = self.states[target]
        with open("serverdata/keys/"+target+".keys","rb") as key_file:
            targetKeys = pickle.load(key_file)
        state.DHs = GENERATE_DH(g, p)
        state.DHr = targetKeys["RK"][self.uid][1]
        state.RK, state.CKs = kdf_rk(SK, long_to_bytes(DH(state.DHs[0], state.DHr,p)))
        state.CKr = None
        state.Ns = 0
        state.Nr = 0
        state.PN = 0
        state.MKSKIPPED = {}
        self.saveUser()

    # Double Ratchet Initialisation for the one receiving before sending the first message
    def ratchetInitSecond(self, target, g, p):
        os.makedirs("serverdata/messages/" + target + "/" + self.uid, exist_ok=True)
        self.states[target] = State(target)
        SK = self.sharedKeys[target]
        state = self.states[target]
        state.DHs = self.ratchetKeys[target]
        state.DHr = None
        state.RK = SK
        state.CKs = None
        state.CKr = None
        state.Ns = 0
        state.Nr = 0
        state.PN = 0
        state.MKSKIPPED = {}
        self.saveUser()

    #Performs Double Ratchet message sending with RC4 encryption
    def RatchetEncrypt(self, target, plaintext):
        state = self.states[target]
        state.CKs, mk = kdf_ck(state.CKs)
        header = Header(state.DHs, state.PN, state.Ns)
        state.Ns += 1
        ciphertext = rc4(mk, plaintext)
        with open("serverdata/messages/"+target+"/"+self.uid+"/message_"+str(state.Ns),"wb") as message_file :
            pickle.dump(ciphertext,message_file)
        with open("serverdata/messages/"+target+"/"+self.uid+"/header_"+str(state.Ns),"wb") as header_file :
            pickle.dump(header,header_file)
        self.saveUser()
        return header, ciphertext

    # Performs Double Ratchet message receiving with RC4 decryption
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
        plaintext = rc4(mk, ciphertext)
        self.saveUser()
        return plaintext

    # Performs Double Ratchet message sending with AES encryption
    def RatchetEncryptAES(self, target, plaintext, filename):
        state = self.states[target]
        state.CKs, mk = kdf_ck(state.CKs)
        iv = os.urandom(16)
        header = Header(state.DHs, state.PN, state.Ns)
        header.filename = filename
        header.iv = iv
        state.Ns += 1
        ciphertext = aes_encrypt(plaintext, mk, iv)
        with open("serverdata/messages/" + target + "/" + self.uid + "/message_" + str(state.Ns),
                  "wb") as message_file:
            pickle.dump(ciphertext, message_file)
        with open("serverdata/messages/" + target + "/" + self.uid + "/header_" + str(state.Ns),
                  "wb") as header_file:
            pickle.dump(header, header_file)
        self.saveUser()
        return header, ciphertext

    # Performs Double Ratchet message receiving with AES decryption
    def RatchetDecryptAES(self, target, header, ciphertext, g, p):
        state = self.states[target]
        plaintext = TrySkippedMessageKeys(state, header, ciphertext)
        if plaintext != None:
            return plaintext
        if header.dh != state.DHr:
            SkipMessageKeys(state, header.pn)
            DHRatchet(state, header, g, p)
        SkipMessageKeys(state, header.n)
        state.CKr, mk = kdf_ck(state.CKr)
        state.Nr += 1
        plaintext = aes_decrypt(ciphertext, mk, header.iv)
        self.saveUser()
        return plaintext


    def __str__(self):
        print("This is user ", self.uid)
        print("Shared Keys :", self.sharedKeys)


class Server :

    #Server object initialisation
    def __init__(self):
        self.name = "Server"
        self.chooseDHP()
        self.g = 5

        with open("serverdata/server.object","wb") as server_object_file :
            pickle.dump(self, server_object_file)

    #New user creation method
    def createUser(self, id):
        print("Creating new user ->", id,"<- ...")
        newUser = User(id, self.g, self.p)
        f = open("serverdata/users.txt", "a")
        f.write(id+"\n")
        f.close
        return newUser

    #method user for user login
    def loadUser(self, id):
        with open("usersdata/" + id + ".object", "rb") as userdata_file:
            currentUser = pickle.load(userdata_file)
        return currentUser

    #method which verify user existence
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