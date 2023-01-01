'''
THIS IS THE MAIN FILE, YOU CAN LAUNCH THE APPLICATION FROM HERE
'''

import os
#Import main objects that simulates users and servers
from classes import User, Server
#Utility functions for file manipulation
from os.path import exists
from os import listdir
import pickle

def display_menu():
    print("Menu:")
    print("1. Create new user")
    print("2. Log in")
    print("3. List all users")
    print("5. Quit")

def main():
    while True:
        display_menu()
        choice = input("Enter your choice : ")
        # Create new user
        if choice == "1":
            id = input("Enter a name : ")
            if server.verifyUserExistence(id) :
                print("Invalid Username (already exists or wrong)")
            else :
                user = server.createUser(id)
                print("User created")

        # Log in user
        elif choice == "2":
            id = input("Enter username: ")
            if server.verifyUserExistence(id)==1 :
                currentUser = server.loadUser(id)
                loggedMenu(currentUser)
            else :
                print("Invalid username, please try again")

        # List all users
        elif choice == "3":
            f = open("serverdata/users.txt", "r")
            for line in f:
                print(line)
            f.close()

        #Quit
        elif choice == "5":
            break
        else:
            print("Invalid choice. Try again.")

def loggedMenu(cuser):
    while True:
        # Accept all contact requests (X3DH response message)
        cuser.acceptContacts(server.g, server.p)
        #Load all new messages on connection
        if(exists("serverdata/messages/"+cuser.uid)) :
            print("!!! New messages !!!")
            for sendername in listdir("serverdata/messages/"+cuser.uid) :
                for i in range(len(listdir("serverdata/messages/"+cuser.uid+"/"+sendername))//2) :
                    if not (exists("serverdata/messages/"+sendername+"/"+cuser.uid)) :
                        cuser.ratchetInitSecond(sendername, server.g, server.p)
                    i+=1
                    while not(exists("serverdata/messages/" + cuser.uid + "/" + sendername + "/message_"+ str(i))) :
                        i+=1
                    with open("serverdata/messages/" + cuser.uid + "/" + sendername + "/message_" + str(i),
                              "rb") as message_file:
                        ciphertext = pickle.load(message_file)
                    with open("serverdata/messages/" + cuser.uid + "/" + sendername + "/header_" + str(i),
                              "rb") as header_file:
                        header = pickle.load(header_file)
                    #If it's a text massage
                    if(header.iv == None) :
                        message = cuser.RatchetDecrypt(sendername, header, ciphertext, server.g , server.p).decode(encoding='UTF-8')
                        print("From",sendername,":",message)
                        os.makedirs("usersdata/messages/"+cuser.uid+"/"+sendername, exist_ok=True)
                        with open("usersdata/messages/"+cuser.uid+"/"+sendername+"/message_"+str(len(listdir("usersdata/messages/"+cuser.uid+"/"+sendername))+1),"wb") as message_save :
                            pickle.dump(message,message_save)
                    #If it's a file
                    else :
                        message = cuser.RatchetDecryptAES(sendername, header, ciphertext, server.g, server.p)
                        print("From", sendername, ":", header.filename)
                        os.makedirs("usersdata/messages/" + cuser.uid + "/" + sendername, exist_ok=True)
                        with open("usersdata/messages/" + cuser.uid + "/" + sendername + "/" + header.filename,"wb") as message_save:
                            message_save.write(message)
                    os.remove("serverdata/messages/" + cuser.uid + "/" + sendername + "/message_" + str(i))
                    os.remove("serverdata/messages/" + cuser.uid + "/" + sendername + "/header_" + str(i))
            print("!!! End !!!")

        #MENU
        print("Welcome "+cuser.uid+ ", please choose an option")
        print("1. Add a new contact")
        print("2. Send File")
        print("3. Read messages")
        print("4. Send messages")
        print("5. Quit")
        print("6. Refresh")
        choice = input("Enter your choice : ")

        #Add new contact (X3DH initial message)
        if choice == "1":
            targetid=None
            while(server.verifyUserExistence(targetid)!=1) :
                targetid = input("Please enter contact name you want to add : ")
            cuser.askContact(targetid, server.g, server.p)
            print("Request sent")
            pass

        #Send file to someone
        elif choice == "2":
            targetid = None
            while (server.verifyUserExistence(targetid) != 1):
                targetid = input("Who do you want to send your file to ?")
            if not (exists("serverdata/messages/" + targetid + "/" + cuser.uid)):
                if not (exists("serverdata/messages/" + cuser.uid + "/" + targetid)):
                    cuser.ratchetInitFirst(targetid, server.g, server.p)
            fileExists = False
            while not (fileExists) :
                filepath = input("Enter filepath : ")
                fileExists = exists(filepath)
            with open(filepath, "rb") as file :
                plaintext = file.read()
            filename = os.path.basename(filepath)
            cuser.RatchetEncryptAES(targetid, plaintext, filename)

        #Read saved messages
        elif choice == "3":
            targetid = None
            print("Available messages from :", listdir("usersdata/messages/"+cuser.uid))
            while (server.verifyUserExistence(targetid) != 1):
                targetid = input("Whose message do you want to read ? :")
            print("Avaible messages from",targetid,":",listdir("usersdata/messages/"+cuser.uid+"/"+targetid))
            msgnb = input("Enter the message number you want to read :")
            with open("usersdata/messages/"+cuser.uid+"/"+targetid+"/message_"+msgnb,"rb") as message_file :
                message = pickle.load(message_file)
            print("Message_"+msgnb+" :",message)

        #Send new message
        elif choice == "4":
            targetid = None
            while (server.verifyUserExistence(targetid) != 1):
                targetid = input("Who do you want to send your message to ?")
            if not (exists("serverdata/messages/"+targetid+"/"+cuser.uid)) :
                if not (exists("serverdata/messages/"+cuser.uid+"/"+targetid)) :
                    cuser.ratchetInitFirst(targetid, server.g, server.p)
            message = input("Enter your message : ")
            plaintext = bytes(message, encoding='UTF-8')
            cuser.RatchetEncrypt(targetid,plaintext)

        #Quit
        elif choice == "5":
            break
        #Refresh
        elif choice == "6":
            pass
        else :
            print("Invalid choice. Try again.")


#Instanciate server
if exists("serverdata/server.object"):
    with open("serverdata/server.object", "rb") as server_object_file:
        server = pickle.load(server_object_file)
else :
    server = Server()

if __name__ == "__main__":
    main()