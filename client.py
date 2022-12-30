from classes import User, Server
from os.path import exists
import pickle

def display_menu():
    print("Menu:")
    print("1. Create new user")
    print("2. Log in")
    print("3. List all users")
    print("4. Quit")

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
            pass
        # Log in user
        elif choice == "2":
            id = input("Enter username: ")
            if server.verifyUserExistence(id)==1 :
                currentUser = server.loadUser(id)
                loggedMenu(currentUser)
            else :
                print("Invalid username, please try again")
            pass
        # List all users
        elif choice == "3":
            f = open("serverdata/users.txt", "r")
            for line in f:
                print(line)
            f.close()
            pass
        elif choice == "4":
            break
        else:
            print("Invalid choice. Try again.")

def loggedMenu(cuser):
    while True:
        print("Welcome "+cuser.uid+ ", please choose an option")
        print("1. Add a new contact")
        print("2. Accept contact requests")
        print("3. Read messages")
        print("4. Send messages")
        print("5. Quit")
        print("9. Show shared Keys")
        choice = input("Enter your choice : ")
        if choice == "1":
            targetid=None
            while(server.verifyUserExistence(targetid)!=1) :
                targetid = input("Please enter contact name you want to add : ")
            cuser.askContact(targetid, server.g, server.p)
            print("Request sent")
            pass
        elif choice == "2":
            cuser.acceptContacts(server.g, server.p)
            pass
        elif choice == "9":
            cuser.__str__()
        elif choice == "5":
            break
        else :
            print("Invalid choice. Try again.")


#Instancier le serveur
if exists("serverdata/server.object"):
    with open("serverdata/server.object", "rb") as server_object_file:
        server = pickle.load(server_object_file)
        server.__str__()
else :
    server = Server()
    server.__str__()

if __name__ == "__main__":
    main()