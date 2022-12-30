from classes import User, Server
from os.path import exists
import pickle

def display_menu():
  print("Menu:")
  print("1. Create new user")
  print("2. Log in")
  print("3. Option 3")
  print("4. Quit")

def main():
  while True:
    display_menu()
    choice = input("Enter your choice: ")
    if choice == "1":
      id = input("Enter a name : ")
      user = server.createUser(id)
      if user==None :
        print("Invalid Username (already exists or wrong)")
      else :
        print("User created")
      pass
    elif choice == "2":
      # Do something for option 2
      pass
    elif choice == "3":
      # Do something for option 3
      pass
    elif choice == "4":
      break
    else:
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