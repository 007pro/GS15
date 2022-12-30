import pickle
with open("bobkeys","rb") as key_file :
    dic = pickle.load(key_file)
    print(dic)