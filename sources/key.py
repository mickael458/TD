import base64
import os
import time

CNC_FOLDER = "cnc_data/"

def main():
    #input a token in hexa
    input_key = input("Enter the token: ")


    path = CNC_FOLDER + input_key
     #read the key
    with open(os.path.join(path, "key.bin"), "rb") as key_file:
        key = key_file.read()

    #print the key
    print("The key is: " + base64.b64encode(key).decode("utf-8"))


if __name__ == "__main__":
    main()