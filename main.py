import hashlib  # used for the pbkdf2 function
import os  # used for generating random bytes = salt and working with files
from getpass import getpass  # invisible passwort entry

users = {}  # username, salt and hash value from the password are stored here


def register():
    password = ""
    passwordConfirm = " "
    while True:
        print("new username: ")
        username = input()
        if users.__contains__(username):
            print("the username is in use. pick another one")
        else:
            break
    while password != passwordConfirm:
        password = getpass("new password: ")
        passwordConfirm = getpass("new password confirmation: ")
        if password != passwordConfirm:
            print("the passwords did not match. insert the password again")
        else:
            break
    salt = os.urandom(16)  # new salt for this user, size in bytes, 16 bytes = 128 bits
    try:
        key = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, 310000, 128)  # 128 bytes = 1024 bits = 2
        # * 512 bits (from sha512)
        # (hash_name, password, salt, iterations, dklen) dklen is the length of the derived key in bytes. default is
        # the length of the hash alg
        users[username] = {  # store the salt and key
            'salt': salt.hex(),
            'key': key.hex()
        }
    except:
        print("user could not be created")
    try:
        file1 = open("Password.secure", "a")
        fileOutput = [username, users[username]]
        file1.writelines(str(fileOutput))
        file1.write("\n")
        file1.close()
        print("registration successful")
    except:
        print("the changes could not be saved")


def login():
    print("enter username: ")
    enteredUsername = input()
    enteredPassword = getpass("enter password: ")
    try:
        currentUser = users[enteredUsername]
        enteredKey = hashlib.pbkdf2_hmac('sha512', enteredPassword.encode('utf-8'), bytes.fromhex(currentUser['salt']),
                                         310000, 128).hex()
        if currentUser['key'] == enteredKey:
            print("authentication succesful")
        else:
            print("wrong password")
    except:
        print("user not found")


def main():
    while True:
        print("press (r) for register, (l) for log in or (e) for exit: ")
        choice = input()
        if choice == "r":
            if os.geteuid() == 0:  # uid is used identifier and it is used for determining which system resources the
                # user can access. The default UID for the root user is 0
                register()
            else:
                print("this requires root access. run the script as root")
        else:
            if choice == "l":
                login()
            else:
                if choice == "e":
                    print("see you around")
                    break
                else:
                    print("invalid input. try again")


def loadDataFromFile():
    try:
        with open("Password.secure") as file:  # Password.secure is the file where all passwords are stored
            for user in file:
                user = user.rstrip()
                saltIndex = str(user).find("salt")
                keyIndex = str(user).find("key")
                salt = str(user)[int(saltIndex + 8):int(keyIndex - 4)]
                key = str(user)[int(keyIndex + 7):len(str(user)) - 3]
                username = str(user)[2:int(saltIndex - 5)]
                users[username] = {
                    'salt': salt,
                    'key': key
                }
    except:
        print("Data could not be imported!")


if __name__ == "__main__":
    loadDataFromFile()  # executed at start to feed the dictionary with all user data
    main()
