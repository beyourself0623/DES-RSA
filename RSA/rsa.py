import sympy as simp
import secrets
import os
import time 

def key_schedule():
    
    encryptionKey = 65537 #fixed encryption key 

    #to generate decryption key 
    p = generateRandomPrimeKey(128)
    q = generateRandomPrimeKey(128)
    
   
    #N is the multiplication of P and Q
    n = p * q

    #ø(N) 
    øN = (p-1) * (q-1) 

    gcd, x, y = extendedEuclidean(encryptionKey, øN)
    decryptionKey = x % øN
	
    if decryptionKey < 0:
        decryptionKey + øN
    
    return encryptionKey, decryptionKey, n


def generateRandomPrimeKey(bits):

    key = secrets.randbits(bits) #generate key with bits

    while simp.isprime(key) is False:
        key = secrets.randbits(bits) #regenerate key again 
        
    return key 


#refer to GeeksForGeeks code
def extendedEuclidean(numOne, numTwo):
    if numTwo == 0:
        return numOne, 1, 0

    gcd, x1, y1 = extendedEuclidean(numTwo, numOne % numTwo)
    x = y1
    y = x1 - (numOne // numTwo) * y1

   

    return gcd, x, y

#refer to lecture slide, but in logarithm time complexity
def power(base, expo, mod):
    result = 1

    while expo > 0:
        if expo % 2 == 1:
            result = (result * base) % mod
        base = (base * base) % mod
        expo = expo // 2 #logarithm 
    return result

def binaryExponentiation(message, encryptionKey, n):
    x = power(message, encryptionKey , n) 
    
    return x 


def encryption(fileName, encryptionKey, n):

    with open(fileName, "r") as file:
        plaintext = file.read()
       
    
    start_time = time.time()

    ciphertext = []
    for char in plaintext:
        charinAscii = ord(char) #message in char turn to ascii as M
        cipherChar = binaryExponentiation(charinAscii, encryptionKey, n) #c = m^e mod n in hexadecimal
        cipherHex = hex(cipherChar)[2:]
        ciphertext.append(str(cipherHex))
        ciphertext.append(",")

    #once all the code are in ciphertext
    end_time = time.time()
    elapsed_time = end_time - start_time
    print("Time taken:", elapsed_time)
    
    with open("encryption.txt", "w") as en:

        for each in ciphertext:
          
            en.write(each)

def decryption(fileName, decryptionKey, n):
    charinAscii = ""
    with open(fileName, "r") as file:
        ciphertext = file.read()

    plaintext = []
    
    start_time = time.time()
    for char in ciphertext:
        
        if(char != ','): #if its not ','
            charinAscii += char

        if(char == ','): 
            charinAscii = str(int(charinAscii,16))
            pt = chr(binaryExponentiation(int(charinAscii), decryptionKey, n))
            plaintext.append(pt) #c = m^e mod n in hexadecimal
            charinAscii = ""
        
    #once all the code are in ciphertext

    end_time = time.time()
    elapsed_time = end_time - start_time
    print("Time taken:", elapsed_time)
    with open("decryption.txt", "w") as dec:

        for each in plaintext:
            dec.write(each)


def main():

    encryptionKey, decryptionKey, n = key_schedule()
    selection = 0

    while(selection != '3'):
        print("RSA Encryption & Decryption:")
        print("1. Encrypt a file")
        print("2. Decrypt a file")
        print("3. Exit")

        selection = input("Selection: ")

        if(selection == '1'):
            encryption("RSA-text.txt", encryptionKey, n)
            os.system("clear")
            print("Encryption Done !\n\n")
        
        elif(selection == '2'):
            decryption("encryption.txt", decryptionKey, n)
            os.system("clear")
            print("Decryption Done !\n\n")

        elif(selection == '3'):
            print("Bye Bye !")




if __name__ == "__main__":
    main()