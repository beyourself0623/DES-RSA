ip_table = [58, 50, 42, 34, 26, 18, 10, 2,
				60, 52, 44, 36, 28, 20, 12, 4,
				62, 54, 46, 38, 30, 22, 14, 6,
				64, 56, 48, 40, 32, 24, 16, 8,
				57, 49, 41, 33, 25, 17, 9, 1,
				59, 51, 43, 35, 27, 19, 11, 3,
				61, 53, 45, 37, 29, 21, 13, 5,
				63, 55, 47, 39, 31, 23, 15, 7]

# Expansion Table
ebox = [32, 1, 2, 3, 4, 5, 4, 5,
		6, 7, 8, 9, 8, 9, 10, 11,
		12, 13, 12, 13, 14, 15, 16, 17,
		16, 17, 18, 19, 20, 21, 20, 21,
		22, 23, 24, 25, 24, 25, 26, 27,
		28, 29, 28, 29, 30, 31, 32, 1]

# Permutation Table
pbox = [16, 7, 20, 21,
	29, 12, 28, 17,
	1, 15, 23, 26,
	5, 18, 31, 10,
	2, 8, 24, 14,
	32, 27, 3, 9,
	19, 13, 30, 6,
	22, 11, 4, 25]

#key_PC1 table
PC_1 = [57, 49, 41, 33, 25, 17, 9, 1, 
        58, 50, 42, 34, 26, 18, 10, 2, 
        59, 51, 43, 35, 27, 19, 11, 3, 
        60, 52, 44, 36, 63, 55, 47, 39, 
        31, 23, 15, 7, 62, 54, 46, 38, 
        30, 22, 14, 6, 61, 53, 45, 37,
        29, 21, 13, 5, 28, 20, 12, 4]
    
#key_PC2 table
PC_2 = [14, 17, 11, 24, 1, 5, 3, 28,
        15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56,
        34, 53, 46, 42, 50, 36, 29, 32]

# S-box Table
sbox = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
		[0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
		[4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
		[15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

		[[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
		[3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
		[0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
		[13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

		[[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
		[13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
		[13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
		[1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

		[[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
		[13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
		[10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
		[3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

		[[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
		[14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
		[4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
		[11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

		[[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
		[10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
		[9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
		[4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

		[[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
		[13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
		[1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
		[6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

		[[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
		[1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
		[7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
		[2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

# Final Permutation Table
fp_table = [40, 8, 48, 16, 56, 24, 64, 32,
			39, 7, 47, 15, 55, 23, 63, 31,
			38, 6, 46, 14, 54, 22, 62, 30,
			37, 5, 45, 13, 53, 21, 61, 29,
			36, 4, 44, 12, 52, 20, 60, 28,
			35, 3, 43, 11, 51, 19, 59, 27,
			34, 2, 42, 10, 50, 18, 58, 26,
			33, 1, 41, 9, 49, 17, 57, 25]


def input_key():
    key = input("Please enter your key: ")
    print (key)
    return key

def keyToBinary(key):
    key_bytes = key.encode('utf_8')

    if(len(key_bytes) < 8):
        key_bytes = key_bytes.ljust(8, b'\0') # pad with 0 in bytes

    elif (len(key_bytes) > 8): #minus the extra bytes part
        key_bytes = key_bytes[:8]

    #convert to binary

    key_binary = ""
    for byte in key_bytes:
        binary = format(byte,'08b')
        key_binary += binary

    return key_binary

def leftshift(key, shift):

    mid = int(len(key)/2)
    leftKey = key[:mid]
    rightKey = key[mid:]

    newLeftKey = leftKey[shift:] + leftKey[:shift]
    newRightKey = rightKey[shift:] + rightKey[:shift]
    return newLeftKey+newRightKey

def keyshift(key, round):
    if (round in [0,1,8,15]): #Round 1 2 9 16, shift 1
        key = leftshift(key,1) 
        
    else: # other rounds shift 2
        key = leftshift(key,2)
    
    return key


#function 1 works
def key_transmission(key):
    keyList = []
    binary = keyToBinary(key) #convert to 64 bit binary
        
    #PC-1 (permute using table) and change from 64 to 56 bits
    pc1_binary = ""
    for ii in range (len(PC_1)): 
        pc1_binary += binary[PC_1[ii]-1] #correct

    #loop to create 16 subkeys
    for i in range (16):
        
        shifted_key = keyshift(pc1_binary,i)
        pc1_binary = shifted_key
        #Compression permutation (56 to 48)
        newKey = ""
        for iii in range(len(PC_2)):
            newKey += shifted_key[PC_2[iii]-1]

        keyList.append(newKey)
    
    return keyList

def readFile(file):
    with open(file, "r") as text:
        text = text.read()
    return text

#correct
def textToBlocks(text):
    blocks = []
    text_bytes = text.encode('utf_8')
    #Convert to binary
    text_binary = ""
    for byte in text_bytes:
        temp_binary = format(byte,'08b')
        text_binary += temp_binary

    #Split to 64 bit chunks
    temp = ""
    for i in range(len(text_binary)):
        temp += text_binary[i]
        if len(temp) == 64:
            blocks.append(temp)
            temp = ""

    if temp != "":
        # add padding to last block
        temp += "0" * (64 - len(temp))
        blocks.append(temp)

    
    return blocks

def textToBlocksDecrypt(text):
    blocks = []
    #Convert to binary
    cipher_binary = bin(int(str(text), 16))[2:]
    #Split to 64 bit chunks
    temp = ""
    for i in range(len(cipher_binary)):
        temp += cipher_binary[i]

        if len(temp) == 64:
            blocks.append(temp)
            temp = ""

   
        

    return blocks

def initialPermutation(binary_text):
    binary = ""
    for i, b in enumerate(ip_table, start=0): 
        binary += binary_text[ip_table[i]-1]

    return binary

#expand to 48 bits
#correct
def expansionPermutation(binary_text):
    binary = ""
    for i, b in enumerate(ebox, start=0):
        binary += binary_text[ebox[i]-1]
    
    return binary


def XOR(binary_text, binary_key):
    output = ""
    for i in range(len(binary_text)):
        
        if(binary_text[i] == binary_key[i]):
            output += "0"
        else:
            output += "1"
    
    return output
        
def splitText(text):
    mid = len(text) // 2
    leftText = text[:mid]
    rightText = text[mid:]

    return leftText,rightText


#produce 32 bits output text
#correct
def sbox_transform(binary_text):
    textBlock = []
    newTextBlock = []
    temp = ""
    #divide to 8 blocks 6 bits
    for i in range(len(binary_text)):
        temp += binary_text[i]
        if len(temp) == 6:
            textBlock.append(temp)
            temp = ""
    
    #for each element in text block
    count = 0
    for i in range(len(textBlock)):
        
        tempBlock = textBlock[i]
        #print("TempBlock = " + tempBlock)
        row = int((tempBlock[0] + tempBlock[5]), 2)
        col = int(tempBlock[1:5], 2)
        
        currentSbox = sbox[i]
        newTextBlock.append(format(currentSbox[row][col], '04b'))
 
    newBinary = ""
    #for loop combine text block to 32 bits
    for i in range(len(newTextBlock)):
        newBinary += newTextBlock[i]
    
    
    return newBinary


def pbox_transform(sbox_output):
    p_output = ""
    for i in range(len(sbox_output)):
        p_output += sbox_output[pbox[i]-1]

    return p_output

#feistel network or function, goes 16 rounds and finally produce output ciphertext
def f_function(rightText, binary_key_block):
    ep_output = expansionPermutation(rightText)
    xor_output = XOR(ep_output, binary_key_block)
    sbox_output = sbox_transform(xor_output)
    f_output = pbox_transform(sbox_output)

    return f_output

def feistel_cipher(leftText, rightText,binary_key_block, state):

    #repeat 16 times
    if state == "encrypt":
        for i in range(16):
            f_output = f_function(rightText, binary_key_block[i]) #new right output
            oldRightText = rightText
            rightText = XOR(leftText, f_output)
            leftText = oldRightText
        text = rightText + leftText
    else:
        for i in range(16):
            f_output = f_function(rightText, binary_key_block[15-i]) #new right output
            oldRightText = rightText
            rightText = XOR(leftText, f_output)
            leftText = oldRightText
        text = rightText + leftText

    return text
def finalPermutation(text):
    binary = ""
    for i, b in enumerate(fp_table, start=0): 
        binary += text[fp_table[i]-1]

    return binary

def des_encryption(key, text):
    ciphertext_block = []
    binary_key_block = key_transmission(key)
    binary_text_block = textToBlocks(text)

    #for loop in each 64 bits text block
    for i in range(len(binary_text_block)):

        binary_text = binary_text_block[i]
        binary_text = initialPermutation(binary_text)
        leftText, rightText = splitText(binary_text)
        fc_output = feistel_cipher(leftText, rightText, binary_key_block, "encrypt")
        ciphertext = finalPermutation(fc_output)
        hexacipher = format(int(ciphertext, 2), 'x')
        ciphertext_block.append(hexacipher)

        text = ""
        for i in range(len(ciphertext_block)):
            text += ciphertext_block[i]

    with open("encrypt.txt", "w") as f:
        f.write(text)




def des_decryption(key, text):
    plaintext_block = []
    binary_key_block = key_transmission(key)
    binary_text_block = textToBlocksDecrypt(text)

    #for loop in each 64 bits text block
    for i in range(len(binary_text_block)):

        binary_text = binary_text_block[i]
        binary_text = initialPermutation(binary_text)
        leftText, rightText = splitText(binary_text)
        fc_output = feistel_cipher(leftText, rightText, binary_key_block, "decrypt")
        plaintext_binary = finalPermutation(fc_output)
        #64 bit

        char_string = ""
        for i in range(0, len(plaintext_binary), 8):
           # print(plaintext_binary)
            for i in range(0, len(plaintext_binary), 8):
                char_string += chr(int(plaintext_binary[i:i+8], 2))
            
            #print("PTT =" +char_value)
            plaintext_block.append(char_string)


        text = ""
        for i in range(len(plaintext_block)):
            text += plaintext_block[i]

        with open("decrypt.txt", "w") as f:
            f.write(text)
        


def main():

    while(True):
        print("1. Encryption")
        print("2. Decryption")
        print("3. Exit")
        userInput = input("Please select your choice: ")

        if(userInput == "1"):
            fileName = input("Enter file: ")
            text = readFile(fileName)
            key = input("Enter key: ")
            des_encryption(key, text)

        elif userInput == "2":
            fileName = input("Enter file: ")
            text = readFile(fileName)
            key = input("Enter key: ")
            des_decryption(key, text)
        elif userInput == "3":
            break
    
    

main()