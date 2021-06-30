from primesieve import *
from random import *
import math
import base64
from textwrap import wrap

def isPrime(x: int) -> bool:
    """
    returns if a number is prime or not
    """
    if x < 2:
        return False
    elif x == 2:
        return True  
    for n in range(2, x):
        if x % n ==0:
            return False
    return True

def generateKeyFile(n: int, e: int, typ: str):
    """
    Generathe the files for the keys 
    the 3rd parameter is eiver "private" or "public" defining what key to generate
    """
    print("Generating", typ, "key")
    message = str(hex(n) + '\n' + hex(e))
    message_bytes = message.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    
    key = str(base64_bytes.decode("ascii")) # we decode to remove the wierd characters
    
    if typ == "private" :
        f = open("test.priv", "w")
        f.write("---begin monRSA private key---\n")
        f.write(key+'\n')
        f.write("---end monRSA key---")
        f.close()
    elif typ == "public" :
        f = open("test.pub", "w")
        f.write("---begin monRSA public key---\n")
        f.write(key+'\n')
        f.write("---end monRSA key---")
        f.close()
    else :
        print("wrong type")
        return

def generateKeys():
    """
    General all the required numbers
    """
    p = nth_prime(97885344)
    q = nth_prime(85785656)
    print("p", p)
    print("q", q)
    n = p*q
    print("n", n)
    nn = (p-1)*(q-1)
    print("nn",nn)
    temp = genED(nn)
    e = temp[0]
    print("e",e)
    d = temp[1]
    print("d",d)
    ed = temp[2]
    print("ed",ed)
    generateKeyFile(n, e, "public")
    generateKeyFile(n, d, "private")

def extractParamsFromKey(key: str) -> []:
    """
    Extract the two parameters from the key
    the key is given in base 64
    """
    l = base64.b64decode(key).decode('ascii')
    
    param1 = l.split('\n')[0]
    param2 = l.split('\n')[1]
    #convert back to int
    param1 = int(param1, 16)
    param2 = int(param2, 16)
    
    # print(param1,param2)
    return [param1,param2]

def writeToFile(file: str, text: str):
    """
    Write a string to a file
    """
    f = open(file, "w")
    f.write(text)
    f.close()

def readFile(file: str) -> str:
    """
    read a file
    """
    f = open(file, "r")
    content = f.read()
    f.close()
    return content

def encode(keyFile, string):
    """
    Encode a file using the public key
    """
    print("Encoding message ...")
    print("Is public key file ok ?", checkKeyFile(keyFile,"public"))

    if (checkKeyFile(keyFile,"public")):        
        f = open(keyFile)
        keyData = extractParamsFromKey(f.readlines()[1]) # read the second line of the file and extract the param
        print("keydata", keyData)
        
        # transform the ascii string into a series of numbers
        asciiToInt = ""
        for char in string :
            asciiToInt += str(ord(char))
        print("ascii to int", asciiToInt)
        
        # calculate the block length
        blocklen = len(str(keyData[0]))
        print("block size is ",blocklen )
        
        # cut the ascii numbers into bloks of that length.
        blocks = wrap(asciiToInt, blocklen)
        # print(blocks)
        
        # make sur that every block is the corect length, overwise add padding
        for i in range(len(blocks)):
            if(len(str(blocks[i])) != blocklen):
                print("adding padding")
                blocks[i] = blocks[i].zfill(blocklen)

        # crypt everyblock
        tempCryptString = ""
        for i in range(len(blocks)): 
            tempCryptString += str(calculateCrypt(blocks[i], keyData[1], keyData[0]))
        print("encrypted string :",tempCryptString)
        # write the contentes to a file
        writeToFile("encoded", tempCryptString)

        # writeToFile("encoded", stringToHextoBase64(tempCryptString))
    else: 
        print("keyfile is incorrect")

def calculateCrypt(asci: int, e: int, n: int) -> int:
    """
    Calculate the crypt int
    """
    return int(asci)^e % n

def calculateDeCrypt(asci: int, d: int, n: int) -> int:
    """
    Calculate the decrypt int
    """
    return int(asci)^d % n

def stringToHextoBase64(inputString: str) -> str: 
    """
    input = a string of numbers
    Takee a string, transform it to int then to hex then to base64
    """
    inputString = str(inputString)
    message = hex(int(inputString))
    message_bytes = message.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    return str(base64_bytes.decode("ascii"))

def base64ToHexToString(inputString: str) -> str:
    """
    input = a base64 string
    Take the abse 64, make it  ahex then a string
    """

def decode(keyFile: str, string : str):
    """
    decode a file using the private key
    """
    print("Decoding message ...")
    print("Is private key file ok ?", checkKeyFile(keyFile,"private"))

    if (checkKeyFile(keyFile,"private")):        
        f = open(keyFile)
        keyData = extractParamsFromKey(f.readlines()[1]) # read the second line of the file and extract the param
        print("keydata", keyData)
        
        blocklen = len(str(keyData[0]))
        print("block size is ",blocklen)
        
        # split the string into blocks
        blocks = wrap(string, blocklen)
        print(blocks)
        
        tmpDecoded = ""
        for i in range(len(blocks)):    
            tmpDecoded += str(calculateDeCrypt(str(blocks[i]), keyData[1], keyData[0]))
        print(tmpDecoded)

        
    else: 
        print("keyfile is incorrect")


def prime_factors(n) -> []:
    """
    Get the prime factors for a number
    """
    i = 2
    factors = []
    while i * i <= n:
        if n % i:
            i += 1
        else:
            n //= i
            factors.append(i)
    if n > 1:
        factors.append(n)
    return factors

def genED(nn: int) -> []:
    """
    generate the E and D numbers
    """
    found = False
    i = 0
    
    while not found:
        # i don't understand this code but it generates a temp number
        i += 1
        temp = 1 + (i * nn)
        f=prime_factors(temp) #calculate the prime numbers for that number
        if(f != []):
            e = int(f[0]) # take the first one
            # print("e",e)
            f.remove(e)#remove it from the lsit  
            # multipley all the over one together
            d = 1
            for x in f:
                d = d * x
            # print("d",d)
            if(e!=d): # diffrent numbers
                if(isPrime(e) or isPrime(d)): # e or d is prime 
                    ed = e*d
                    if(not isPrime(ed)): # ed can not be prime
                            found = True
                            # print("ed", ed)
                            return [e,d,ed]
                    else:
                        print("ed can not be prime")
                else:
                    print("one number needs to be prime")
            else:
                print("e can not be equal to d")

def checkKeyFile(file : str,typ : str) -> bool:
    """
    check if a key file is or is not valid.
    the 3rd parameter is eiver "private" or "public" defining what key to generate
    """
    with open(file, "r") as file:
        first_line = file.readline()
        for last_line in file:
            pass
    
        if typ == "private" :
            if(first_line == "---begin monRSA private key---\n"):
                if(last_line == "---end monRSA key---"):
                    return True
            return False
        elif typ == "public" :
            if(first_line == "---begin monRSA public key---\n"):
                if(last_line == "---end monRSA key---"):
                    return True
            return False
        else :
            print("wrong type")
            return False

# entry point
generateKeys()
encode("test.pub", "Hello World! I hope you are having a great day!")
decode("test.priv", readFile("encoded"))