import primesieve
from random import *
import math
import base64
from textwrap import wrap
import argparse

verbose = False

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

def generateKeyFile(n: int, e: int, typ: str, filename: str):
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
        f = open("keys/" + filename + ".priv", "w")
        f.write("---begin " + filename + " private key---\n")
        f.write(key+'\n')
        f.write("---end " + filename + " key---")
        f.close()
    elif typ == "public" :
        f = open("keys/" + filename + ".pub", "w")
        f.write("---begin " + filename + " public key---\n")
        f.write(key+'\n')
        f.write("---end " + filename + " key---")
        f.close()
    else :
        print("wrong type")
        return

def generateKeys(filename: str):
    """
    General all the required numbers
    """
    p = primesieve.nth_prime(97885344)
    q = primesieve.nth_prime(85785656)
    #p = nth_prime(1256)
    #q = nth_prime(1478)
    if verbose : print("p", p)
    if verbose : print("q", q)
    n = p*q
    if verbose : print("n", n)
    nn = (p-1)*(q-1)
    if verbose : print("nn",nn)
    temp = genED(nn)
    e = temp[0]
    if verbose : print("e",e)
    d = temp[1]
    if verbose : print("d",d)
    ed = temp[2]
    if verbose : print("ed",ed)
    generateKeyFile(n, e, "public", filename)
    generateKeyFile(n, d, "private", filename)

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
    
    if verbose : print(param1,param2)
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

def encode(keyFile: str, string: str, filename: str=""):
    """
    Encode a file using the public key
    """
    print("Encoding message ...")
    print("Is public key file ok ?", checkKeyFile(keyFile,"public"))

    if (checkKeyFile(keyFile,"public")):        
        f = open(keyFile)
        keyData = extractParamsFromKey(f.readlines()[1]) # read the second line of the file and extract the param
        if verbose : print("keydata (publ) :", keyData)
        
        # take the string and reverse it (because we are doing everything from right to left)

        if verbose : print(string)
        
        # transform the ascii string into a series of numbers
        asciiToInt = ""
        for char in string :
            asciiToInt += str(ord(char)).zfill(3)
        if verbose : print("ascii to int", asciiToInt)

        # calculate the block length
        blocklen = len(str(keyData[0])) -1
        if verbose : print("block size is", blocklen)
        
        # split the string into blocks
        # start bu reversing the string so we can start left to right
        tmp = asciiToInt[::-1]
        # cut them
        blocks = wrap(tmp, blocklen)
        # reverse the lsit of cut
        blocks.reverse()
        # inside eecaht cut reserve the characters
        for i in range(len(blocks)):
            blocks[i] = blocks[i][::-1]
        if verbose : print(blocks)
        
        # make sur that every block is the corect length, overwise add padding
        for i in range(len(blocks)):
            blocks[i] = blocks[i].zfill(blocklen)
        if verbose : print("blocks after padding :", blocks)
        
        # crypt everyblock
        tempCryptString = ""
        if verbose : print("encrypted blocks:")
        for i in range(len(blocks)): 
            blockEncrypted = str(calculateCrypt(blocks[i], keyData[1], keyData[0]))
            if verbose : print(blockEncrypted)
            blockEncrypted = blockEncrypted.zfill(blocklen+1)
            if verbose : print(blockEncrypted)
            tempCryptString += blockEncrypted
        if verbose : print("encrypted string :",tempCryptString)
        
        # write the contentes to a file
        hexstr = intToHexToBase64(tempCryptString)
        if(filename == ""):
            print("Encrypted :")
            print(hexstr)
        else :
            writeToFile(filename, hexstr)
    else: 
        print("keyfile is incorrect")

def decode(keyFile: str, string : str, filename: str=""):
    """
    decode a file using the private key
    """
    print("Decoding message ...")
    print("Is private key file ok ?", checkKeyFile(keyFile,"private"))

    if (checkKeyFile(keyFile,"private")):        
        f = open(keyFile)
        keyData = extractParamsFromKey(f.readlines()[1]) # read the second line of the file and extract the param
        if verbose : print("keydata (priv) :", keyData)
        
        # get block length
        blocklen = len(str(keyData[0]))
        if verbose : print("block size is",blocklen)
        
        # transform hex to string
        string = str(base64ToHexToInt(string))
        #string = str(string)
        blocks = wrap(string, blocklen)

        # blocks = wrap(string, blocklen)
        if verbose : print("encrypted bloks", blocks)
        
        # decode for each block
        tmpDecoded = ""
        for i in range(len(blocks)):  
            blockDecoded = str(calculateDeCrypt(blocks[i], keyData[1], keyData[0]))
            if verbose : print(blockDecoded)
            blockDecoded = blockDecoded.zfill(blocklen-1)
            if verbose : print(blockDecoded)
            tmpDecoded += blockDecoded
        if verbose : print("decrypted ints :", tmpDecoded)
        

        # split the string into blocks
        # start bu reversing the string so we can start left to right
        tmp = tmpDecoded[::-1]
        # cut them
        blocks = wrap(tmp, 3)
        # reverse the lsit of cut
        blocks.reverse()
        # inside eecaht cut reserve the characters
        for i in range(len(blocks)):
            blocks[i] = blocks[i][::-1]
        if verbose : print(blocks)
        
        # make sur that every block is the corect length, overwise add padding
        for i in range(len(blocks)):
            if(len(str(blocks[i])) != 3):
                if verbose : print("adding padding")
                blocks[i] = blocks[i].zfill(3)
        if verbose : print("blocks after padding :", blocks)
        
        tmpfinal = ""
        for i in range(len(blocks)):  
            tmpfinal += blocks[i]
        
        # write the decoded string to a file
        if(filename == ""):
            print("Decrypted :")
            print(multipleIntsToChar(tmpDecoded))
        else :
            writeToFile(filename, multipleIntsToChar(tmpDecoded))
    else: 
        print("keyfile is incorrect")

def calculateCrypt(asci: int, e: int, n: int) -> int:
    """
    Calculate the crypt int
    """
    return pow(int(asci),e,n)

def calculateDeCrypt(asci: int, d: int, n: int) -> int:
    """
    Calculate the decrypt int
    """
    return pow(int(asci),d,n)

def intToHexToBase64(inputString: str) -> str: 
    """
    input = a string of numbers
    Takee a string, transform it to int then to hex then to base64
    """
    message = hex(int(inputString))
    message_bytes = message.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')
    return str(base64_message)

def base64ToHexToInt(inputString: str) -> str:
    """
    input = a base64 string
    Take the abse 64, make it  ahex then a string
    """
    inputString = base64.b64decode(inputString).decode('ascii')
    return int(inputString,0)

def multipleIntsToChar(inpt: str) -> str :
    """
    Transform a series of ints to ascii charasters
    basicly separate every 3 chars 
    """
    inpt = str(inpt)
    chars = wrap(inpt, 3)
    if verbose : print(chars)
    tmp = ""
    for c in chars:
        tmp += chr(int(c))
    if verbose : print(tmp)
    return tmp

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
            if verbose : print("e",e)
            f.remove(e)#remove it from the lsit  
            # multipley all the over one together
            d = 1
            for x in f:
                d = d * x
            if verbose : print("d",d)
            if(e!=d): # diffrent numbers
                if(isPrime(e) or isPrime(d)): # e or d is prime 
                    ed = e*d
                    if(not isPrime(ed)): # ed can not be prime
                            found = True
                            if verbose : print("ed", ed)
                            return [e,d,ed]
                    else:
                        if verbose : print("ed can not be prime")
                else:
                    if verbose : print("one number needs to be prime")
            else:
                if verbose : print("e can not be equal to d")

def checkKeyFile(file : str,typ : str) -> bool:
    """
    check if a key file is or is not valid.
    the 2nd parameter is eiver "private" or "public" defining what key to check
    """
    return True #TODO : improuve this
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

def parse_args():
    """
    Parse the arguments
    """
    parser = argparse.ArgumentParser()    
    parser.add_argument("action", help="Action to execute : keygen,crypt,decrypt,help")
    parser.add_argument("key", help="key to use")
    parser.add_argument("text", help="text to encrypt")
    parser.add_argument("-f", "--filename", help="name of the keys to use", default="")
    parser.add_argument("-s", "--size", help="size of the key size", default="10")
    parser.add_argument("-i", "--input", help="use a text file instead of a string", default=False)
    parser.add_argument("-o", "--output", help="name of the file to output instead of printing the output", default="")
    parser.add_argument("-v", "--verbose", help="Talk more", default=False)

    parser.add_subparsers
    return parser.parse_args()

# Entry point
args = parse_args()
print(args.verbose)
print(args.action)
print(args.key)
print(args.text)
print(args.filename)
print(args.input)
print(args.output)
print(args.size)


if args.action == "keygen":
    if(args.filename == ""): 
        # do not use a custom key name
        generateKeys("monRSA")
    else:
        # use a custom key name
        generateKeys(args.filename)
elif args.action == "crypt":
    if(args.input == ""):
        # use text passed in args
        encode(args.key, args.text)
    else : 
        # use files
        encode(args.key, readFile(args.text))

elif args.action == "decrypt":
    if(args.input == ""):
        # use text passed in args
        encode(args.key, args.text)
    else : 
        # use files
        decode(args.key, readFile(args.text))
