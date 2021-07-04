from utils import writeToFile, readFile, isPrime, intToHexToBase64, base64ToHexToInt
import primesieve
from random import *
import math
import base64
from textwrap import wrap
import argparse

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
        f = open(filename + ".priv", "w")
        f.write("---begin " + filename + " private key---\n")
        f.write(key+'\n')
        f.write("---end " + filename + " key---")
        f.close()
    elif typ == "public" :
        f = open(filename + ".pub", "w")
        f.write("---begin " + filename + " public key---\n")
        f.write(key+'\n')
        f.write("---end " + filename + " key---")
        f.close()
    else :
        print("wrong type")
        return

def generateKeys(filename: str="monRSA", keylength: int=10):
    """
    General all the required numbers
    """
    minn = int("1".ljust(int(keylength/2), '0'))
    maxx = int("9".ljust(int(keylength/2), '9'))
    if args.verbose : print("min max of the possble primes :", minn, maxx)
    pos1 = randint(minn, maxx)
    pos2 = randint(minn, maxx)

    if args.verbose : print("position of the primes chosen :", pos1, pos2)
    p = primesieve.nth_prime(pos1)
    q = primesieve.nth_prime(pos2)
    
    # fixed values used to generate my key paire (i don't care if you hack me)
    # p = primesieve.nth_prime(97885344)
    # q = primesieve.nth_prime(85785656)
    
    # smaller primes used for testing
    # p = nth_prime(1256)
    # q = nth_prime(1478)
    
    if args.verbose : print("p", p)
    if args.verbose : print("q", q)
    n = p*q
    if args.verbose : print("n", n)
    if args.verbose : print("length", len(str(n)))
    nn = (p-1)*(q-1)
    if args.verbose : print("nn",nn)
    temp = genED(nn)
    e = temp[0]
    if args.verbose : print("e",e)
    d = temp[1]
    if args.verbose : print("d",d)
    ed = temp[2]
    if args.verbose : print("ed",ed)
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
    
    if args.verbose : print(param1,param2)
    return [param1,param2]

def encode(keyFile: str, string: str="", inputFile: str="", outputFile:str="") -> str:
    """
    Encode a file using the public key
    """
    print("Encoding message ...")
    print("Is public key file ok ?", checkKeyFile(keyFile,"public"))

    if (checkKeyFile(keyFile,"public")):        
        f = open(keyFile)
        keyData = extractParamsFromKey(f.readlines()[1]) # read the second line of the file and extract the param
        if args.verbose : print("keydata (publ) :", keyData)
        
        #open a file if the string is empty
        if(string == ""):
            string = str(readFile(inputFile))
        else:
            string = string

        # transform the ascii string into a series of numbers
        asciiToInt = ""
        for char in string :
            asciiToInt += str(ord(char)).zfill(3)
        if args.verbose : print("ascii to int", asciiToInt)

        # calculate the block length
        blocklen = len(str(keyData[0])) -1
        if args.verbose : print("block size is", blocklen)
        
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
        if args.verbose : print(blocks)
        
        # make sur that every block is the corect length, overwise add padding
        for i in range(len(blocks)):
            blocks[i] = blocks[i].zfill(blocklen)
        if args.verbose : print("blocks after padding :", blocks)
        
        # crypt everyblock
        tempCryptString = ""
        if args.verbose : print("encrypted blocks:")
        for i in range(len(blocks)): 
            blockEncrypted = str(calculateCrypt(blocks[i], keyData[1], keyData[0]))
            if args.verbose : print(blockEncrypted)
            blockEncrypted = blockEncrypted.zfill(blocklen+1)
            if args.verbose : print(blockEncrypted)
            tempCryptString += blockEncrypted
        if args.verbose : print("encrypted string :",tempCryptString)
        
        # write the contentes to a file
        hexstr = intToHexToBase64(tempCryptString)
        if(outputFile == ""):
            print("Encrypted :")
            print(hexstr)
        else :
            print("writing to file", outputFile)
            writeToFile(outputFile, hexstr)
        return hexstr
    else: 
        print("keyfile is incorrect")
        return

def decode(keyFile: str, string : str="", inputFile: str="", outputFile:str="") -> str:
    """
    decode a file using the private key
    """
    print("Decoding message ...")
    print("Is private key file ok ?", checkKeyFile(keyFile,"private"))

    if (checkKeyFile(keyFile,"private")):        
        f = open(keyFile)
        keyData = extractParamsFromKey(f.readlines()[1]) # read the second line of the file and extract the param
        if args.verbose : print("keydata (priv) :", keyData)
        
        # get block length
        blocklen = len(str(keyData[0]))
        if args.verbose : print("block size is",blocklen)

        # open a file if the string is empty
        if(string == ""):
            # transform hex to string
            string = str(base64ToHexToInt(str(readFile(inputFile))))
        else:
            # transform hex to string
            string = str(base64ToHexToInt(string))

        # add padding to have the correct length 
        if (len(string) % blocklen != 0):
            if args.verbose : print("not the correct legnth")
            rem = len(string) % blocklen 
            if args.verbose : print(rem)
            pad = blocklen - rem
            if args.verbose : print(pad)
            string = string.zfill(len(string)+pad)
        
        blocks = wrap(string, blocklen)
        if args.verbose : print("encrypted bloks", blocks)
        
        # decode for each block
        tmpDecoded = ""
        for i in range(len(blocks)):  
            blockDecoded = str(calculateDeCrypt(blocks[i], keyData[1], keyData[0]))
            if args.verbose : print(blockDecoded)
            blockDecoded = blockDecoded.zfill(blocklen-1)
            if args.verbose : print(blockDecoded)
            tmpDecoded += blockDecoded
        if args.verbose : print("decrypted ints :", tmpDecoded)

        # split the string into blocks
        # start bu reversing the string so we can start left to right
        tmp = tmpDecoded[::-1]
        # cut them
        blocks_ascii = wrap(tmp, 3)
        # reverse the lsit of cut
        blocks_ascii.reverse()
        # inside eecaht cut reserve the characters
        for i in range(len(blocks_ascii)):
            blocks_ascii[i] = blocks_ascii[i][::-1]
        if args.verbose : print(blocks_ascii)

        # make sur that every block is the corect length, overwise add padding
        for i in range(len(blocks_ascii)):
            if(len(str(blocks_ascii[i])) != 3):
                if args.verbose : print("adding padding for ascii")
                blocks_ascii[i] = blocks_ascii[i].zfill(3)
        if args.verbose : print("blocks after padding :", blocks_ascii)
        
        string = ""
        for c in blocks_ascii:
            string += chr(int(c))
        
        # write the decoded string to a file
        if(outputFile == ""):
            print("Decrypted :")
            print(string)
        else :
            writeToFile(outputFile, string)
        return string
    else: 
        print("keyfile is incorrect")
        return

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
            if args.verbose : print("e",e)
            f.remove(e)#remove it from the lsit  
            # multipley all the over one together
            d = 1
            for x in f:
                d = d * x
            if args.verbose : print("d",d)
            if(e!=d): # diffrent numbers
                if(isPrime(e) or isPrime(d)): # e or d is prime 
                    ed = e*d
                    if(not isPrime(ed)): # ed can not be prime
                            found = True
                            if args.verbose : print("ed", ed)
                            return [e,d,ed]
                    else:
                        if args.verbose : print("ed can not be prime")
                else:
                    if args.verbose : print("one number needs to be prime")
            else:
                if args.verbose : print("e can not be equal to d")

def checkKeyFile(file : str, typ : str) -> bool:
    """
    check if a key file is or is not valid.
    the 2nd parameter is eiver "private" or "public" defining what key to check
    """
    return True
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
    parser.add_argument("action", help="Action to execute : keygen,crypt,decrypt", type=str)
    parser.add_argument("-k", "--key", help="key to use", type=str, default="")
    parser.add_argument("-t", "--text", help="text to encrypt", type=str, default="")
    parser.add_argument("-f", "--filename", help="name of the keys to use", type=str, default="monRSA")
    parser.add_argument("-s", "--size", help="size of the key generated", type=int, default="10")
    parser.add_argument("-i", "--input", help="use a text file instead of a string", type=str, default="")
    parser.add_argument("-o", "--output", help="name of the file to output instead of printing the output", type=str, default="")
    parser.add_argument("-v", "--verbose", help="Talk more", action="store_true")
    return parser.parse_args()

# Entry point
args = parse_args()
if(args.verbose):
    print("Arguments :")
    print("verbose :",args.verbose)
    print("action :",args.action)
    print("key :",args.key)
    print("text :",args.text)
    print("filename :",args.filename)
    print("input :",args.input)
    print("output :",args.output)
    print("size :",args.size)
    print("end arguments")

if args.action == "keygen":
    generateKeys(args.filename,args.size )      
elif args.action == "crypt":
    encode(args.key, args.text, args.input, args.output)
elif args.action == "decrypt":
    decode(args.key, args.text, args.input, args.output)
elif args.action == "test":
    # this is for fast testing
    generateKeys()
    #1 
    encode("monRSA.pub", "Hello World ! Welcome to my RSA implementation ! :)", outputFile="1.test")
    decode("monRSA.priv", inputFile="1.test", outputFile="1_decode.test")
    #2
    encode("monRSA.pub", "my test Text", outputFile="2.test")
    decode("monRSA.priv", inputFile="2.test", outputFile="2_decode.test")
    #3
    encode("monRSA.pub", inputFile="AllAsciiCharacters.txt", outputFile="3.test")
    decode("monRSA.priv", inputFile="3.test", outputFile="3_decode.test" )
    #4
    encode("monRSA.pub", inputFile="AllAsciiCharacters.txt", outputFile="4.test")
    decode("monRSA.priv", inputFile="4.test", outputFile="4_decode.test")
    #5
    encode("monRSA.pub", inputFile="LICENSE.md", outputFile="5.test")
    decode("monRSA.priv", inputFile="5.test", outputFile="5_decode.test")
