import base64

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