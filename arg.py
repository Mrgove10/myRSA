import argparse

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", help="Action to execute : keygen,crypt,decrypt,help")
    parser.add_argument("key")
    parser.add_argument("text")
    parser.add_argument("-f", "--filename", help="name of the keys to use", default="")
    parser.add_argument("-s", "--size", help="size of the key size", default="10")
    parser.add_argument("-i", "--input", help="use a text file instead of a string", default=False)
    parser.add_argument("-o", "--output", help="name of the file to output instead of printing the output", default="")
    return parser.parse_args()

print(parse_args())
print(parse_args().action)
print(parse_args().key)
print(parse_args().text)
print(parse_args().filename)
print(parse_args().input)
print(parse_args().output)
print(parse_args().size)

if parse_args().action == "keygen":
    print("keygen")
elif parse_args().action == "crypt":
    print("cryptage")
elif parse_args().action == "decrypt":
    print("decryptage")
