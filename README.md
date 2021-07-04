# myRSA

DIY RSA implementation from scratch

- [myRSA](#myrsa)
  - [instalation](#instalation)
  - [Verbose](#verbose)
  - [Generate keys](#generate-keys)
  - [encode](#encode)
  - [decode](#decode)

## instalation

Install all the requierments in requierments.txt `pip install -r requirements.txt`

## Verbose

You can add `-v` or `--verbose` for debug information

## Generate keys

Generate a key ( default size (10))
`python rsa.py keygen`

Generate a key with custom key size
`python rsa.py keygen -s 15`

## encode

With text in the command:
`python rsa.py crypt -k monRSA.pub -t "my test Text"`

With files:
`python rsa.py crypt -k monRSA.pub -t myFile.txt -i`

Export to a file:
`python rsa.py crypt -k monRSA.pub -t "my test Text" -o output.txt`

## decode

With text in the command:
`python rsa.py decrypt -k monRSA.priv -t "MyEncryptedSting"`

With files:
`python rsa.py decrypt -k monRSA.priv -t myFile.txt -i` 

Export to a file:
`python rsa.py crypt -k monRSA.pub -t "my test Text" -o output.txt`
