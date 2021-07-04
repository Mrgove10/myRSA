# myRSA

DIY RSA implementation from scratch

- [myRSA](#myrsa)
  - [instalation](#instalation)
  - [Verbose](#verbose)
  - [Generate keys](#generate-keys)
  - [encode](#encode)
  - [decode](#decode)
  - [Bugs](#bugs)
    - [size paraeter not working](#size-paraeter-not-working)
    - [Wierd ascii](#wierd-ascii)

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
`python rsa.py crypt -k monRSA.pub -i myFile.txt`

Export to a file:
`python rsa.py crypt -k monRSA.pub -i myFile.txt -o output.txt`

## decode

With text in the command:
`python rsa.py decrypt -k monRSA.priv -t "MHg5NzEwOTg0YTE2OGYxNjU5NmNkYjgwYTc2Yzg4YTc="`

With files:
`python rsa.py decrypt -k monRSA.priv -i output.txt`

Export to a file:
`python rsa.py crypt -k monRSA.pub -t "my test Text" -o output.txt`

## Bugs

This implementation is far from perfect.

### size paraeter not working

The -s param is not working correctly, don't expect anything from it
### Wierd ascii

It may happen that sometimes some invisble asci characters are generated at the start of the decoded string, like this :

![Sample of the error](https://i.imgur.com/0Gm7Pzt.png)

This is not visible when you use it in the console (so i suggest you do that and hide the error).
