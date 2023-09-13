import base64
from Crypto.Protocol import KDF
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import argparse

def decryptKey(cipherText, passPhrase, 
               saltValue, passwordIterations, 
               initVector, keySize):
    cipherDecoded = base64.b64decode(cipherText)

    decryptionKey = KDF.PBKDF2(passPhrase, saltValue, count=passwordIterations, dkLen=round(keySize/8))

    aes = AES.new(decryptionKey, AES.MODE_CBC, initVector.encode('utf-8'))

    plainTextPadded = aes.decrypt(cipherDecoded)

    plainText = unpad(plainTextPadded, AES.block_size).decode('utf-8')

    return plainText

def main():
    parser = argparse.ArgumentParser(description='Decrypts the password used to encrypt the NtfsPermissionsReporter database.')
    parser.add_argument('cipherText', help='The encrypted password')

    args = parser.parse_args()
    cipherText = args.cipherText

    passPhrase = "Cjwd3v"
    saltValue = "Y5ug0tM1"
    passwordIterations = 2
    initVector = "114R52RABDL89413"
    keySize = 256

    try:
        plainText = decryptKey(cipherText, passPhrase, saltValue, passwordIterations, initVector, keySize)
        print(plainText)
    except:
        print("Error decrypting password. Check your input.")

if __name__ == "__main__":
    main()