import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii

#AES implementation
def aes_encrypt(plain_text, key_hex, iv_hex):
    key = binascii.unhexlify(key_hex)
    iv = binascii.unhexlify(iv_hex)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text.encode(), AES.block_size))
    encoded_text = base64.b64encode(cipher_text).decode()
    return encoded_text

def aes_decrypt(encoded_text, key_hex, iv_hex):
    key = binascii.unhexlify(key_hex)
    iv = binascii.unhexlify(iv_hex)
    cipher_text = base64.b64decode(encoded_text)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_text = unpad(cipher.decrypt(cipher_text), AES.block_size).decode()
    return decrypted_text

#Data in offset value
def get_data(file_path, offset_hex):
    with open(file_path, "rb") as file:
        offset = int(offset_hex, 16)  
        file.seek(offset)
        
        ascii_string = ""
        byte_value = file.read(1) 
        
        while byte_value != b'\x00': 
            ascii_string += byte_value.decode()
            byte_value = file.read(1)
        
    return ascii_string

file_path = "asd" #Invicta Stealer binary
offset_hex = "001E4460"  #AES encrypted C2 offset

ascii_string = get_data(file_path, offset_hex)


key_hex = '00000000000000000000000000000000'  #AES KEY
iv_hex = '00000000000000000000000000000000'   #AES IV
decrypted_text = aes_decrypt(ascii_string, key_hex, iv_hex)
print("Invicta Stealer C2:", decrypted_text)

