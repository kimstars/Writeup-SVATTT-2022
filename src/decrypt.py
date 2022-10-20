from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

data = open("secret.ascis","rb")

key = "ASCIS{1t_i5_v3Ry_str0nG_p@S5w0Rd}"
start = data.read(8)
phSalt = data.read(16) # salt 
phIV = data.read(16) # iv 
phsth = data.read(4)
phEnc = data.read()

keyhash = PBKDF2(key, phSalt, 32, count=20000,hmac_hash_module=SHA256)

# keyhash = b"\xEF\x04\x7D\x26\x02\x2A\xB9\xC1\x73\x6B\xA2\x25\xC1\x06\x48\x64\x51\xDD\xEE\x1F\x05\x47\xAF\x06\x3B\xB9\x3F\xBB\x0B\x1D\x13\xC1"

cipher = AES.new(keyhash, AES.MODE_CBC, phIV)
plaintext = cipher.decrypt(phEnc)
print(plaintext[:30])
with open("sec.zip","wb") as f:
    f.write(plaintext)




