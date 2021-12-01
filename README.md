# ISITDTU CTF
## Where is your ticket?
> Source Challenge
```python
from Crypto.Cipher import AES
from hashlib import md5
import hmac
from os import urandom
import sys
import random
from binascii import hexlify, unhexlify
import secret
import socket
import threading
import socketserver
import signal

host, port = '0.0.0.0', 5000
BUFF_SIZE = 1024

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
	allow_reuse_address = True
class ThreadedTCPRequestHandler(socketserver.StreamRequestHandler):

	def handle(self):
		self.AES_BLOCK_SIZE = 32
		self.SIG_SIZE = md5().digest_size
		self.message = b'guest'
		self.key = self._hash_key(secret.key)
		self.enc_role, self.sig = self.encrypt(self.message)

		try:
			while True:
				self.menu()

				try:
					self.request.sendall(b'Your choice: ')
					opt = int(self.rfile.readline().decode())
				except ValueError:
					self.request.sendall(
						b'Invalid option!!!\n')
					continue
				if opt == 1:
					self.request.sendall(b'Data format: name=player101&role=enc_role&sign=sig, enc_role and sign are in hex.\n')
					self.request.sendall(b'Your data: ')
					data = self.rfile.readline().strip()
					self.confirm(data)
				elif opt == 2:
					self.request.sendall(b'Your data: ')
					data = self.rfile.readline().strip()
					if b'&role=' in data:
						self.request.sendall(b'Not that easy!\n')
					else:
						sign = self.sign_new(data)
						if sign == None:
							pass
						else:
							self.request.sendall(b"Hash: " + hexlify(sign) + b'\n')
				elif opt == 3:
					self.request.sendall(b'Your data: ')
					data = self.rfile.readline().strip()
					sign = self.sign_old(data)
					self.request.sendall(b"Hash: " + hexlify(sign) + b'\n')
				elif opt == 4:
					self.request.sendall(b'Goodbye!\n')
					return
				else:
					self.request.sendall(b'Invalid option!!!\n')

		except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
			print("{} disconnected".format(self.client_address[0]))

	def menu(self):
		self.request.sendall(b'\nYour role: ' + self.decrypt(b'name=player101&role='+hexlify(self.enc_role), hexlify(self.sig)))
		self.request.sendall(b'\nEncrypted data of your role:')
		self.request.sendall(b'\nEncrypted: ' + hexlify(self.enc_role))
		self.request.sendall(b'\nSignature: ' + hexlify(self.sig) + b'\n')
		self.request.sendall(b'1. Verify your data:\n')
		self.request.sendall(b'2. Sign your data in new way:\n')
		self.request.sendall(b'3. Sign your data in old way:\n')
		self.request.sendall(b'4. Quit\n')

	def _hash_key(self, key):
		return md5(key).digest()
	
	def _initialisation_vector(self):
		return urandom(16)
	
	def _cipher(self, key, iv):
		return AES.new(key, AES.MODE_CBC, iv)

	def encrypt(self, data):
		iv = self._initialisation_vector()
		cipher = self._cipher(self.key, iv)
		pad = self.AES_BLOCK_SIZE - len(data) % self.AES_BLOCK_SIZE
		data = data + (pad * chr(pad)).encode()
		data = iv + cipher.encrypt(data)
		ss = b'name=player101&role=%s'%(hexlify(data))
		sig = self.sign_new(ss)
		return data, sig
		
	def decrypt(self, data, sig):
		if hexlify(self.sign_new(data)) != sig:
			self.request.sendall(b'Message authentication failed')
			return
		else:
			pos = data.rfind(b'&role=')
			data = unhexlify(data[pos+6:])
			iv = data[:16]
			data = data[16:]
			cipher = AES.new(self.key, AES.MODE_CBC, iv)
			data = cipher.decrypt(data)
			return data[:-data[-1]]

	def XR(self, a, b):
		len_max = len(a) if len(a) > len(b) else len(b)
		s = ''
		for i in range(len_max):
			h = hex(a[i%len(a)] ^ b[i%len(b)])[2:]
			if(len(h) < 2):
				s += '0' + hex(a[i%len(a)] ^ b[i%len(b)])[2:]
			else:
				s += hex(a[i%len(a)] ^ b[i%len(b)])[2:]
		return unhexlify(s.encode())

	def xor_key(self, a):
		if isinstance(a, str):
			a = a.encode()
		b = self.key
		s = b''
		if len(a) > len(b):
			s += self.XR(a[:len(b)], b) + a[len(b):]
		elif len(a) < len(b):
			s += self.XR(b[:len(a)], a) + b[len(a):]
		return s

	def sign_old(self, data):
		return md5(self.xor_key(data)).digest()

	def sign_new(self, data):
		return hmac.new(self.key, data, md5).digest()

	def confirm(self, data):
		if isinstance(data, str):
			data = data.encode('utf-8')
		pos_name = data.rfind(b'name=')
		pos_role = data.rfind(b'&role=')
		pos_sign = data.rfind(b'&sign=')
		if pos_role == -1 or pos_sign == -1 or pos_name == -1:
			self.request.sendall(b'\nInvalid data!\n')
			return
		enc_role = data[:pos_sign]
		sign = data[pos_sign + 6:]
		try:
			check = self.decrypt(enc_role, sign)
		except Exception:
			self.request.sendall(b'\nInvalid data!\n')
		if check == b'royal':
			self.request.sendall(b'\nFlag here: ' + secret.flag)
		elif check == b'guest':
			self.request.sendall(b'\nHello peasant!\n')
		elif check == None:
			self.request.sendall(b'\nYou\'re a intruder!!!\n')
		else:
			self.request.sendall(b'\nStranger!!!\n')

	def parse_qsl(self, query):
		m = {}
		parts = query.split(b'&')
		for part in parts:
			key, val = part.split(b'=')
			m[key] = val
		return m


def main():
	server = ThreadedTCPServer((host, port), ThreadedTCPRequestHandler)
	server_thread = threading.Thread(target=server.serve_forever)
	server_thread.daemon = True
	server_thread.start()
	print("Server loop running in thread:", server_thread.name)
	server_thread.join()

if __name__=='__main__':
	main()

```

~~Bài này lúc đó mình không làm được :( write up lại cho nhớ thôi~~


Các option của bài : 
```
lethang29@DESKTOP-6U86GOO:~$ nc 34.125.6.66 5000

Your role: guest
Encrypted data of your role:
Encrypted: e75fb429ba9441507cba3d2b41d3d6b2ebe3d84db993c7377d91ab18f3fa62214d50dd3796c2e54022821b95d9feb156
Signature: b8587b5e1893bc9773a0655ba5ac3eb1
1. Verify your data:
2. Sign your data in new way:
3. Sign your data in old way:
4. Quit
Your choice: 1
Data format: name=player101&role=enc_role&sign=sig, enc_role and sign are in hex.
Your data: name=player101&role=e75fb429ba9441507cba3d2b41d3d6b2ebe3d84db993c7377d91ab18f3fa62214d50dd3796c2e54022821b95d9feb156&sign=b8587b5e1893bc9773a0655ba5ac3eb1

Hello peasant!

Your role: guest
Encrypted data of your role:
Encrypted: e75fb429ba9441507cba3d2b41d3d6b2ebe3d84db993c7377d91ab18f3fa62214d50dd3796c2e54022821b95d9feb156
Signature: b8587b5e1893bc9773a0655ba5ac3eb1
1. Verify your data:
2. Sign your data in new way:
3. Sign your data in old way:
4. Quit
Your choice: 2
Your data: lethang
Hash: 1885a0307a8b5fc9fec64d76852c5655

Your role: guest
Encrypted data of your role:
Encrypted: e75fb429ba9441507cba3d2b41d3d6b2ebe3d84db993c7377d91ab18f3fa62214d50dd3796c2e54022821b95d9feb156
Signature: b8587b5e1893bc9773a0655ba5ac3eb1
1. Verify your data:
2. Sign your data in new way:
3. Sign your data in old way:
4. Quit
Your choice: 3
Your data: lethang
Hash: 40ebc2333c280b36ea94001183a36062

Your role: guest
Encrypted data of your role:
Encrypted: e75fb429ba9441507cba3d2b41d3d6b2ebe3d84db993c7377d91ab18f3fa62214d50dd3796c2e54022821b95d9feb156
Signature: b8587b5e1893bc9773a0655ba5ac3eb1
1. Verify your data:
2. Sign your data in new way:
3. Sign your data in old way:
4. Quit
Your choice: 4
Goodbye!
```
## phân tích đề
Các bước xác thực để được flag : 
```python
if opt == 1:
    self.request.sendall(b'Data format: name=player101&role=enc_role&sign=sig, enc_role and sign are in hex.\n')
    self.request.sendall(b'Your data: ')
    data = self.rfile.readline().strip()
    self.confirm(data) 
 ```
 ```python
def confirm(self, data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    pos_name = data.rfind(b'name=')
    pos_role = data.rfind(b'&role=')
    pos_sign = data.rfind(b'&sign=')
    if pos_role == -1 or pos_sign == -1 or pos_name == -1:
        self.request.sendall(b'\nInvalid data!\n')
        return
    enc_role = data[:pos_sign]
    sign = data[pos_sign + 6:]
    try:
        check = self.decrypt(enc_role, sign)
    except Exception:
        self.request.sendall(b'\nInvalid data!\n')
    if check == b'royal':
        self.request.sendall(b'\nFlag here: ' + secret.flag)
    elif check == b'guest':
        self.request.sendall(b'\nHello peasant!\n')
    elif check == None:
        self.request.sendall(b'\nYou\'re a intruder!!!\n')
    else:
        self.request.sendall(b'\nStranger!!!\n')
```
```python
def decrypt(self, data, sig):
    if hexlify(self.sign_new(data)) != sig:
        self.request.sendall(b'Message authentication failed')
        return
    else:
        pos = data.rfind(b'&role=')
        data = unhexlify(data[pos+6:])
        iv = data[:16]
        data = data[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        data = cipher.decrypt(data)
        return data[:-data[-1]]
```
Ta có các dữ kiện :
* `Encrypted = enc_role = iv + AES_CBC("guest"+padding)` 
* `Signature = sign_new("name=player101&role=(enc_role)") tạo chữ kí bằng hmac-md5`
* `Các hàm encrypt(), decrypt(), sign_old() and sign_new() đề dùng chung 1 key = self._hash_key(secret.key) = 16bytes`

Bây giờ muốn bypass :
* đầu tiên ta cần sửa `Encrypted` sao cho server decrypt thành `"royal"+padding` thay vì là `"guest"+padding` như cũ. Việc này có thể làm được bằng Bit Flip Attack
* Tiếp theo là tính được `hmac_md5("name=player101&role=(enc_role)")` lưu ý là ta không có key nên không tính trực tiếp được, phải dựa vào sign_new hoặc sign_old.
* nếu xong 2 bước trên thì ta chỉ cần gửi enc_role mới và sig mới `f"name=player101&role={enc_role}&sign={sig}"` là nhận được flag thôi.

## Tấn công
### Bit flip
Ý tưởng về lật bit :

![image](https://user-images.githubusercontent.com/72289126/144277703-c6b0e3b9-f8f4-43f0-b471-104d34d89615.png)

### HMAC Implementation
```function hmac is
    input:
        key:        Bytes    // Array of bytes
        message:    Bytes    // Array of bytes to be hashed
        hash:       Function // The hash function to use (e.g. SHA-1)
        blockSize:  Integer  // The block size of the hash function (e.g. 64 bytes for SHA-1)
        outputSize: Integer  // The output size of the hash function (e.g. 20 bytes for SHA-1)
 
    // Keys longer than blockSize are shortened by hashing them
    if (length(key) > blockSize) then
        key ← hash(key) // key is outputSize bytes long

    // Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
    if (length(key) < blockSize) then
        key ← Pad(key, blockSize) // Pad key with zeros to make it blockSize bytes long

    o_key_pad ← key xor [0x5c  blockSize]   // Outer padded key
    i_key_pad ← key xor [0x36  blockSize]   // Inner padded key

    return  hash(o_key_pad ∥ hash(i_key_pad ∥ message))
```
![image](https://user-images.githubusercontent.com/72289126/144278646-619c2b99-6569-4f40-bd52-8b88ddf9e23a.png)

Mình có đọc được write up một bài tương tự : https://github.com/smokeleeteveryday/CTF_WRITEUPS/tree/master/2015/CONFIDENCE_TEASER/crypto/machacking

Ta đã biết HMAC hoạt động ra sao, giờ hãy quay lại bài, ta có thể sử dụng sign_old để tính cái đoạn H(K^i_pad||m) này : 
![image](https://user-images.githubusercontent.com/72289126/144284261-d601066d-536e-49b7-9409-45976fa6d226.png)

Nếu ta gửi `b'\x36'*64+msg` cho sign_old ta có thể tính được H = md5(i_key_pad + msg).digest()
```python
from binascii import hexlify, unhexlify
from hashlib import md5
from os import urandom

key = urandom(16)

def XR( a, b):
    len_max = len(a) if len(a) > len(b) else len(b)
    s = ''
    for i in range(len_max):
        h = hex(a[i % len(a)] ^ b[i % len(b)])[2:]
        if (len(h) < 2):
            s += '0' + hex(a[i % len(a)] ^ b[i % len(b)])[2:]
        else:
            s += hex(a[i % len(a)] ^ b[i % len(b)])[2:]
    return unhexlify(s.encode())

def xor_key(a):
    if isinstance(a, str):
        a = a.encode()
    b = key
    s = b''
    if len(a) > len(b):
        s += XR(a[:len(b)], b) + a[len(b):]
    elif len(a) < len(b):
        s += XR(b[:len(a)], a) + b[len(a):]
    return s


def sign_old(data):
    return md5(xor_key(data)).digest()


trans_5C = bytearray((x ^ 0x5c) for x in range(256))
trans_36 = bytearray((x ^ 0x36) for x in range(256))
blocksize = md5().block_size # 64

def hmac_md5(key, msg):
   if len(key) > blocksize:
       key = md5(key).digest()
   key = key + bytearray(blocksize - len(key))
   o_key_pad = key.translate(trans_5C)
   i_key_pad = key.translate(trans_36)
   print(md5(i_key_pad + msg).digest())
   return #md5(o_key_pad + md5(i_key_pad + msg).digest()).digest()

msg = b'lethethang'
print(hmac_md5(key,msg))

print(sign_old(b'\x36'*64+msg))
```
Tương tự để tìm HMAC cuối cùng ta chỉ việc gửi `b'\x5c'*64+H(vừa tìm được)` là có thể có được chữ kí mà không cần key rồi :D

### Script
```python
from pwn import *
from Crypto.Cipher import AES
from hashlib import md5
import hmac
from Crypto.Util.Padding import pad,unpad

r = remote("34.125.6.66",5000)
r.recvuntil(b"Encrypted: ")
Encrypted = r.recvline().strip().decode()
print(f"Encrypted = {Encrypted}")
Encrypted = bytes.fromhex(Encrypted)
iv = Encrypted[:16]
role_enc = Encrypted[16:] # enc(pad(b"guest",32))
print("[+] Bit flip attack")
print(f"iv old = {iv.hex()}")
print(f"role_enc = {role_enc.hex()}")
target = pad(b"royal",32)
iv = xor(xor(pad(b"guest",32)[:16],pad(b"royal",32)[:16]),iv)
print(f"iv new = {iv.hex()}")
Encrypted = iv+role_enc
print(f"Encrypted new = {Encrypted.hex()}")

print("[+] exploit")
r.recvuntil(b"Your choice:")
r.sendline(b"3")
msg = f"name=player101&role={Encrypted.hex()}".encode()
data = b"\x36"*64+msg
r.recvuntil(b"Your data:")
r.sendline(data)
r.recvuntil(b"Hash: ")
H = r.recvline().strip().decode()
print(f"H = {H}")
H = bytes.fromhex(H)

r.recvuntil(b"Your choice:")
r.sendline(b"3")
data = b"\x5c"*64+H
r.recvuntil(b"Your data:")
r.sendline(data)
r.recvuntil(b"Hash: ")
HMAC = r.recvline().strip().decode()
print(f"HMAC = {HMAC}")

print("[+] Verify")
enc_role = Encrypted.hex()
sig = HMAC
print(f"enc_role = {enc_role}")
print(f"sig = {sig}")
r.recvuntil(b"Your choice:")
r.sendline(b"1")
r.recvuntil(b"Your data: ")
data = f"name=player101&role={enc_role}&sign={sig}".encode()
r.sendline(data)
r.recvline()
print(r.recvline())
#ISITDTU{p34s4nts_w1LL_n0T_f1Nd_mY_S3cr3t}
```


