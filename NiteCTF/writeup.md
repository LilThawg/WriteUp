# NiteCTF

## Variablezz

```Description : Too many variables. Idk what to do. Can you help?```

`enc.py`

```python
import random
flag = 'nite{XXXXXXXXXXXXXXXXXXXXXXXX}'
a = random.randint(1,9999999999)
b = random.randint(1,9999999999)
c = random.randint(1,9999999999)
d = random.randint(1,9999999999)
enc = []
for x in flag:
    res = (a*pow(ord(x),3)+b*pow(ord(x),2)+c*ord(x)+d)
    enc.append(res)
print(enc)
```

`ciphertext.txt`

```
Ciphertext = [8194393930139798, 7130326565974613, 9604891888210928, 6348662706560873, 11444688343062563, 7335285885849258, 3791814454530873, 926264016764633, 9604891888210928, 5286663580435343, 5801472714696338, 875157765441840, 926264016764633, 2406927753242613, 5980222734708251, 5286663580435343, 2822500611304865, 5626320567751485, 3660106045179536, 2309834531980460, 12010406743573553]
```
res được tính theo phương trình : 

<img src="https://latex.codecogs.com/svg.image?f(x)&space;=&space;ax^{3}&plus;bx^{2}&plus;cx&plus;d" title="f(x) = ax^{3}+bx^{2}+cx+d" />

với a,b,c,d ngẫu nhiên và x là ord(charFlag).

Lập hệ 4 phương trình 4 ẩn a,b,c,d ta sẽ tìm lại được a,b,c,d sau đó
thay vào f(x) là có thể giải được x.

`solve.sage`
```sage
var('a b c d')
eq1 = (a*pow(ord('n'),3)+b*pow(ord('n'),2)+c*ord('n')+d)==8194393930139798
eq2 = (a*pow(ord('i'),3)+b*pow(ord('i'),2)+c*ord('i')+d)==7130326565974613
eq3 = (a*pow(ord('t'),3)+b*pow(ord('t'),2)+c*ord('t')+d)==9604891888210928
eq4 = (a*pow(ord('e'),3)+b*pow(ord('e'),2)+c*ord('e')+d)==6348662706560873

res = solve([eq1,eq2,eq3,eq4],a,b,c,d)[0] 
a,b,c,d = (int(str(res[i])[5:]) for i in range(4))

ciphertext = [8194393930139798, 7130326565974613, 9604891888210928, 6348662706560873, 11444688343062563, 7335285885849258, 3791814454530873, 926264016764633, 9604891888210928, 5286663580435343, 5801472714696338, 875157765441840, 926264016764633, 2406927753242613, 5980222734708251, 5286663580435343, 2822500611304865, 5626320567751485, 3660106045179536, 2309834531980460, 12010406743573553]
plaintext = ''
for i in ciphertext:
    var('x')
    eq = (a*pow(x,3)+b*pow(x,2)+c*x+d)==i
    p=int(str(solve(eq,x)[2])[5:])
    plaintext+=chr(p)
print(plaintext)
#nite{jU5t_b45Ic_MaTH}
```

## Rabin To The Rescue
```
Description : It may look like a piece of cake, but you need to dive deep into it.
```

`rabin_to_the_rescue.py`

```python
from Crypto.Util.number import *
from sympy import *
import random

def mixer(num):
    while(num>1):
        if(int(num) & 1):
            num=3*num+1
        else:
            num=num/2
    return num

def gen_sexy_primes():
    p=getPrime(256)
    q=p+6

    while((p%4!=3)or(q%4!=3)):
        p=getPrime(256)
        q=nextprime(p+1)
    return p, q

p, q=gen_sexy_primes()
n=p*q
    

def encrypt(m, e, n):
    return pow(m, e, n)
    
e=int(mixer(q-p))*2

print("________________________________________________________________________________________________")
print("\n\n")
print("-----------------------------------")
print("-----------------------------------")
print("-----------------------------------")
print("               /\\")
print("            __/__\\__")
print("            \\/    \\/")
print("            /\\____/\\")
print("            ``\\  /``  ")
print("               \\/")
print("-----------------------------------")
print("-----------------------------------")
print("-----------------------------------")
print("\n\n")
print("Welcome to the Encryption challenge!!!!")
print("\n")
print("Menu:")
print("=> [E]ncrypt your message")
print("=> [G]et Flag")
print("=> E[x]it")
print("________________________________________________________________________________________________")

while(true):
    choice=input(">>")
    if choice.upper()=='E':
        print("Enter message in hex:")
        try:
            m=bytes_to_long(bytes.fromhex(input()))
        except:
            print("Wrong format")
            exit(0)
        ciphertext=encrypt(m,e,n)
        print("Your Ciphertext is: ")
        print(hex(ciphertext)[2:])
    elif choice.upper()=='G':
        print("Your encrypted flag is:")
        with open('flag.txt','rb') as f:
            flag=bytes_to_long(f.read())
        t=random.randint(2, 2*5)
        for i in range(t):
            ciphertext=encrypt(flag,e,n)
        print(hex(ciphertext)[2:])
    elif choice.upper()=='X':
        print("Exiting...")
        break
    else:
        print("Please enter 'E','G' or 'X'")
```
```commandline
Menu:
=> [E]ncrypt your message
=> [G]et Flag
=> E[x]it
________________________________________________________________________________________________
>>E
Enter message in hex:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Your Ciphertext is:
147e5bb4dadd22737ba35209b4dad36e991da698b0f222a710b6d8d72e08a07426a2aaebee3a230c69cec2e813d1b56d41aa450f0950d9fb8eb25a38683b3edb
>>E
Enter message in hex:
ABCD
Your Ciphertext is:
734b8229
>>G
Your encrypted flag is:
1b1948ee40d9965832cfd824e7c4fab5ea7818af23d11e2a4135cde10c1682f2ccdad7dbafd43cf97fb0d6f8f3dc02e5262c89ea279fcabbb2853401ec347323
>>X
Exiting...
```

Một bài RSA :) có 2 chức năng là Encrypt msg và Encrypt flag

Oracle chỉ trả về ciphertext không trả về e,n giờ muốn decryt
việc đầu tiên ta cần làm là : `recover n`.

Ta biết rằng : 

<img src="https://latex.codecogs.com/svg.image?\\&space;c1&space;\equiv&space;(m1)^e&space;\mod&space;n&space;\\&space;c2&space;\equiv&space;(m2)^e&space;\mod&space;n" title="\\ c1 \equiv (m1)^e \mod n \\ c2 \equiv (m2)^e \mod n" />

Hay có thể viết : 

<img src="https://latex.codecogs.com/svg.image?\\&space;c1&space;-&space;(m1)^e&space;=&space;k*n&space;\\&space;c2&space;-&space;(m2)^e&space;=&space;h*n" title="\\ c1 - (m1)^e = k*n \\ c2 - (m2)^e = h*n" />

Tới đây ta có thể dễ dàng tính gcd(c1-m1e,c2-m2e) là có thể tìm được bội số n.

Tìm được n xong thì mọi thứ đơn giản rồi :) vì dùng fermat attack ta có thể tìm được p,q

Từ đó ta có thể giải mã rabin ~~hôm đó ngu quá, không để ý đây là rabin nên giải theo RSA mãi đ ra :(~~ 
`script.py` 

```python
from pwn import *
import random
import math
import gmpy2
import egcd
from Crypto.Util.number import *

r = remote("rabin.challenge.cryptonite.team",1337)

r.recvuntil(b">>")
r.sendline(b"E")
r.recvuntil(b"Enter message in hex:")
m1 = random.getrandbits(256) 
m1e = m1**2
m1hex = hex(m1)[2:]
if len(m1hex)%2==1:
    m1hex="0"+m1hex
r.sendline(m1hex.encode())
r.recvuntil(b"Your Ciphertext is:")
r.recvline()
c1 = int(r.recvline().strip().decode(),16)
#print(c1)

r.recvuntil(b">>")
r.sendline(b"E")
r.recvuntil(b"Enter message in hex:")
m2 = random.getrandbits(256)
m2e = m2**2
m2hex = hex(m2)[2:]
if len(m2hex)%2==1:
    m2hex="0"+m2hex
r.sendline(m2hex.encode())
r.recvuntil(b"Your Ciphertext is:")
r.recvline()
c2 = int(r.recvline().strip().decode(),16)
#print(c2)

N = math.gcd(c1-m1e,c2-m2e)
print(N)

r.recvuntil(b">>")
r.sendline(b"G")
r.recvuntil(b"Your encrypted flag is:")
r.recvline()
encryptedFlag = int(r.recvline().strip().decode(),16)
#print(encryptedFlag)

def fermat_factor(n):
    assert n % 2 != 0
    a = gmpy2.isqrt(n)
    b2 = gmpy2.square(a) - n
    while not gmpy2.is_square(b2):
        a += 1
        b2 = gmpy2.square(a) - n
    p = a + gmpy2.isqrt(b2)
    q = a - gmpy2.isqrt(b2)
    return int(p), int(q)

p,q = fermat_factor(N)

def decryptRabin(p,q,c):
    assert p % 4 == 3 and q % 4 == 3
    n = p*q
    d, a, b = egcd.egcd(p, q)
    assert a * p + b * q == 1
    r = int(pow(c, (p + 1) // 4, p))
    s = int(pow(c, (q + 1) // 4, q))
    x = (a * p * s + b * q * r) % n
    y = (a * p * s - b * q * r) % n
    return x % n, -x % n, y % n, -y % n

res = decryptRabin(p,q,encryptedFlag)
for i in res :
    print(long_to_bytes(i))
```
```commandline
output
b'l\xca\xb5\xf1\xe5\xa43\'\x18\x9c\xc5\x7fF\xcb\xecb$\xa0A\xbc\x88\x12\xe5\xf9\xc8x \xce\x1f\xfc\xd3\x8c\xc9=~\xa4\xa4\xc4}?:\xed\x16\xa3\xbf\x8a\xa7U\xba"k\x18\xcd^\xd7:]x\xf6\x82\xdd\xe1\xdc\x8f'
b':Nc9\\X\xa2\x8d\xd2\x19Xp\xb7wg\xfc/\xf8\xb3\xf6l\xc6h\xfd{A$\xbe\xd3\xca \x1c\xd1\xdfh\x1e\x03\xf7\x08y\x95g\xfcA5\xe5\x8a\x05\xe5;\x91Y\n\xeco\xbdW\xb5\x14\x99x\x92\x94\xea'
b'nite{r3p34t3d_r461n_3ncrypt10n_l1tr4lly_k1ll5_3d6f4adc5e}'
b'\xa7\x19\x19+A\xfc\xd5F\x81A\xb8t\x8c\x0f\xe4+ $\xc2N\x95g\x1a\xc1\x12J\xe6Y\x85c\x810*\xa8\xb5\x92:\\\x19\x87[\xe2\xdex\x88\xf6\xd1\xf0m\xf1\x90<y\x17\xe2\xc1N\xf9\xa9\xb7\xf3?\x0b\xfc'
```

đọc thêm : https://github.com/ashutosh1206/Crypton/tree/master/RSA-encryption/Attack-Retrieve-Modulus

## Flip Me Over
```
Description : AES-CBC apparently had a lot of flippy stuff so we tried to strengthen it using our custom anti-flippy cbc implementation. Can you break this and get the flag?
```

Nghe tên bài + AES-CBC thì là bit flip chứ còn gì nữa =))

```python
from Crypto.Cipher import AES
from Crypto.Util.number import *
import os
from Crypto.Util.Padding import pad,unpad
from Crypto.Util.strxor import strxor
import random
import hashlib
FLAG = b'lethethang2909'

KEY = os.urandom(16)
entropy = hashlib.md5(os.urandom(128)).digest()

def generate_token(username):
    iv = os.urandom(16)
    try:
        pt = bytes.fromhex(username)
    except:
        print("Invalid input.")
        exit(0)
    if b'gimmeflag' in pt:
        print("Nah not allowed.")
        exit(0)
    cipher = AES.new(KEY,AES.MODE_CBC,iv)
    ct = cipher.encrypt(pad(pt,16))
    tag = b'\x00'*16
    for i in range(0,len(ct),16):
        tag = strxor(tag,ct[i:i+16])
    tag = strxor(tag,iv)
    tag = strxor(tag,entropy)
    return tag.hex()+ct.hex()

def verify(tag,token):
    try:
        tag = bytes.fromhex(tag)
        ct = bytes.fromhex(token)
    except:
        print("Invalid input")
        exit(0)
    for i in range(0,len(ct),16):
        tag = strxor(tag,ct[i:i+16])
    tag = strxor(tag,entropy)
    iv = tag
    cipher = AES.new(KEY,AES.MODE_CBC,iv)
    username = cipher.decrypt(ct)
    return username.hex()

print("Hello new user")
print("We shall allow you to generate one token:")
print("Enter username in hex():")
username = input()
token = generate_token(username)
print(token)
while True:
    print("Validate yourself :)")
    print("Enter token in hex():")
    token = input()
    print("Enter tag in hex():")
    tag = input()
    if b'gimmeflag'.hex() in verify(tag,token):
        print("Oh no u flipped me...")
        print("I am now officially flipped...")
        print("Here's ur reward...")
        print(FLAG)
        break
    else:
        print("Something went wrong...")
        print(f"Is your username {verify(tag,token)}")
        print("Smthin looks fishy")
        print("Pls try again :(")
        print()
    entropy = hashlib.md5(entropy).digest()
```

Bài này không khó, vẽ hình ra xíu là làm được à ...

```python
from pwn import *
from Crypto.Util.Padding import pad,unpad
r = remote("flipmeover.chall.cryptonite.team",1337)
r.recvuntil(b"Enter username in hex():")
username = (b"\x00"*9).hex()
r.sendline(username.encode())
r.recvline()
token = r.recvline().strip().decode()
tag = token[:32]
token = token[32:]
target = pad(b"gimmeflag",16)
tagFake = xor(bytes.fromhex(tag),target)
r.recvuntil(b"Enter token in hex():")
r.sendline(token.encode())
r.recvuntil(b"Enter tag in hex():")
r.sendline(tagFake.hex().encode())
r.interactive()
```

```
output
Oh no u flipped me...
I am now officially flipped...
Here's ur reward...
nite{flippity_floppity_congrats_you're_a_nerd}
```

## NJWT

`Description : Well we all know that JWT has a lot of issues. So we decided to make our own custom implementation called NotJWT. Hopefully its not vulnerable to the same things JWT is.`

`NJWT.py`

```python
import base64
from Crypto.Util.number import *
import sys
import random
import os
import sympy

class NJWT:
    n = 1
    e = 1
    d = 1

    def __init__(self):
        self.genkey()
        return

    def genkey(self):
        p = getStrongPrime(1024)
        q = p
        k = random.randint(0,100)
        for _ in range(k):
            q += random.randint(0,100)
        q = sympy.nextprime(q)
        self.n = p*q
        self.e = 17
        self.d = inverse(self.e,(p-1)*(q-1))
        return

    # Utility function to just add = to base32 to ensure right padding
    def pad(self,data):
        if len(data)%8 != 0:
            data += b"=" * (8-len(data)%8)
        return data

    def sign(self,token):
        sig = long_to_bytes(pow(bytes_to_long(token),self.d,self.n))
        return sig

    def generate_token(self,username):
        if 'admin' in username:
            print("Not authorized to generate token for this user")
            return "not_auth"

        header = b'{"alg": "notRS256", "typ": "notJWT"}'
        payload = b'{user : "' + username.encode() + b'", admin : False}'
        token = header + payload
        sig = self.sign(token)
        # Base-32 and underscores cuz its NOT JWT
        token = base64.b32encode(header).decode().strip("=") + "_" + base64.b32encode(payload).decode().strip("=") + "_" + base64.b32encode(sig).decode().strip("=")
        return token

    def verify_token(self,token):
        data = token.split("_")
        header = base64.b32decode(self.pad(data[0].encode()))
        if header != b'{"alg": "notRS256", "typ": "notJWT"}':
            return "invalid_header"

        payload = base64.b32decode(self.pad(data[1].encode()))

        if not b'admin : True' in payload:
            return "access_denied"
            
        given_sig = bytes_to_long(base64.b32decode(self.pad(data[2].encode())))
        msg = long_to_bytes(pow(given_sig,self.e,self.n))
        if msg == header+payload:
            return "Success"
        else:
            return "invalid_signature"
        return
```

~~bài này nghĩ cả ngày k ra mà lúc đọc wu nó dễ quá ạ :( f^ck~~ 

Vẫn là `recover n` nhưng lần này khi kí ta chỉ biết e và không biết d.

<img src="https://latex.codecogs.com/svg.image?\\&space;s1&space;\equiv&space;&space;(m1)^{d}&space;\mod&space;n\\\&space;s2&space;\equiv&space;&space;(m2)^{d}&space;\mod&space;n\&space;" title="\\ s1 \equiv (m1)^{d} \mod n\\\ s2 \equiv (m2)^{d} \mod n\ " />

Mũ e 2 vế ta được :

<img src="https://latex.codecogs.com/svg.image?\\&space;(s1)^{e}&space;\equiv&space;&space;m1&space;\mod&space;n\\\&space;(s2)^{e}&space;\equiv&space;&space;m2&space;\mod&space;n\&space;" title="\\ (s1)^{e} \equiv m1 \mod n\\\ (s2)^{e} \equiv m2 \mod n\ " />

Cuối cùng ta được : 

<img src="https://latex.codecogs.com/svg.image?\\&space;(s1)^{e}&space;-&space;m1&space;=&space;kN\\&space;(s2)^{e}&space;-&space;m2&space;=&space;hN&space;" title="\\ (s1)^{e} - m1 = kN\\ (s2)^{e} - m2 = hN " />

đến đây ta có thể tính được N rồi : 

```python
import base64
from Crypto.Util.number import *
import math
def pad(data):
    if len(data) % 8 != 0:
        data += b"=" * (8 - len(data) % 8)
    return data

e = 17
m1 = b'{"alg": "notRS256", "typ": "notJWT"}'+b'{user : "' + b'a' + b'", admin : False}'
m1 = bytes_to_long(m1)
s1 = "OFZPOXVXMDD6GJTOSZWFAF2DLXUAOHRSN5LDWH55DCP6FGEB2BDDNIYEQPQKKAVCYSWTG25OGA2CZFJM7LHL5YMSFDS6GH7ZCDIEZ2TOX2GRW5Q34NEFOI4NGASRVJUZFVD7YC4CWKDZBDMJRK3JDVHOO4FYNAL3WKVXENSELDEOGO7IBRYBWD7R3OTQD7SUK53NLWTMDDBKA"
s1 = base64.b32decode(pad(s1.encode()))
s1 = bytes_to_long(s1)
kN = s1**e-m1

m2 = b'{"alg": "notRS256", "typ": "notJWT"}'+b'{user : "' + b'b' + b'", admin : False}'
m2 = bytes_to_long(m2)
s2 = "JGB65ZOFXNAEEPXBZQR4CXJLIDC643UNM4OO6Y5KHDGDRFGFNMCCKC5RMIQSYLFFN5LLPMUT5JEZCVWKJP2A47MU4LZABFBDI2YANM4S7NW2PEXE2J4PAWJOZKCCS5WFXDPWFZEUIKQRCA7GOVCP2ASNNWNDZTEGO5MVIKK253ASD7GXQ7JVGHD527RDX7PAU4WNAWRIZMAJY"
s2 = base64.b32decode(pad(s2.encode()))
s2 = bytes_to_long(s2)
hN = s2**e-m2

N = math.gcd(kN,hN)
print(N)
#102023933594675885727482433536439603313632025195349898254625572154788087636596726779743824870900843601539817993317820155294998954199744518048988886468997222220666721611696723040994762222197748727494695173456938071542809742020103628264792844624806487145961325583122253303731850753231923830549425654252156250831
```
Đem n đi factor ta được p,q :

![image](https://user-images.githubusercontent.com/72289126/145713339-c9b09769-b19c-4a92-bbc8-35c7561b19f0.png)

Tìm được n xong thì mọi thứ ez rồi :D

```python
p = 10100689758361845940152847780003783431536611814466949762123436043866022425559374294766769331161147305436476202608669069280862160355739741762723891797772291
q = 10100689758361845940152847780003783431536611814466949762123436043866022425559374294766769331161147305436476202608669069280862160355739741762723891797775941
d = inverse(e,(p-1)*(q-1))

header = b'{"alg": "notRS256", "typ": "notJWT"}'
payload = b'{user : "LilThawg", admin : True}'
sig = base64.b32encode(long_to_bytes(pow(bytes_to_long(header+payload),d,N))).strip(b"=").decode()
payload = base64.b32encode(payload).decode().strip("=")
header = base64.b32encode(header).decode().strip("=")
token = header+"_"+payload+"_"+sig
print(token)
#PMRGC3DHEI5CAITON52FEUZSGU3CELBAEJ2HS4BCHIQCE3TPORFFOVBCPU_PN2XGZLSEA5CAISMNFWFI2DBO5TSELBAMFSG22LOEA5CAVDSOVSX2_AEFAFG6LRYIBORBFB4XTQ7C4XE3YCXFNWMRQ3LMJROBKUPESLC3QXL77KDZGAQDORHUDWDA4VVJHXJ753Q3T3SCTRA6O5FG6QVJMCMQIYZC2JDOHFSFKA54MLJV2SRTWLZU6TSWFCQKEY7OAYUCYRNS2TDQW5YNZTQMK7FXW6HYGSOWBFD6TTST6MO2KYP4ZQ44IGG2MAVWUK
```

Post lên server và lấy flag thôi !

![image](https://user-images.githubusercontent.com/72289126/145713418-547d1aad-93f3-4e1e-b7ab-4e5681eeed6d.png)
