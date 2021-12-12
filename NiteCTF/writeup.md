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
