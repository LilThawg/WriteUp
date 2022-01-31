# Write Up 2 Chall cuối Crypto

## China

Đề bài : 

China.py

```python
from Crypto.Util.number import *

#Sau cuộc chiến tranh Trung-Nhật (1894-1895) các nước đế quốc gồm : Đức, Anh, Pháp, Nga và Nhật bắt đầu xâu xé chiếc bánh ngọt Trung Quốc

flag_China = b'KCSC{fakeFlagggggggggggggggggggggggggggggggggggggggggggggggggggg}'
flag_China = bytes_to_long(flag_China)
Germany = getPrime(512)
England = getPrime(256)
France = getPrime(128)
Russia = getPrime(96)
Japan = getPrime(64)

f = open("china_output.txt","w")
print(f"Germany = {Germany}",file=f)
print(f"flag_China/Zmod(Germany) = {flag_China%Germany}",file=f)
print(f"England = {England}",file=f)
print(f"flag_China/Zmod(England) = {flag_China%England}",file=f)
print(f"France = {France}",file=f)
print(f"flag_China/Zmod(France) = {flag_China%France}",file=f)
print(f"Russia = {Russia}",file=f)
print(f"flag_China/Zmod(Russia) = {flag_China%Russia}",file=f)
print(f"Japan = {Japan}",file=f)
print(f"flag_China/Zmod(Japan) = {flag_China%Japan}",file=f)
```

Output.txt
```
Germany = 7755934692072604179603672807547074563449173175152584957381849779577698815460171372376722062463576748724318022931980110095939489961391460901793769041204559
flag_China/Zmod(Germany) = 3000103585088955349554482593100297151003806823642212252582531433698916399891813017788890750632793185851465149179937174820610538985027691907523706095888024
England = 67960800240234481911671097713154930313034565982351437792703335552289330612393
flag_China/Zmod(England) = 67699759555297046704340788771133614234034607143407655271511047189986131254364
France = 336636992072370523527297206549540425361
flag_China/Zmod(France) = 146763688188153476956417344471681650622
Russia = 44300073407269489829845269949
flag_China/Zmod(Russia) = 13577026376403150427866851792
Japan = 9476087292530451479
flag_China/Zmod(Japan) = 5180070760009672523
```

Dân chơi nhìn tên bài biết sử dụng CRT (Chinese remainder theorem)

Tên biến đặt hơi xàm tý tại tự nhiên nhắc đến Trung Quốc là mình nhớ đến sự kiện đó, chả hiểu sao xD. 

Google tý ta sẽ tìm thấy 1 vài cách tính CRT mình thì dùng lib có sẵn luôn : https://www.geeksforgeeks.org/python-sympy-crt-method/

```python
from Crypto.Util.number import *
from sympy.ntheory.modular import crt

Germany = 7755934692072604179603672807547074563449173175152584957381849779577698815460171372376722062463576748724318022931980110095939489961391460901793769041204559
flag_China_Zmod_Germany = 3000103585088955349554482593100297151003806823642212252582531433698916399891813017788890750632793185851465149179937174820610538985027691907523706095888024
England = 67960800240234481911671097713154930313034565982351437792703335552289330612393
flag_China_Zmod_England = 67699759555297046704340788771133614234034607143407655271511047189986131254364
France = 336636992072370523527297206549540425361
flag_China_Zmod_France = 146763688188153476956417344471681650622
Russia = 44300073407269489829845269949
flag_China_Zmod_Russia = 13577026376403150427866851792
Japan = 9476087292530451479
flag_China_Zmod_Japan = 5180070760009672523

list_c = [flag_China_Zmod_Germany,flag_China_Zmod_England,flag_China_Zmod_France,flag_China_Zmod_Russia,flag_China_Zmod_Japan]
list_n = [Germany,England,France,Russia,Japan]

res = crt(list_n,list_c)
A = int(res[0])

print(A)
print(long_to_bytes(A))
```

Kết quả : 
```
9943282806594687121610001821640070891657319636651701252502171666594045914252483428817421015707261247376407766488220193668298132717925201169682092768570283668000684485923982848585002985045226791518906396499985298653845920863797237814459404445960827470693742134115718370545422644803342410265201805336943824708920624097
b'\x03K\xfb\xf2\x9a\x0b\xf3\xf5\x81\xba\xf2\x0b\xab$\xc7\x93\xad;y\x9d\x14\xee2\xe2 z\x90,\xd1\xac\xc7\xf3\xd7Q\xaczY\xee\x9cF\xab\x9c\xd4\xf6;\xc0\x03\x02\x00\x93\x04\x902R{v\x01V\xdcc\xb4#\x11\xa3\x9c\xb7\xdd2c\xef3,w\xa3,\x1b\xed\x0b\x1c0\xf6\x8e\xcerE\xf3\xdaa\x8aC\x1a\x95\xf0\xd6\t53&\xadO\xc3\x10\x90}>R\xa5>I\xcc;\xffgw\x90+>z\xf9\xaeO\x9e\x99\x10/h\xad\xe9J\xd3C\xe1'
```

Chả có ý nghĩa gì ? mình biết ngay là đến đoạn này nhiều bạn quay đầu vì tưởng tính sai mà =))) Nhưng khi giải phương trình đồng dư và được kết quả ` x ≡ A ` thì các bạn lại chỉ chú tâm đến kết quả,
mà quên mất rằng kết luận phải là ` x ≡ A (mod N) ` do đó flag có phải có dạng đầy đủ là : ` x = A + kN ` và ta brute-force cái k là được.

```python
from Crypto.Util.number import *
from sympy.ntheory.modular import crt

Germany = 7755934692072604179603672807547074563449173175152584957381849779577698815460171372376722062463576748724318022931980110095939489961391460901793769041204559
flag_China_Zmod_Germany = 3000103585088955349554482593100297151003806823642212252582531433698916399891813017788890750632793185851465149179937174820610538985027691907523706095888024
England = 67960800240234481911671097713154930313034565982351437792703335552289330612393
flag_China_Zmod_England = 67699759555297046704340788771133614234034607143407655271511047189986131254364
France = 336636992072370523527297206549540425361
flag_China_Zmod_France = 146763688188153476956417344471681650622
Russia = 44300073407269489829845269949
flag_China_Zmod_Russia = 13577026376403150427866851792
Japan = 9476087292530451479
flag_China_Zmod_Japan = 5180070760009672523

list_c = [flag_China_Zmod_Germany,flag_China_Zmod_England,flag_China_Zmod_France,flag_China_Zmod_Russia,flag_China_Zmod_Japan]
list_n = [Germany,England,France,Russia,Japan]

res = crt(list_n,list_c)
A = int(res[0])
N = res[1]

k = 0
while True:
    flag = A + k*N
    if b'KCSC' in long_to_bytes(flag):
        print(long_to_bytes(flag))
        break
    k+=1

# FLAG : KCSC{The Chinese remainder theorem is a theorem which gives a unique solution to simultaneous linear congruences with coprime moduli}
```

## DES weakness

`nc -v 45.77.39.59 3900`

Đề bài : 

encrypt.py

```python
import os
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
from pwn import xor

IV = os.urandom(8)
FLAG = b'KCSC{????????????????????????????????????????????????????}'

def encrypt(plaintext,key):
    key = bytes.fromhex(key)
    plaintext = bytes.fromhex(plaintext)
    if (len(plaintext) % 8 != 0):
        plaintext = pad(plaintext,8)
    plaintext = xor(plaintext, IV)
    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    ciphertext = xor(ciphertext, IV)
    return ciphertext.hex()

plaintext = b"nhap bat ky".hex()
key = b"8bytekey".hex()

ciphertext = encrypt(plaintext,key)
encrypted_flag = encrypt(FLAG.hex(),key)

print(f"{ciphertext = }")
print(f"{encrypted_flag = }")
```

Bài này cho 1 oracle `chỉ có khả năng encrypt` thôi,hàm encrypt nhận vào 2 tham số `plaintext` và `key` và trả về ciphertext xor với IV. (tại sao mình lại phải xor với IV ư ? thế bạn nhập key vào và lấy key đó đi giải mã thôi à xD )

Khi nhập `1` cặp `plaintext` và `key` thì ta được trả lại `2` giá trị `ciphertext` và `encrypted_flag` 

![image](https://user-images.githubusercontent.com/72289126/151827253-f416e5bc-f093-4a0f-ae3d-9b342c444c09.png)

Với những tóm tắt trên những bạn nào tinh ý sẽ nhận ra phải khai thác vào key, và mình nhớ ở môn `Nhập môn Mật Mã học` ở trường có đề cập đến khoá yếu rồi bạn nào không tin có thể đọc lại blog của mình.

Do đó google 1 tý ta sẽ tìm được những khoá yếu của DES : https://en.wikipedia.org/wiki/Weak_key

Weak Keys có tính chất 2 lần mã hoá các bạn sẽ nhận lại được bản rõ. Tham khảo thêm : https://crypto.stackexchange.com/questions/12214/can-you-explain-weak-keys-for-des

Do đó ta chỉ cần gửi 2 lần là có thể recover flag (không cần pwntools làm gì)

![image](https://user-images.githubusercontent.com/72289126/151830163-b339f2e2-2794-4bdc-a502-c8c129ea1090.png)

```
>>> bytes.fromhex('4b4353437b5765616b204b657973206d616b6520656e6372797074696e67207477696365207969656c64732074686520706c61696e746578747d060606060606')
b'KCSC{Weak Keys make encrypting twice yields the plaintext}\x06\x06\x06\x06\x06\x06'
```
