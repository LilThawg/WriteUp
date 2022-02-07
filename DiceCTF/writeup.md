# Write Up DiceCTF

## crypto/baby-rsa

generate.py

```python
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes

def getAnnoyingPrime(nbits, e):
	while True:
		p = getPrime(nbits)
		if (p-1) % e**2 == 0:
			return p

nbits = 128
e = 17

p = getAnnoyingPrime(nbits, e)
q = getAnnoyingPrime(nbits, e)

flag = b"dice{???????????????????????}"

N = p * q
cipher = pow(bytes_to_long(flag), e, N)

print(f"N = {N}")
print(f"e = {e}")
print(f"cipher = {cipher}")
```

data.txt

```
N = 57996511214023134147551927572747727074259762800050285360155793732008227782157
e = 17
cipher = 19441066986971115501070184268860318480501957407683654861466353590162062492971
```

Bài này khi làm như bình thường lại thấy không bình thường :)
sau khi check lại kỹ thì thấy `gcd(e,phi) = 17`.
Do đó nó không chỉ có duy nhất 1 đáp án.

~~Bài này mình lục lọi tìm mà k thấy gì phải đi hỏi chị Uyên~~

<img src="https://latex.codecogs.com/svg.image?\\&space;have&space;:&space;\&space;c&space;\equiv&space;&space;m^{17}&space;\&space;mod&space;(p.q)\\&space;\Rightarrow&space;m&space;\equiv&space;&space;c^{\frac{1}{17}}&space;\&space;mod&space;(p.q)\\&space;\Leftrightarrow&space;\left\{\begin{matrix}m&space;&&space;\equiv&space;&&space;c^{\frac{1}{17}}&space;\&space;mod&space;\&space;p&space;\\m&space;&&space;\equiv&space;&&space;c^{\frac{1}{17}}&space;\&space;mod&space;\&space;q&space;\\\end{matrix}\right." title="\\ have : \ c \equiv m^{17} \ mod (p.q)\\ \Rightarrow m \equiv c^{\frac{1}{17}} \ mod (p.q)\\ \Leftrightarrow \left\{\begin{matrix}m & \equiv & c^{\frac{1}{17}} \ mod \ p \\m & \equiv & c^{\frac{1}{17}} \ mod \ q \\\end{matrix}\right." />

Đến đây ta tìm m bằng cách tính CRT của `căn 17 của c mod p` và `căn 17 của c mod q` thôi.

```python
from Crypto.Util.number import long_to_bytes

N = 57996511214023134147551927572747727074259762800050285360155793732008227782157
e = 17
cipher = 19441066986971115501070184268860318480501957407683654861466353590162062492971
# factor with cado-nfs
p, q = 172036442175296373253148927105725488217, 337117592532677714973555912658569668821

assert p * q == N

p_roots = mod(cipher, p).nth_root(e, all=True)
q_roots = mod(cipher, q).nth_root(e, all=True)

for xp in p_roots:
    for xq in q_roots:
        x = crt([Integer(xp), Integer(xq)], [p,q])
        x = int(x)
        flag = long_to_bytes(x)
        if flag.startswith(b"dice"):
            print(flag.decode())
#b'dice{cado-and-sage-say-hello}'
```

