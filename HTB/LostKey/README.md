# LostKey

Thông thường đối với 1 bài `ECC`, việc đầu tiên ta cần làm là xác định `parameters` của đường cong đó. Bài này cũng vậy, ta giả sử rằng đường cong E có dạng: `y^2 = x^3 + ax + b (mod p)`

- `e = EC(101177610013690114367644862496650410682060315507552683976670417670408764432851)` => `p = 101177610013690114367644862496650410682060315507552683976670417670408764432851`

Nhờ vào trường hợp 2 điểm trùng nhau `P = Q` ta xác định được a, b

```PY
else:
    Lambda = (3*(P.x*Q.x) + 417826948860567519876089769167830531934*P.x + 177776968102066079765540960971192211603) * inverse(P.y+Q.y+3045783791, self.p)
```

Thế nhưng lambda nó lạ lắm =))) thông thường lambda = `3*x1^2 + a / 2*y1` nếu P = Q

![image](https://lilthawg29.files.wordpress.com/2021/09/image-210.png)

Do vậy ta có thể suy ra đường cong này có dạng tổng quát theo phương trình Weierstrass: 

![image](./img/Screenshot%202022-07-22%20155523.png)

Từ đó retrieve được các parameters 

![image](./img/Screenshot%202022-07-22%20155642.png)

```py
a2 = 208913474430283759938044884583915265967 # 2*a2 = 417826948860567519876089769167830531934
a4 = 177776968102066079765540960971192211603
a1 = 0
a3 = 3045783791
```

`G = coord(14374457579818477622328740718059855487576640954098578940171165283141210916477, 97329024367170116249091206808639646539802948165666798870051500045258465236698)`

```
x = 14374457579818477622328740718059855487576640954098578940171165283141210916477
y = 97329024367170116249091206808639646539802948165666798870051500045258465236698
```

Từ phương trình Weierstrass ta có thể tìm được a6: 

`a6 = y^2 + a1*x*y + a3*y - (x^3 + a2*x^2 + a4*x)`

```py
p = 101177610013690114367644862496650410682060315507552683976670417670408764432851
a2 = 208913474430283759938044884583915265967 # 2*a2 = 417826948860567519876089769167830531934
a4 = 177776968102066079765540960971192211603
a1 = 0
a3 = 3045783791
x = 14374457579818477622328740718059855487576640954098578940171165283141210916477
y = 97329024367170116249091206808639646539802948165666798870051500045258465236698

a6 = (y^2 + a1*x*y + a3*y - (x^3 + a2*x^2 + a4*x)) % p 

E = EllipticCurve(GF(p), [a1, a2, a3, a4, a6])
E
```

Đề cho toạ độ x của Gn. Ta dễ dàng recover Gn bằng cách sử Dụng `lift_x` : `Gn = E.lift_x(32293793010624418281951109498609822259728115103695057808533313831446479788050)`

Factor order của G ta được kết quả: 

![image](./img/Screenshot%202022-07-22%20183201.png)

Do `assert(n < 38685626227668133590597631)` nên khi dùng Pohlig Hellman ta chỉ cần lấy 4 thôi

```py
from sympy.ntheory.modular import crt
p = 101177610013690114367644862496650410682060315507552683976670417670408764432851
a2 = 208913474430283759938044884583915265967 # 2*a2 = 417826948860567519876089769167830531934
a4 = 177776968102066079765540960971192211603
a1 = 0
a3 = 3045783791
x = 14374457579818477622328740718059855487576640954098578940171165283141210916477
y = 97329024367170116249091206808639646539802948165666798870051500045258465236698
a6 = (y^2 + a1*x*y + a3*y - (x^3 + a2*x^2 + a4*x)) % p 

E = EllipticCurve(GF(p), [a1, a2, a3, a4, a6])
G = E(x,y)
Gn = E.lift_x(32293793010624418281951109498609822259728115103695057808533313831446479788050)
list(factor(G.order()))

def pohlig_hellman_ecc(P,Q):
    fac = list(factor(P.order()))[:-2]
    moduli = []
    remainders = []
    for i in fac:
        P0 = P*ZZ(P.order()/(i[0]^i[1]))
        Q0 = Q*ZZ(P.order()/(i[0]^i[1]))
        moduli.append(i[0]^i[1])
        remainders.append(discrete_log(Q0,P0, operation = '+'))
    return crt(moduli, remainders)

x, N = pohlig_hellman_ecc(G, Gn)
x = int(x)

print(x*G)
```

Thế nhưng khi thử lại ta biết đây không phải là đáp án ta cần tìm do x*G != Gn

![image](./img/Screenshot%202022-07-22%20184146.png)

Vì CTTQ của n là: `n = x + k*N (n < 38685626227668133590597631)`, ta brute-force k là được 

```py
x, N = pohlig_hellman_ecc(G, Gn)
x = int(x)

k = (38685626227668133590597631 - x)//N
for i in range(k):
    n = x + i*N
    if n*G == Gn:
        print(f'[+] KEY: {n}')
        break
```

[Full script](./solve.py)
