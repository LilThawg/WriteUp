from sympy.ntheory.modular import crt
from Crypto.Util.number import *
from hashlib import sha1
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

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

k = (38685626227668133590597631 - x)//N
for i in range(k):
    n = x + i*N
    if n*G == Gn:
        print(f'[+] KEY: {n}')
        break
        
Ciphertext = "df572f57ac514eeee9075bc0ff4d946a80cb16a6e8cd3e1bb686fabe543698dd8f62184060aecff758b29d92ed0e5a315579b47f6963260d5d52b7ba00ac47fd"
IV = "baf9137b5bb8fa896ca84ce1a98b34e5"
Ciphertext = bytes.fromhex(Ciphertext)
IV = bytes.fromhex(IV)

key = sha1(str(n).encode('ascii')).digest()[0:16]
cipher = AES.new(key, AES.MODE_CBC, IV)
flag = cipher.decrypt(Ciphertext)

print(flag)
