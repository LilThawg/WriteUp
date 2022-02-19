# Jet's Pizza

Đề bài : 
```
- Giá 1 Pizza chưa có topping : $15.0
- Topping : (Phần topping cho vào 1 dict mà xử lý thôi)
    - (T) tomatoes (+$1.50)
    - (O) onions (+$1.25)
    - (P) pineapple (+$3.50)
    - (M) mushrooms (+$3.75)
    - (A) avocado (+$0.40)
- Nếu tổng tiền > $20.0 : được giảm giá 5% 

Sample Input 1:
TPM
Sample Output 1:
22.56
Explanation 1:
Tổng tiền = T + P + M + 1 Pizza không = 1.50 + 3.50 + 3.75 + 15.0 = 23.75 > 20 nên được giảm 5% nữa.
=> Tổng tiền = 23.75 - 5% * 23.75 = 22.5625 = 22.56

Sample Input 2:
AAAAAAAMMTGTMMMXMMT
Sample Output 2:
19.62
Explanation 2:
Mặc dù 1 topping có nhiều lần lặp lại nhưng chỉ tính 1 lần thôi (dùng set), 
và có những topping không hợp lệ thì bỏ qua (đặt try except)
Tổng tiền = A + M + T + 1 Pizza không = 0.40 + 3.75 + 1.50 + 15.0 = 20.65 > 20 nên được giảm 5% nữa.
=> Tổng tiền = 20.65 - 5% * 20.65 = 22.5625 = 19.6175 = 19.62
```

Lời giải : 

```python
dict = {"T":1.50, "O":1.25, "P":3.50, "M":3.75, "A":0.40}

def solve(Input):
    sumMoney = 15.0
    for s in set(Input):
        try:
            sumMoney+=dict[s]
        except:
            pass
    if sumMoney > 20:
        sumMoney = sumMoney - sumMoney*5/100
    return round(sumMoney,2)

if __name__ == '__main__':
    for i in range(7):
        line = input()
        print("{:.2f}".format(solve(line)))
```

# Euler's Method

Bài này đã học ở môn `Phương Pháp Tính`  AT17 vừa thi xong nhé, mình AT16 rồi nên phải ngồi xem lại video =)) https://www.youtube.com/watch?v=Rx9fbWeMVyY

Đề bài : 

```
Cho y'(x) = x^2 - 6y^2, y(5) = 2 xét trên đoạn [-10;10] 

Sample Input 1:
0.8 5.8 
(Giải thích : h (bước nhảy) = 0.8; x = 5.8 ; và bài toán hỏi y(5.8) = ? 

Sample Output 1:
2.8 (Không có giải thích gì nữa nhé, xem video đi)

Sample Input 2:
0.9 7.7 (tương tự)
Sample Output 2:
-645.1
```

Lời giải :

Khi làm việc với bài này mình khá khó chịu với việc này : 

![image](https://user-images.githubusercontent.com/72289126/154806715-c9b243c4-d94e-4580-9182-9a4aae6b2fa5.png)

Bạn chưa hình dung nó khó chịu như nào đúng không ? Đây là code cũ của mình mô phỏng lại bài trong video

```python
def solve(h,xTarget):
    f = lambda X,Y : -pow(X,2) + pow(Y,2)

    x = 1
    y = 1

    while x < xTarget:

        y = y + h*f(x,y)
        x += h
        print(x,y)

    return round(y,1)

if __name__ == '__main__':
    NumTestCase = int(input())
    for i in range(NumTestCase):
        line = input()
        params = line.split(' ')
        h, xTarget = float(params[0]), float(params[1])
        print(solve(h,xTarget))
```

![image](https://user-images.githubusercontent.com/72289126/154806947-3f560355-21e7-48e2-9bbb-3113517677b4.png)

Đó thấy không, tại vì 1.9999999999999998 < 2 nên nó vẫn chạy tiếp và return ra kết quả sai :) chứ đáp án dúng là -0.3650109689906646 kia kìa.

Do đó mình phải sửa 1 tý : đổi thành for 

```python
def solve(h,xTarget):
    f = lambda X,Y : pow(X,2) - 6*pow(Y,2)

    x = 5
    y = 2

    n = int((xTarget-x)/h)

    for i in range(n):
        y = y + h*f(x,y)
        x += h

    return round(y,1)

if __name__ == '__main__':
    NumTestCase = int(input())
    for i in range(NumTestCase):
        line = input()
        params = line.split(' ')
        h, xTarget = float(params[0]), float(params[1])
        print(solve(h,xTarget))
 ```
 
 # Cloudy w/ a Chance of Rain
 
 Đề bài : 

Đối với mỗi đầu vào, bạn sẽ nhận được một mảng các số nguyên được phân tách bằng dấu cách (mỗi số từ 0 đến 100) 
đại diện cho phần trăm khả năng có mưa cho mỗi giờ trong khoảng thời gian sáu giờ. 

Chương trình của bạn sẽ trả về phần trăm cơ hội (làm tròn xuống số nguyên gần nhất)
mà trời mưa trong bất kỳ thời gian nào trong sáu giờ đó.

 ```
Sample Input 1:
5 93 83 28 100 8
Sample Output 1:
100

Sample Input 1:
5 93 83 28 100 8
Sample Output 1:
100
 ```
 
 Lời giải : 
 
 Xác suất có mưa trong 6 giờ đó là (1 - xác suất trong 6 giờ đó không có mưa) 
 
 ```python
 import math
def solve(Input):
    arr = list(map(int,Input.split(' ')))
    res = 1
    for i in range(6):
        res*=100-arr[i]
    return math.floor((1 - res/(100**6))*100)
if __name__ == '__main__':
    NumTestCase = int(input())
    for i in range(NumTestCase):
        line = input()
        print(solve(line))
 ```
 
 Bài này các bạn tự code cũng được chứ mình ngại code lại :D nói ý tưởng thôi là hiểu rồi còn gì :D
 
