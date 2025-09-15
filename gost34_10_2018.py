from Crypto.Util.number import getRandomRange, inverse
from pygost import gost34112012
from asn1 import Decoder, Encoder, Numbers
from os.path import splitext


def point_double(x_coord, y_coord, curve_param, modulus):
    if x_coord == 0 and y_coord == 1:
        return x_coord, y_coord

    slope = ((3 * x_coord ** 2 + curve_param) * inverse(2 * y_coord, modulus)) % modulus
    new_x = (slope ** 2 - 2 * x_coord) % modulus
    new_y = (slope * (x_coord - new_x) - y_coord) % modulus
    return new_x, new_y

def point_add(x1, y1, x2, y2, curve_param, curve_b, modulus):
    if x1 == 0 and y1 == 1:
        return x2, y2
    if x2 == 0 and y2 == 1:
        return x1, y1

    if x1 == x2 and y1 == y2:
        return point_double(x1, y1, curve_param, modulus)

    if x1 == x2:
        return 0, 1

    slope = ((y2 - y1) * inverse(x2 - x1, modulus)) % modulus
    new_x = (slope ** 2 - x1 - x2) % modulus
    new_y = (slope * (x1 - new_x) - y1) % modulus
    return new_x, new_y

def scalar_mult(x_coord, y_coord, scalar, curve_param, curve_b, modulus):
    if scalar == 0:
        return 0, 1
    if scalar == 1:
        return x_coord, y_coord
    if scalar == 2:
        return point_double(x_coord, y_coord, curve_param, modulus)

    result_x, result_y = 0, 1
    for bit in bin(scalar)[2:]:
        result_x, result_y = point_double(result_x, result_y, curve_param, modulus)
        if bit == "1":
            result_x, result_y = point_add(result_x, result_y, x_coord, y_coord, curve_param, curve_b, modulus)
    return result_x, result_y




a = 1
b = 41431894589448105498289586872587560387979247722721848579560344157562082667257

x = 54672615043105947691210796380713598019547553171137275980323095812145568854782
y = 42098178416750523198643432544018510845496542305814546233883323764837032783338

p = 57896044622894643241131754937450315750132642216230685504884320870273678881443
q = 28948022311447321620565877468725157875067316353637126186229732812867492750347



d = 13873194258458127070203476830858425814147318774610441043924572800009363432861
# Q = dP
Q = (28097187722225916526728226611146511957812429606264550078631099370827278885117, 53571884733407411154191972316052538561343664929011087516925937319898238683778)


def generate_key():
    global d
    d = getRandomRange(2, q)
    global Q
    # Q = dP 
    Q = scalar_mult(x, y, d, a, b, p)


# Подпись сообщения ГОСТ Р 34.10-2018
# Вход: сообщение data
# Выход: Сформированная подпись сообщения (r || s)
def sign(data):
    # 1. Вычисление хэш-образа сообщения
    h = gost34112012.GOST34112012(data).hexdigest()
    print(f'\nMessage hash: {h}\n')
    # 2. Нахождение e: e = a (mod q)
    # a - число, двоичным представлением которого является вектор h
    e = int(h, 16) % q

    if e == 0:
        e = 1
        
    while True:
        # 3. Вырабатывается случайный показатель k: 0 < k < q 
        k = getRandomRange(1, q)
        # 4. Вычисляется точка C: C <- kP, C = (Xc, Yc), r = Xc (mod q)
        C = scalar_mult(x, y, k, a, b, p)
        # r = Xc (mod q)
        r = C[0] % q
        if r == 0:
            continue
        # 5. Вычисляется s <- (rd + ke) (mod q)
        s = (r * d + k * e) % q
        if s != 0:
            break
    # возвращаем числа r, s
    return r, s


# Проверка подписи ГОСТ Р 34.10-2018
# Вход: сообщение data, параметры подписи
# Выход: сообщение о результате проверки подписи (совпадает или нет)
def check_sign(data, r, s):
    # 1. Проверяется выполнение неравенства 0 < 𝑟 < 𝑞, 0 < 𝑠 < 𝑞
    if r < 0 or q < r or s < 0 or q < s:
        print('\n[-] Sign NOT correct\n')
        return False
    # 2. Вычисляется хэш-образ сообщения data
    h = gost34112012.GOST34112012(data).hexdigest()
    # 3. Находится значение e: e = a (mod q)
    e = int(h, 16) % q
    # При e = 0 полагается, что e = 1
    if e == 0:
        e = 1
    # 4. Вычисляется v: v = e^-1 (mod q) 
    v = inverse(e, q)
    # 5. Вычисляется z1 и z2:
        # z1 = sv (mod q)
    z1 = (s * v) % q
        # z2 = -rv (mod q)
    z2 = (-1 * r * v) % q
    # 6. Находится точка C: C = z1P + z2Q, C = (Xc, Yc), R = Xc (mod q)
        # z1P
    A = scalar_mult(x, y, z1, a, b, p)
        # z2Q
    B = scalar_mult(Q[0], Q[1], z2, a, b, p)
        # C
    C = point_add(A[0], A[1], B[0], B[1], a, b, p)
    # 7. Проверяется выполнение равенства R = r ?
    R = C[0] % q

    if r == R:
        print('\n[+] Sign correct\n')
    else:
        print('\n[-] Sign NOT correct\n')


def sign_to_asn(r, s):
    asn1 = Encoder()
    asn1.start()
    asn1.enter(Numbers.Sequence)
    asn1.enter(Numbers.Set)
    asn1.enter(Numbers.Sequence)
    asn1.write(b'\x80\x06\x07\x00', Numbers.OctetString) # идентификатор алгоритма (протокол подписи ГОСТ)
    asn1.enter(Numbers.Sequence)
    asn1.write(int(Q[0]), Numbers.Integer) # x - координата точки Q
    asn1.write(int(Q[1]), Numbers.Integer) # y - координата точки Q
    asn1.leave()
    asn1.enter(Numbers.Sequence)
    asn1.enter(Numbers.Sequence)
    asn1.write(p, Numbers.Integer) # простое число p
    asn1.leave()
    asn1.enter(Numbers.Sequence)
    asn1.write(a, Numbers.Integer) # коэффициент A уравнения кривой
    asn1.write(b, Numbers.Integer) # коэффициент B уравнения кривой
    asn1.leave()
    asn1.enter(Numbers.Sequence)
    asn1.write(int(x), Numbers.Integer) # x - координата образующей точки P
    asn1.write(int(y), Numbers.Integer) # y - координата образующей точки P
    asn1.leave()
    asn1.write(q, Numbers.Integer) # порядок группы q
    asn1.leave()
    asn1.enter(Numbers.Sequence) # параметры криптосистемы
    asn1.write(r, Numbers.Integer) # число r
    asn1.write(s, Numbers.Integer) # число s
    asn1.leave()
    asn1.leave()
    asn1.leave()
    asn1.enter(Numbers.Sequence) # параметры файла (не используются)
    asn1.leave()
    asn1.leave()
    return asn1.output()


def asn_to_sign(data):
    asn1 = Decoder()
    asn1.start(data)
    asn1.enter()
    asn1.enter()
    asn1.enter()
    value = asn1.read()
    asn1.enter()
    Q = (asn1.read()[1], asn1.read()[1])
    asn1.leave()
    asn1.enter()
    asn1.enter()
    p = asn1.read()[1]
    asn1.leave()
    asn1.enter()
    a = asn1.read()[1]
    b = asn1.read()[1]
    asn1.leave()
    asn1.enter()
    x = asn1.read()[1]
    y = asn1.read()[1]
    asn1.leave()
    q = asn1.read()[1]
    asn1.leave()
    asn1.enter()
    r = asn1.read()[1]
    s = asn1.read()[1]
    asn1.leave()
    asn1.leave()
    asn1.leave()
    asn1.enter()
    asn1.leave()
    asn1.leave()
    return a, b, x, y, p, q, d, Q, r, s 
    

def parse(data):
    while True:
        res = asn_to_sign(data)
        r, s = res[8], res[9]
        break
    return r, s


if __name__ == "__main__":
    while True:
        n = int(input("[?] Choose option:\n[+] 1. Generate keys\n[+] 2. Sign\n[+] 3. Check sign\n[+] 4. Exit\n>>> "))
        if n == 1:
            generate_key()
            print(f'[!] Keys generated:\nd = {d},\nQ = {Q}')

        elif n == 2:
            path = input("Enter filename: ")
            f = open(path, "rb")

            data = f.read()
            f.close()

            r, s = sign(data)
            result = sign_to_asn(r, s)

            filename, ext = splitext(path)
            f = open(filename + ".asn1", "wb")
            f.write(bytes(result))
            f.close()
            print('[!] Sign completed!\n')

        elif n == 3:
            path = input("Enter filename: ")
            f = open(path, "rb")

            data = f.read()
            f.close()

            filename, ext = splitext(path)
            f = open(filename + ".asn1", "rb")
            sig = f.read()
            f.close()

            r, s = parse(sig)
            check_sign(data, r, s)

        elif n == 4:
            exit()
        else:
            pass
