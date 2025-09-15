### pyGOST_R_34.10-2018

Implementation of the digital signature protocol GOST R 34.10–2018 (ГОСТ Р 34.10-2018).

### How to run

1. Install requirements:

```python
pip install -r requirements.txt
```

	2. Run .py file using python:

```python
py gost34_10_2018.py
```

### About

A program that implements the signature protocol in accordance with GOST R 34.10−2018. The parameters of the cryptosystem are given below. The program must support the functions of signature generation and verification, as well as allow the use of different keys.

### Cryptosystem parameters

```
p = 57896044622894643241131754937450315750132642216230685504884320870273678881443
r = 28948022311447321620565877468725157875067316353637126186229732812867492750347
a = 1
b = 41431894589448105498289586872587560387979247722721848579560344157562082667257
xP = 54672615043105947691210796380713598019547553171137275980323095812145568854782
yP = 42098178416750523198643432544018510845496542305814546233883323764837032783338
```

