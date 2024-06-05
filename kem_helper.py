import hashlib
from Crypto.Util.number import long_to_bytes as l2b
from fractions import Fraction
from timeit import timeit
from random import randint
from secrets import token_bytes as random_bytes

q = 3329

class XOF:
  def __init__(self, seed, strength=256):
    self.strength = min(strength, 256)
    self.generator = seed
    self.state = b""

  def __getitem__(self, i):
    while i >= len(self.state):
      self.extend_state()
    return self.state[i]

  def extend_state(self):
    s = hashlib.shake_256(self.generator).digest(self.strength*2 + 32)
    self.state += s[:-32]
    self.generator = s[-32:]


def samplePolyCBD(n, B=None, q=3329):
  if B is None:
    B = random_bytes(64*n)
  b = bytes2Bits(B)
  f = []
  for i in range(256):
    x = 0
    y = 0
    for j in range(n):
      x += b[2*i*n + j]
      y += b[2*i*n + n + j]
    f.append((x - y) % q)
  return f

def bitRev(k, v):
  st = "{:0%db}" % k
  s = st.format(v)[-k:][::-1]
  return int(s, 2)

def num2Bytes(b, l):
  s = l2b(b)
  t = (l - len(s)) % l
  return b'\x00' * t + s

def prf(n, s, b):
  h = hashlib.shake_256(s + l2b(b))
  return h.digest(n*64)

def mod_ud(a, m):
  b = a % m
  if b > m // 2:
    b -= m
  return b

def xof(p, i, j):
  return XOF(p + l2b(i) + l2b(j))

def hashH(s):
  return hashlib.sha3_256(s).digest()

def hashJ(s):
  return hashlib.shake_256(s).digest(32)

def hashG(s):
  return hashlib.sha3_512(s).digest()

def bits2Bytes(b):
  assert len(b) % 8 == 0
  B = []
  for i, v in enumerate(b):
    if i % 8 == 0:
      B.append(0)
    B[-1] += v << (i % 8)
  return bytes(B)

def bytes2Bits(B):
  b = []
  for v in B:
    for i in range(8):
      b.append(v & 1)
      v >>= 1
  return b

def compress(d, x):
  if type(x) == list:
    return [compress(d, xi) for xi in x]
  return round(Fraction(1 << d) / q * x)

def decompress(d, x):
  if type(x) == list:
    return [decompress(d, xi) for xi in x]
  return round(Fraction(q) / (1 << d) * x)

def byteEncode(f, d):
  assert len(f) == 256
  b = []
  for v in f:
    for j in range(d):
      b.append(v & 1)
      v >>= 1
  return bits2Bytes(b)

def byteDecode(B, d):
  m = 1 << d
  if d == 12:
    m = q
  b = bytes2Bits(B)
  f = []
  for i, v in enumerate(b):
    if i % d == 0:
      f.append(0)
    f[-1] = (f[-1] + (v << i % d)) % m
  return f


def main():
  d = random_bytes(32)
  print(len(hashG(d)))

if __name__ == '__main__':
  main()