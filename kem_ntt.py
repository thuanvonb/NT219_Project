from kem_helper import bytes2Bits, bitRev, XOF
from secrets import token_bytes as random_bytes
from Crypto.Util.number import bytes_to_long as b2l

q = 3329
n = 256
zt = 17

def baseCaseMultiply(a0, a1, b0, b1, g):
  c0 = a0*b0 + a1*b1*g
  c1 = a1*b0 + a0*b1
  return (c0 % q, c1 % q)

def sampleNTT(hashgen=None):
  B = hashgen if hashgen is not None else XOF(random_bytes(32))
  i = 0
  j = 0
  a = []
  while j < 256:
    d1 = B[i] + (B[i+1] % 16) << 8
    d2 = B[i+1] // 16 + B[i+2] << 4
    if d1 < q:
      a.append(d1)
      j += 1
    if d2 < q and j < 256:
      a.append(d2)
      j += 1

    i += 3
  return a


class NTT:
  def __init__(self, init=None, hashgen=None):
    self.data = init if init is not None else sampleNTT(hashgen)

  @staticmethod
  def fromPoly(f):
    f_out = list(f)
    k = 1
    l = 128
    while l >= 2:
      i = 0
      while i < 256:
        z = pow(zt, bitRev(7, k), q)
        k = (k + 1) % 128
        for j in range(i, i+l):
          t = (z*f_out[j+l]) % q
          f_out[j+l] = (f_out[j] - t) % q
          f_out[j] = (f_out[j] + t) % q

        i += 2*l
      l //= 2
    return NTT(init=f_out)

  def toPoly(self):
    f = list(self.data)
    k = 127
    for lp in range(1, 8):
      l = 1 << lp
      i = 0
      while i < 256:
        z = pow(zt, bitRev(7, k), q)
        k = (k - 1) % 128
        for j in range(i, i+l):
          t = f[j]
          f[j] = (t + f[j+l]) % q
          f[j+l] = (z*(f[j+l] - t)) % q
        i += 2*l
    return list([(v * 3303) % q for v in f])

  def __mul__(self, other):
    f = self.data
    g = other.data
    h = []
    for i in range(128):
      h0, h1 = baseCaseMultiply(f[2*i], f[2*i+1], g[2*i], g[2*i+1], pow(zt, 2*bitRev(7, i)+1, q))
      h.extend([h0, h1])
    return NTT(init=h)

  def __add__(self, other):
    f = self.data
    g = other.data
    return NTT(init=[(fi + gi) % q for fi, gi in zip(f, g)])

  @staticmethod
  def zero():
    return NTT(init=[0]*256)

  def __len__(self):
    return len(self.data)

  def __iter__(self):
    return iter(self.data)

def addVecs(f, g):
  return [(fi + gi) % q for fi, gi in zip(f, g)]