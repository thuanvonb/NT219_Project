from dsa_helper import *
from secrets import token_bytes as random_bytes
from Crypto.Util.number import bytes_to_long as b2l

q = 8380417
zt = 3073009

def polyMultiply(poly1, poly2):
  t = [0] * 512
  for i in range(256):
    for j in range(256):
      t[i+j] = (t[i+j] + poly1[i] * poly2[j]) % q
  for i in range(511, 255, -1):
    if t[i] == 0:
      continue
    t[i-256] += t[i]*(q-1)
    t[i-256] %= q
  return t[:256]

def baseCaseMultiply(a0, a1, b0, b1, g):
  c0 = a0*b0 + a1*b1*g
  c1 = a1*b0 + a0*b1
  return (c0 % q, c1 % q)

def rejNTTPoly(rho):
  c = 0
  a = []
  generator = XOF(rho)
  while len(a) < 256:
    t = CoefFromThreeBytes(generator[c], generator[c+1], generator[c+2])
    c += 3
    if t is not None:
      a.append(t)
  return a

def rejBoundedPoly(rho, nu):
  a = []
  c = 0
  generator = XOF(rho)
  while len(a) < 256:
    z = generator[c]
    z0 = CoefFromHalfByte(z % 16, nu)
    z1 = CoefFromHalfByte(z >> 4, nu)
    if z0 is not None:
      a.append(z0)
    if z1 is not None and len(a) < 256:
      a.append(z1)
    c += 1
  return a


def expandA(rho, k, l):
  A = []
  for i in range(k):
    r = []
    for j in range(l):
      r.append(NTT(rejNTTPoly(rho + bytes(integer2Bits(j, 8)) + bytes(integer2Bits(i, 8)))))
    A.append(r)
  return A

def expandS(rho, k, l, nu):
  s1 = []
  s2 = []
  for i in range(l):
    s1.append(rejBoundedPoly(rho + bytes(integer2Bits(i, 16)), nu))
  for j in range(k):
    s2.append(rejBoundedPoly(rho + bytes(integer2Bits(i+l, 16)), nu))
  return s1, s2

def expandMask(rho, mu, l, g1):
  c = 1 + bitLen(g1 - 1)
  s = []
  for r in range(l):
    n = integer2Bits(mu+r, 16)
    h = XOF(rho + bytes(n))
    v = []
    for j in range(32*c):
      v.append(h[32*r*c+j])
    s.append(BitUnpack(bytes(v), g1-1, g1))
  return s


def recursiveNTT(arr):
  if not hasattr(arr[0], "__len__"):
    return NTT.fromPoly(arr)
  return [recursiveNTT(i) for i in arr]

def recursiveNTT_inv(arr):
  if not hasattr(arr, "__len__"):
    return arr.toPoly()
  return [recursiveNTT_inv(i) for i in arr]


class NTT:
  def __init__(self, init):
    self.data = init

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
    return list([(v * 8314945) % q for v in f])

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

  def __sub__(self, other):
    f = self.data
    g = other.data
    return NTT(init=[(fi - gi) % q for fi, gi in zip(f, g)])

  @staticmethod
  def zero():
    return NTT(init=[0]*256)

  def __iter__(self):
    return iter(self.data)

def multNTT(mat, vec):
  out = []
  for r in mat:
    t = NTT.zero()
    for i, j in zip(r, vec):
      t = t + i*j
    out.append(t)
  return out

def addVecs(f, g):
  return [(fi + gi) % q for fi, gi in zip(f, g)]

def subVecs(f, g):
  return [(fi - gi) % q for fi, gi in zip(f, g)]