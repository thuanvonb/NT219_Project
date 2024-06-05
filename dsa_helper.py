from secrets import token_bytes as random_bytes
from random import randint
import hashlib

q = 8380417
d = 13

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


def bitRev(k, v):
  st = "{:0%db}" % k
  s = st.format(v)[-k:][::-1]
  return int(s, 2)

def mod_ud(a, m):
  b = a % m
  if b > m // 2:
    b -= m
  return b

bitLen = lambda x: len(bin(x))-2

def integer2Bits(n, a):
  o = []
  for i in range(a):
    o.append(n & 1)
    n >>= 1
  return o

def bits2Integer(bits):
  p = 1
  x = 0
  for b in bits:
    x += p if b else 0
    p <<= 1
  return x

def bits2Bytes(b):
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

def CoefFromThreeBytes(b0, b1, b2):
  if b2 > 127:
    b2 -= 128
  z = (b2 << 16) + (b1 << 8) + b0
  if z < q:
    return z

def CoefFromHalfByte(b, mu):
  if mu == 2 and b < 15:
    return 2 - (b % 5)
  if mu == 4 and b < 9:
    return 4 - b

def SimpleBitPack(w, b):
  z = []
  bl = bitLen(b)
  for i in range(256):
    z.extend(integer2Bits(w[i], bl))
  return bits2Bytes(z)

def SimpleBitUnpack(v, b):
  bl = bitLen(b)
  z = bytes2Bits(v)
  w = []
  for i in range(256):
    w.append(bits2Integer(z[i*bl:(i+1)*bl]))
  return w

def BitPack(w, a, b):
  z = []
  bl = bitLen(a+b)
  for i in range(256):
    z.extend(integer2Bits(b-w[i], bl))
  return bits2Bytes(z)

def BitUnpack(v, a, b):
  bl = bitLen(a+b)
  z = bytes2Bits(v)
  w = []
  for i in range(256):
    w.append(b-bits2Integer(z[i*bl:(i+1)*bl]))
  return w

def HintBitPack(h, omega, k):
  y = [0] * (omega + k)
  idx = 0
  for i in range(k):
    for j in range(256):
      if h[i][j] == 0:
        continue
      y[idx] = j
      idx += 1
    y[omega + i] = idx
  return bytes(y)

def HintBitUnpack(y, omega, k):
  h = [[0]*256 for _ in range(k)]
  idx = 0
  for i in range(k):
    if y[omega+i] < idx or y[omega+i] > omega:
      return None
    while idx < y[omega+i]:
      h[i][y[idx]] = 1
      idx += 1
  while idx < omega:
    if y[idx] != 0:
      return None
    idx += 1
  return h

def pkEncode(rho, t1):
  k = len(t1)
  pk = rho
  for i in range(k):
    pk += SimpleBitPack(t1[i], 2**(bitLen(q-1) - d)-1)
  return pk

def pkDecode(pk):
  m = (bitLen(q-1) - d)
  k = (len(pk) - 32) // (m*32)
  rho = pk[:32]
  t = []
  for i in range(k):
    t.append(SimpleBitUnpack(pk[32+i*32*m:32+(i+1)*32*m], 2**m-1))
  return rho, t

def skEncode(rho, K, tr, s1, s2, t0, k, l, nu):
  sk = rho + K + tr
  for i in range(l):
    sk += BitPack(s1[i], nu, nu)
  for i in range(k):
    sk += BitPack(s2[i], nu, nu)
  for i in range(k):
    sk += BitPack(t0[i], 2**(d-1)-1, 2**(d-1))
  return sk

def skDecode(sk, k, l, nu):
  rho = sk[:32]
  K = sk[32:64]
  tr = sk[64:128]
  sk = sk[128:]
  ls = 32*bitLen(2*nu)
  lt = 32*d
  s1 = []
  s2 = []
  t0 = []
  for i in range(l):
    s1.append(BitUnpack(sk[:ls], nu, nu))
    sk = sk[ls:]
  for i in range(k):
    s2.append(BitUnpack(sk[:ls], nu, nu))
    sk = sk[ls:]
  for j in range(k):
    t0.append(BitUnpack(sk[:lt], 2**(d-1)-1, 2**(d-1)))
    sk = sk[lt:]
  return rho, K, tr, s1, s2, t0

def sigEncode(c, z, h, k, l, g1, omega):
  sig = c
  for i in range(l):
    sig += BitPack(z[i], g1-1, g1)
  sig += HintBitPack(h, omega, k)
  return sig

def sigDecode(sig, lmbda, k, l, g1, omega):
  c = sig[:lmbda // 4]
  sig = sig[lmbda // 4:]
  z = []
  sl = 32*(1+bitLen(g1-1))
  for i in range(l):
    v = sig[:sl]
    z.append(BitUnpack(v, g1-1, g1))
    sig = sig[sl:]
  h = HintBitUnpack(sig, omega, k)
  return c, z, h

def w1Encode(w1, k, g2):
  w = []
  for i in range(k):
    w.extend(bytes2Bits(SimpleBitPack(w1[i], (q-1)//(2*g2)-1)))
  return w

def SampleInBall(rho, tau):
  c = [0]*256
  k = 8
  h = XOF(rho)
  for i in range(256-tau, 256):
    while h[k] > i:
      k += 1
    j = h[k]
    c[i] = c[j]
    c[j] = (-1)**(h[i+tau-256])
    k += 1
  return c

def Power2Round(r):
  if not hasattr(r, "__len__"):
    r = r % q
    r0 = mod_ud(r, 2**d)
    r1 = (r - r0) // (2**d)
    return (r1, r0)

  o1 = []
  o2 = []
  for x in r:
    a, b = Power2Round(x)
    o1.append(a)
    o2.append(b)
  return o1, o2

def decompose(r, g2):
  if not hasattr(r, "__len__"):
    r = r % q
    r0 = mod_ud(r, 2*g2)
    if r - r0 == q-1:
      r1 = 0
      r0 = r0-1
    else:
      r1 = (r - r0) // (2*g2)
    return (r1, r0)

  o1 = []
  o2 = []
  for x in r:
    a, b = decompose(x, g2)
    o1.append(a)
    o2.append(b)
  return o1, o2

def highBits(r, g2):
  return decompose(r, g2)[0]

def lowBits(r, g2):
  return decompose(r, g2)[1]

def makeHint(z, r, g2):
  if not hasattr(z, "__len__"):
    return int(highBits(r, g2) != highBits(r+z, g2))

  o = []
  for zi, ri in zip(z, r):
    o.append(makeHint(zi, ri, g2))
  return o

def useHint(h, r, g2):
  if not hasattr(h, "__len__"):
    m = (q-1) // (2*g2)
    r1, r0 = decompose(r, g2)
    if h != 1:
      return r1
    if r0 > 0:
      return (r1 + 1) % m
    return (r1 - 1) % m

  o = []
  for hi, ri in zip(h, r):
    o.append(useHint(hi, ri, g2))
  return o

def inf_norm(w):
  if type(w) == int:
    return mod_ud(w, q)
  if hasattr(w, "__len__") and not hasattr(w[0], "__len__"):
    return max(map(lambda x: mod_ud(x, q), w))
  return max(map(inf_norm, w))


if __name__ == '__main__':
  t = 1230234
  t2 = 8751135
  r1, r0 = decompose([[t, t2]], (q-1) // 88)
  print(r1, r0)
  print(highBits([[t, t2]], (q-1) // 88))
  print(lowBits([[t, t2]], (q-1) // 88))