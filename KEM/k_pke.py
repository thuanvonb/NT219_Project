from helper_functions import *
from ntt import *
from secrets import token_bytes as random_bytes
from Crypto.Util.Padding import pad, unpad
from json import dumps

q = 3329
n = 256

class K_PKE:
  def __init__(self, k, n1, n2, du, dv):
    self.k = k
    self.n1 = n1
    self.n2 = n2
    self.du = du
    self.dv = dv

  def genKey(self):
    d = random_bytes(32)
    h = hashG(d)
    (rho, sigma) = (h[:32], h[32:])
    N = 0
    A = []
    for i in range(self.k):
      row = []
      for j in range(self.k):
        row.append(NTT(hashgen=xof(rho, i, j)))
      A.append(row)

    s = []
    e = []
    for i in range(self.k):
      s.append(NTT.fromPoly(samplePolyCBD(self.n1, prf(self.n1, sigma, N))))
      N += 1
    for j in range(self.k):
      e.append(NTT.fromPoly(samplePolyCBD(self.n1, prf(self.n1, sigma, N))))
      N += 1

    t = []
    for r, ei in zip(A, e):
      ti = NTT.zero()
      for ri, si in zip(r, s):
        ti = ti + ri * si
      t.append(ti + ei)

    ek = b""
    dk = b""
    for ti, si in zip(t, s):
      ek += byteEncode(ti, 12)
      dk += byteEncode(si, 12)
    
    ek += rho
    return ek, dk

  def encrypt(self, ek, m, r):
    N = 0
    t2 = byteDecode(ek[:384*self.k], 12)
    t = []
    l = len(t2) // self.k
    for i in range(self.k):
      t.append(NTT(init=t2[i*l:(i+1)*l]))

    rho = ek[384*self.k:]
    A = []
    for i in range(self.k):
      row = []
      for j in range(self.k):
        row.append(NTT(hashgen=xof(rho, j, i)))
      A.append(row)

    s = []
    e = []
    for i in range(self.k):
      s.append(NTT.fromPoly(samplePolyCBD(self.n1, prf(self.n1, r, N))))
      N += 1
    for j in range(self.k):
      e.append(samplePolyCBD(self.n2, prf(self.n2, r, N)))
      N += 1

    e2 = samplePolyCBD(self.n2, prf(self.n2, r, N))

    u = []
    for row, ei in zip(A, e):
      tmp = NTT.zero()
      for ri, si in zip(row, s):
        tmp = tmp + ri * si
      u.append(addVecs(tmp.toPoly(), ei))

    muy = decompress(1, byteDecode(m, 1))

    v = NTT.zero()
    
    for ti, si in zip(t, s):
      v = v + ti * si
    v = addVecs(addVecs(v.toPoly(), e2), muy)

    # print(u)
    # print(v)

    com_u = compress(self.du, u)
    com_v = compress(self.dv, v)

    c1 = b''
    c2 = byteEncode(com_v, self.dv)
    for ui in com_u:
      c1 += byteEncode(ui, self.du)

    return c1 + c2

  def decrypt(self, dk, ct):
    c = ct[:32*self.du*self.k]
    c2 = ct[32*self.du*self.k:]
    l = len(c) // self.k
    c1 = [c[l*i:l*(i+1)] for i in range(self.k)]

    c2 = byteDecode(c2, self.dv)
    for i in range(self.k):
      c1[i] = byteDecode(c1[i], self.du)

    c1 = decompress(self.du, c1)
    c2 = decompress(self.dv, c2)

    u = []
    for i in range(self.k):
      u.append(NTT.fromPoly(c1[i]))

    l = len(dk) // self.k
    dk2 = [dk[l*i:l*(i+1)] for i in range(self.k)]
    s = [NTT(init=byteDecode(dk_, 12)) for dk_ in dk2]

    k = NTT.zero()
    for si, ui in zip(s, u):
      k = k + si * ui
    k = k.toPoly()
    w = [(vi - ki) % q for vi, ki in zip(c2, k)]
    m = byteEncode(compress(1, w), 1)

    return m


if __name__ == '__main__':
  kpke = K_PKE(2, 2, 3, 10, 4)
  ek, dk = kpke.genKey()
  # print(len(ek), len(dk))
  m = b"Lorem ipsum dolor sit amet"
  ct = kpke.encrypt(ek, pad(m, 32), random_bytes(32))
  msg = unpad(kpke.decrypt(dk, ct), 32)

  print(ct)
  print(msg)
  # print()
