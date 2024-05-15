import sys
sys.path.insert(1, 'DSA')

from secrets import token_bytes as random_bytes
from hashlib import shake_256, md5, sha3_512
from helper_functions import *
from ntt import *

q = 8380417
d = 13

params = {
  "ML-DSA-44": {
    "tau": 39, "lmbda": 128, "g1": 2**17, "g2": (q-1)//88, 
    "k": 4, "l": 4, "nu": 2, "omega": 80
  },
  "ML-DSA-65": {
    "tau": 49, "lmbda": 192, "g1": 2**19, "g2": (q-1)//32, 
    "k": 6, "l": 5, "nu": 4, "omega": 55
  },
  "ML-DSA-87": {
    "tau": 60, "lmbda": 256, "g1": 2**19, "g2": (q-1)//32, 
    "k": 8, "l": 7, "nu": 2, "omega": 75
  }
}

class ML_DSA:
  def __init__(self, tau, lmbda, g1, g2, k, l, nu, omega):
    self.tau = tau
    self.lmbda = lmbda
    self.g1 = g1
    self.g2 = g2
    self.k = k 
    self.l = l
    self.nu = nu
    self.omega = omega
    self.beta = self.tau * self.nu


  def genKey(self):
    epd = random_bytes(128)
    rho, rho2, K = epd[:32], epd[32:96], epd[96:]
    A_ntt = expandA(rho, self.k, self.l)
    s1, s2 = expandS(rho2, self.k, self.l, self.nu)
    s1_ntt = recursiveNTT(s1)
    prod = recursiveNTT_inv(multNTT(A_ntt, s1_ntt))
    t = [addVecs(*p) for p in zip(prod, s2)]
    t1, t0 = Power2Round(t)
    pk = pkEncode(rho, t1)
    tr = sha3_512(bytes(bytes2Bits(pk))).digest()
    sk = skEncode(rho, K, tr, s1, s2, t0, self.k, self.l, self.nu)
    return pk, sk

  def sign(self, sk, msg):
    rho, K, tr, s1, s2, t0 = skDecode(sk, self.k, self.l, self.nu)
    s1_ntt = recursiveNTT(s1)
    s2_ntt = recursiveNTT(s2)
    t0_ntt = recursiveNTT(t0)
    A_ntt = expandA(rho, self.k, self.l)
    msg_r = sha3_512(tr + msg).digest()
    rnd = random_bytes(256//8)
    rho2 = sha3_512(K + rnd + msg_r).digest()
    counter = 0
    z = None
    h = None
    while z is None and h is None:
      y = expandMask(rho2, counter, self.l, self.g1)
      w = recursiveNTT_inv(multNTT(A_ntt, recursiveNTT(y)))
      w1 = highBits(w, self.g2)
      c_r = shake_256(msg_r + bytes(w1Encode(w1, self.k, self.g2))).digest(2*self.lmbda//8)
      c1 = c_r[:32]
      c2 = c_r[32:]
      c = SampleInBall(c1, self.tau)
      c_ntt = NTT.fromPoly(c)
      cs1 = [(c_ntt * s_).toPoly() for s_ in s1_ntt]
      cs2 = [(c_ntt * s_).toPoly() for s_ in s2_ntt]
      z = [addVecs(yi, x) for yi, x in zip(y, cs1)]
      r0 = lowBits([subVecs(wi, x) for wi, x in zip(w, cs2)], self.g2)
      fm = lambda z: [[mod_ud(zii, q) for zii in zi] for zi in z]
      if inf_norm(z) >= self.g1 - self.beta or inf_norm(r0) >= self.g2 - self.beta:
        z = None
      else:
        ct0 = [(c_ntt * s_).toPoly() for s_ in t0_ntt]
        ct02 = [list(map(lambda x: -x, i)) for i in ct0]
        ww = [addVecs(subVecs(wi, csi), cti) for wi, (csi, cti) in zip(w, zip(cs2, ct0))]
        h = makeHint(ct02, ww, self.g2)
        if inf_norm(ct0) > self.g2 or sum([sum(hi) for hi in h]) > self.omega:
          z = None
          h = None
      counter += self.l
    z_ = [list(map(lambda x: mod_ud(x, q), zi)) for zi in z]
    return sigEncode(c_r, z_, h, self.k, self.l, self.g1, self.omega)


  def verify(self, pk, msg, sig):
    rho, t1 = pkDecode(pk)
    c_r, z, h = sigDecode(sig, self.lmbda, self.k, self.l, self.g1, self.omega)
    if h is None:
      return False
    A_ntt = expandA(rho, self.k, self.l)
    tr = sha3_512(bytes(bytes2Bits(pk))).digest()
    msg_r = sha3_512(tr + msg).digest()
    c1 = c_r[:32]
    c2 = c_r[32:]
    c = SampleInBall(c1, self.tau)
    c_ntt = NTT.fromPoly(c)
    z_ntt = recursiveNTT(z)
    Az_ntt = multNTT(A_ntt, z_ntt)
    t1_ntt = [(c_ntt * NTT.fromPoly(list(map(lambda x: x << d, ti)))) for ti in t1]
    w_appr = recursiveNTT_inv([ai - ti for ai, ti in zip(Az_ntt, t1_ntt)])
    w1 = useHint(h, w_appr, self.g2)
    c_n = shake_256(msg_r + bytes(w1Encode(w1, self.k, self.g2))).digest(2*self.lmbda//8)
    return all([
      inf_norm(z) < self.g1 - self.beta,
      c_n == c_r,
      sum([sum(hi) for hi in h]) <= self.omega
    ])


if __name__ == '__main__':
  mldsa = ML_DSA(**params["ML-DSA-65"])
  pk, sk = mldsa.genKey()
  print("Public key:", pk.hex())
  print("\nSecret key:", sk.hex())

  msg = random_bytes(64)
  print("\nMessage:", msg.hex())
  sig = mldsa.sign(sk, msg)
  print("\nSignature:", sig.hex())
  print("\nVerification:", mldsa.verify(pk, msg, sig))
