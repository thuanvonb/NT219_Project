from secrets import token_bytes as random_bytes
from k_pke import K_PKE
from helper_functions import *

class ML_KEM:
  def __init__(self, k, n1, n2, du, dv):
    self.k = k
    self.n1 = n1
    self.n2 = n2
    self.du = du
    self.dv = dv
    self.kpke = K_PKE(k, n1, n2, du, dv)

  def genKey_MLKEM(self):
    z = random_bytes(32)
    (ek_p, dk_p) = self.kpke.genKey()
    ek = ek_p
    dk = dk_p + ek + hashH(ek) + z

    return ek, dk

  def validateEk(self, ek):
    t = ek[:-32]
    m = byteDecode(t, 12)
    u = b''.join([byteEncode(m[256*i:256*(i+1)], 12) for i in range(self.k)])
    return u == t

  def encapsulate(self, ek):
    if len(ek) != 384*self.k + 32:
      return (False, "Invalid encapsulation key length")

    if not self.validateEk(ek):
      return (False, "Invalid encapsulation key")

    m = random_bytes(32)
    t = hashG(m + hashH(ek))
    K = t[:32]
    r = t[32:]
    c = self.kpke.encrypt(ek, m, r)
    return (True, (K, c))

  def decapsulate(self, dk, ct):
    if len(ct) != 32*(self.du * self.k + self.dv):
      return (False, "Corrupted ciphertext")

    if len(dk) != 768*self.k + 96:
      return (False, "Invalid decapsulation key")

    dk_pke = dk[:384*self.k]
    ek_pke = dk[384*self.k:768*self.k + 32]

    d2 = dk[768*self.k + 32:]

    h = d2[:32]
    z = d2[32:]

    m = self.kpke.decrypt(dk_pke, ct)
    gm = hashG(m + h)
    K_out = gm[:32]
    r2 = gm[32:]
    K3 = hashJ(z + ct)
    ct2 = self.kpke.encrypt(ek_pke, m, r2)

    if ct != ct2:
      return (False, "Compromised ciphertext")

    return (True, K_out)

def main():
  mlkem = ML_KEM(4, 2, 2, 10, 4)
  ek, dk = mlkem.genKey_MLKEM()
  print("Encapsulation key:", ek.hex())

  res, out = mlkem.encapsulate(ek)
  if not res:
    print("\nEncapsulation error: " + out)
    return

  K, ct = out
  print("\nEncapsulated secret:", ct.hex())

  print("\nDecapsulation key:", dk.hex())
  res, out = mlkem.decapsulate(dk, ct)
  if not res:
    print("\nDecapsulation error: " + out)
    return

  K2 = out
  assert K == K2
  print("\nShared secret:")
  print("Encapsulation key's owner party:", K.hex())
  print("Decapsulation key's owner party:", K2.hex())

if __name__ == '__main__':
  main()