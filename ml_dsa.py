import sys
from secrets import token_bytes as random_bytes
from hashlib import shake_256, md5, sha3_512
from dsa_helper import *
from dsa_ntt import *
import argparse
from base64 import encodebytes, b64decode

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

def pemEncode(data, name):
  head = f"----- BEGIN {name} -----\n"
  tail = f"----- END {name} -----\n"
  return head.encode() + encodebytes(data) + tail.encode()

def pemDecode(data):
  data = data.decode()
  data = ''.join(data.strip().split('\n')[1:-1])
  return b64decode(data)

def keygen(mldsa, publicKey, secretKey):
  pk, sk = mldsa.genKey()

  if publicKey.endswith(".pem"):
    pk = pemEncode(pk, "MLDSA PUBLIC KEY")

  if secretKey.endswith(".pem"):
    sk = pemEncode(sk, "MLDSA SECRET KEY")    

  with open(secretKey, 'wb') as f:
    f.write(sk)
  with open(publicKey, 'wb') as f:
    f.write(pk)


def sign(mldsa, secretKey, data, signatureFile):
  sk = open(secretKey, 'rb').read()
  if secretKey.endswith(".pem"):
    sk = pemDecode(sk)

  sig = None
  try:
    sig = mldsa.sign(sk, data)
  except:
    print("An error has occured", file=sys.stderr)
    return False

  if signatureFile.endswith(".pem"):
    sig = pemEncode(sig, "MLDSA SIGNATURE")

  with open(signatureFile, 'wb') as f:
    f.write(sig)

  return True


def verify(mldsa, publicKey, data, signatureFile):
  pk = open(publicKey, 'rb').read()
  if publicKey.endswith(".pem"):
    pk = pemDecode(pk)

  sig = open(signatureFile, 'rb').read()
  if signatureFile.endswith(".pem"):
    sig = pemDecode(sig)

  result = False
  try:
    result = mldsa.verify(pk, data, sig)
  except:
    print("An error has occured", file=sys.stderr)
    return False

  return result


def readFromSTDIN():
  print("No target specified, reading from STDIN instead. Use Ctrl+D to stop the input.", file=sys.stderr)
  while True:
    line = input().encode()
    if b"\x04" in line:
      data += line[:line.index(b"\x04")]
      break
    else:
      data += line + b'\n'
  return data


def main():
  parser = argparse.ArgumentParser(description="Python script for creating and signing with ML-DSA")
  parser.add_argument("-p", "--params", help="Params set for ML-DSA: 44, 65, 87; coresponding to 128-bit, 192-bit, 256-bit security (resp); default: 65", default=65, type=int)
  parser.add_argument("-m", "--mode", help="Mode of operation [keygen|sign|verify]", required=True)
  parser.add_argument("--secret-key", help="Secret key path to store (keygen) or read (sign)", default=None)
  parser.add_argument("--public-key", help="Public key path to store (keygen) or read (verify)", default=None)
  parser.add_argument("--target-file", help="File used to sign (sign) or verify (verify); read from STDIN if not set", default=None)
  parser.add_argument("--signature-file", help="Signature path to store (sign) or read (verify)", default=None)

  args = parser.parse_args()
  if args.params not in [44, 65, 87]:
    print("Params set is either 44, 65 or 87", file=sys.stderr)
    return

  param_name = "ML-DSA-" + str(args.params)
  mldsa = ML_DSA(**params[param_name])

  if args.mode == "keygen":
    if args.secret_key is None:
      print("Require secret key path", file=sys.stderr)
      return
    if args.public_key is None:
      print("Require public key path", file=sys.stderr)
      return

    keygen(mldsa, args.public_key, args.secret_key)

  elif args.mode == "sign":
    if args.secret_key is None:
      print("Require secret key path", file=sys.stderr)
      return
    if args.signature_file is None:
      print("Please specify where to store the signature", file=sys.stderr)
      return

    data = b""
    if args.target_file is None:
      data = readFromSTDIN()
    else:
      data = open(args.target_file, 'rb').read()

    sign(mldsa, args.secret_key, data, args.signature_file)

  elif args.mode == "verify":
    if args.public_key is None:
      print("Require public key path", file=sys.stderr)
      return
    if args.signature_file is None:
      print("Please specify where to refer the signature", file=sys.stderr)
      return

    data = b""
    if args.target_file is None:
      data = readFromSTDIN()
    else:
      data = open(args.target_file, 'rb').read()

    res = verify(mldsa, args.public_key, data, args.signature_file)
    if res:
      print("Accepted")
    else:
      print("Rejected")


if __name__ == '__main__':
  # mldsa = ML_DSA(**params["ML-DSA-87"])
  # pk, sk = mldsa.genKey()
  # print("Public key:", pk.hex())
  # print("\nSecret key:", sk.hex())

  # msg = random_bytes(64)
  # print("\nMessage:", msg.hex())
  # sig = mldsa.sign(sk, msg)
  # print("\nSignature:", sig.hex())
  # print("\nVerification:", mldsa.verify(pk, msg, sig))
  main()
