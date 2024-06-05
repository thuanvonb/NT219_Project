from ml_kem import ML_KEM, params as mlkem_params
from ml_dsa import ML_DSA, verify, pemDecode, params as mldsa_params
from pwn import remote
from struct import pack, unpack
from secrets import token_bytes
from byte_stream import ByteStream
from hashlib import shake_256, sha384, md5, sha1
from Crypto.Cipher import AES

signature = "ML-DSA-65"
hash_size = 384 // 8
iv_size = 16

mlkems = [0, 1, 2]
aes_keysize = [0, 1, 2]

def wrap_len(data, indicator):
  return bytes([indicator]) + pack('<l', len(data)) + data

def encode_client_hello(mlkem, aes, client_random):
  data = client_random
  for t in [mlkem, aes]:
    data += bytes([len(t)])
    for v in t:
      data += bytes([v])
  data += b"\0\0"
  return wrap_len(data, 1)

def decode_server_hello(data):
  server_random = data.extract(32)
  mlkem = data.extract(1)[0]
  aes = data.extract(1)[0]

  if data.extract(1) != b'\x0b':
    return None

  pk_len = unpack('<l', data.extract(4))[0]
  pk = data.extract(pk_len)
  sig_len = unpack('<l', data.extract(4))[0]
  sig = data.extract(sig_len)

  ek_len = unpack('<l', data.extract(4))[0]
  ek = data.extract(ek_len)
  sig_ek_len = unpack('<l', data.extract(4))[0]
  sig_ek = data.extract(sig_ek_len)

  if not data.isComplete:
    return None
  return server_random, mlkem, aes, pk, sig, ek, sig_ek


class Client:
  def __init__(self, connect_ip, connect_port):
    self.connect_ip = connect_ip
    self.connect_port = connect_port
    self.mldsa = ML_DSA(**mldsa_params[signature])
    self.handshake_msg = b""

  def connect(self):
    self.connection = remote(self.connect_ip, self.connect_port)
    if not self.establish_secure_session():
      self.connection.close()

  def send_client_hello(self):
    self.client_random = token_bytes(32)
    client_hello = encode_client_hello(mlkems, aes_keysize, self.client_random)
    self.handshake_msg += client_hello
    self.connection.send(client_hello)

  def receive_server_hello(self):
    server_hello, raw_data = ByteStream.recv(self.connection, 2, b"\x0e\x00\x00\x00")
    if server_hello is None:
      return False
    self.handshake_msg += raw_data
    res = decode_server_hello(server_hello)
    if res is None:
      return False

    self.server_random, selected_mlkem, selected_aes, pk, sig, ek, sig_ek = res

    ca_pk = pemDecode(open('client_vaults/ca_public.pem', 'rb').read())
    if not self.mldsa.verify(ca_pk, pk, sig):
      return False

    if not self.mldsa.verify(pk, ek, sig_ek):
      return False

    self.server_ek = ek
    self.kem_param = mlkem_params[list(mlkem_params.keys())[selected_mlkem]]
    self.aes_keysize = [16, 24, 32][selected_aes]
    self.mlkem = ML_KEM(**self.kem_param)
    if not self.mlkem.validateEk(self.server_ek):
      return False
    return True


  def send_client_key_exchange(self):
    res, data = self.mlkem.encapsulate(self.server_ek)
    if not res:
      return False
    pre_master_secret, encapsulated = data
    data = wrap_len(encapsulated + b"\x00\x00\x00\x00", 0x16)
    self.handshake_msg += data
    self.connection.send(data)
    self.master_secret = shake_256(pre_master_secret + b"master secret" + self.server_random + self.client_random).digest(48)
    return True


  def generate_session_keys(self):
    total_length = hash_size*2 + self.aes_keysize*2 + iv_size*2
    key_block = ByteStream(shake_256(self.master_secret + b"key expansion" + self.server_random + self.client_random).digest(total_length))
    self.client_mac_secret = key_block.extract(hash_size)
    self.server_mac_secret = key_block.extract(hash_size)
    self.client_key = key_block.extract(self.aes_keysize)
    self.server_key = key_block.extract(self.aes_keysize)
    self.client_iv = key_block.extract(iv_size)
    self.server_iv = key_block.extract(iv_size)

    self.aes_server = AES.new(self.server_key, AES.MODE_GCM, nonce=self.server_iv)
    self.aes_client = AES.new(self.client_key, AES.MODE_GCM, nonce=self.client_iv)


  def receive_server_final_message(self):
    data, _ = ByteStream.recv(self.connection, 0x14, b"\0\0\0\0")
    if data is None:
      return False

    data = data.data
    final_msg = shake_256(self.master_secret + b"client finished" + md5(self.handshake_msg).digest() + sha1(self.handshake_msg).digest()).digest(16)

    ef, tag = data[:-16], data[-16:]
    try:
      pt = self.aes_client.decrypt_and_verify(ef, tag)
    except ValueError:
      return False

    return final_msg == pt


  def establish_secure_session(self):
    assert self.connection is not None
    self.send_client_hello()
    if not self.receive_server_hello():
      return False

    if not self.send_client_key_exchange():
      return False

    self.generate_session_keys()

    final_msg = shake_256(self.master_secret + b"client finished" + md5(self.handshake_msg).digest() + sha1(self.handshake_msg).digest()).digest(16)
    final_msg, tag = self.aes_server.encrypt_and_digest(final_msg)
    final_msg += tag
    self.connection.send(wrap_len(final_msg + b"\0\0\0\0", 0x14))

    if not self.receive_server_final_message():
      return False

    print("Secure session established")
    return True

  


client = Client('127.0.0.1', 4433)
client.connect()
