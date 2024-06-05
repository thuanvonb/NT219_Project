from ml_kem import ML_KEM, params as mlkem_params
from ml_dsa import ML_DSA, sign, pemDecode, params as mldsa_params
from pwn import listen
from Crypto.Cipher import AES
from hashlib import shake_256, sha384, md5, sha1
from secrets import token_bytes
from struct import pack
from byte_stream import ByteStream

signature = "ML-DSA-65"
hash_size = 384 // 8
iv_size = 16

def wrap_len(data, indicator):
  return bytes([indicator]) + pack('<l', len(data)) + data

def decode_client_hello(data):
  ml_kems = []
  aes_keysize = []
  client_random = data.extract(32)

  for t in [ml_kems, aes_keysize]:
    n = data.extract(1)[0]
    for i in range(n):
      t.append(data.extract(1)[0])

  if not data.isComplete:
    return None

  return ml_kems, aes_keysize, client_random

def encode_selected_suite(mlkem, aes, server_random):
  data = server_random
  data += bytes([mlkem, aes])
  return data


class Server:
  def __init__(self, listen_ip, port, priority_suite=None):
    self.listen_ip = listen_ip
    self.port = port
    self.priority_suite = priority_suite
    self.mldsa = ML_DSA(**mldsa_params[signature])
    self.handshake_msg = b""

  def listen(self):
    self.connection = listen(port=self.port, bindaddr=self.listen_ip)
    self.connection.wait_for_connection()
    if not self.establish_secure_session():
      self.connection.close()

  def receive_client_hello(self):
    client_hello, raw_data = ByteStream.recv(self.connection, 1, b"\0\0")
    if client_hello is None:
      return False

    self.handshake_msg += raw_data
    out = decode_client_hello(client_hello)
    if out is None:
      return False

    ml_kems, aes_keysize, self.client_random = out
    selected_mlkem = max(ml_kems)
    selected_aes = max(aes_keysize)
    if self.priority_suite is not None:
      if self.priority_suite in ml_kems:
        selected_mlkem = self.priority_suite
      if self.priority_suite in aes_keysize:
        selected_aes = self.priority_suite

    self.kem_param = mlkem_params[list(mlkem_params.keys())[selected_mlkem]]
    self.aes_keysize = [16, 24, 32][selected_aes]
    self.mlkem = ML_KEM(**self.kem_param)
    self.server_random = token_bytes(32)
    return (selected_mlkem, selected_aes)

  def send_server_hello(self, selected_suite):
    selected_mlkem, selected_aes = selected_suite
    data = encode_selected_suite(selected_mlkem, selected_aes, self.server_random)
    pk = open("server_vaults/server_public.bin", 'rb').read()
    data += b"\x0b" + pack('<l', len(pk)) + pk
    sig = open("server_vaults/pk.sig", 'rb').read()
    data += pack('<l', len(sig)) + sig
    sig_sk = pemDecode(open("server_vaults/server_secret.pem", 'rb').read())

    self.ek, self.dk = self.mlkem.genKey()
    sig_ek = self.mldsa.sign(sig_sk, self.ek)

    data += pack('<l', len(self.ek)) + self.ek
    data += pack('<l', len(sig_ek)) + sig_ek

    data += bytes([14, 0, 0, 0])
    server_hello = wrap_len(data, 2)
    self.handshake_msg += server_hello
    self.connection.send(server_hello)

  def receive_client_key_exchange(self):
    ec_secret, raw_data = ByteStream.recv(self.connection, 0x16, b"\0\0\0\0")
    if ec_secret is None:
      return False
    self.handshake_msg += raw_data
    res, pre_master_secret = self.mlkem.decapsulate(self.dk, ec_secret.data)
    if not res:
      return False

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


  def receive_client_final_message(self):
    data, _ = ByteStream.recv(self.connection, 0x14, b"\0\0\0\0")
    if data is None:
      return False

    data = data.data
    final_msg = shake_256(self.master_secret + b"client finished" + md5(self.handshake_msg).digest() + sha1(self.handshake_msg).digest()).digest(16)

    ef, tag = data[:-16], data[-16:]
    try:
      pt = self.aes_server.decrypt_and_verify(ef, tag)
    except ValueError:
      return False

    return final_msg == pt

  def establish_secure_session(self):
    assert self.connection is not None
    res = self.receive_client_hello()
    if res == False:
      return False

    self.send_server_hello(res)
    if not self.receive_client_key_exchange():
      return False

    self.generate_session_keys()

    if not self.receive_client_final_message():
      return False

    final_msg = shake_256(self.master_secret + b"client finished" + md5(self.handshake_msg).digest() + sha1(self.handshake_msg).digest()).digest(16)
    final_msg, tag = self.aes_client.encrypt_and_digest(final_msg)
    final_msg += tag

    self.connection.send(wrap_len(final_msg + b"\0\0\0\0", 0x14))
    print("Secure session established")
    return True


    
server = Server("0.0.0.0", 4433, priority_suite=1)
server.listen()
