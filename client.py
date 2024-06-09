from ml_kem import ML_KEM, params as mlkem_params
from ml_dsa import ML_DSA, verify, pemDecode, params as mldsa_params
from pwn import remote
from struct import pack, unpack
from secrets import token_bytes
from byte_stream import ByteStream
from hashlib import shake_256, sha384, md5, sha1
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA3_384
from kem_helper import XOF
from time import sleep
import threading
import tkinter as tk
from tkinter import messagebox
import tkthread

signature = "ML-DSA-65"
hash_size = 384 // 8
iv_size = 16

mlkems = [0, 1, 2]
aes_keysize = [0, 1, 2]

def wrap_len(data, indicator=None):
  d = b""
  if indicator is not None:
    d = bytes([indicator])
  return d + pack('<l', len(data)) + data

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


def iv_at_idx(iv, id):
  return iv[id:id+12]

class Client:
  def __init__(self, connect_ip, connect_port):
    self.connect_ip = connect_ip
    self.connect_port = connect_port
    self.mldsa = ML_DSA(**mldsa_params[signature])
    self.handshake_msg = b""
    self.secured = False
    self.connection = None

  def connect(self):
    self.connection = remote(self.connect_ip, self.connect_port)
    if not self.establish_secure_session():
      self.connection.close()
      return False

    self.secured = True
    return True

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
    total_length = hash_size*2 + self.aes_keysize*4 + iv_size*4
    key_block = ByteStream(shake_256(self.master_secret + b"key expansion" + self.server_random + self.client_random).digest(total_length))
    self.client_mac_key = key_block.extract(hash_size)
    self.server_mac_key = key_block.extract(hash_size)
    client_msg_key = key_block.extract(self.aes_keysize)
    server_msg_key = key_block.extract(self.aes_keysize)
    self.client_key = key_block.extract(self.aes_keysize)
    self.server_key = key_block.extract(self.aes_keysize)
    self.client_iv = shake_256(key_block.extract(iv_size)).digest(65536+12)
    self.server_iv = shake_256(key_block.extract(iv_size)).digest(65536+12)
    self.client_final_iv = key_block.extract(iv_size)
    self.server_final_iv = key_block.extract(iv_size)
    self.aes_client_msg = AES.new(client_msg_key, AES.MODE_ECB)
    self.aes_server_msg = AES.new(server_msg_key, AES.MODE_ECB)

  def receive_server_final_message(self):
    data, _ = ByteStream.recv(self.connection, 0x14, b"\0\0\0\0")
    if data is None:
      return False

    data = data.data
    final_msg = shake_256(self.master_secret + b"client finished" + md5(self.handshake_msg).digest() + sha1(self.handshake_msg).digest()).digest(16)

    ef, tag = data[:-16], data[-16:]
    try:
      aes_client = AES.new(self.client_key, AES.MODE_GCM, nonce=self.client_final_iv)
      pt = aes_client.decrypt_and_verify(ef, tag)
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

    aes_server = AES.new(self.server_key, AES.MODE_GCM, nonce=self.server_final_iv)
    final_msg = shake_256(self.master_secret + b"client finished" + md5(self.handshake_msg).digest() + sha1(self.handshake_msg).digest()).digest(16)
    final_msg, tag = aes_server.encrypt_and_digest(final_msg)
    final_msg += tag
    self.connection.send(wrap_len(final_msg + b"\0\0\0\0", 0x14))

    if not self.receive_server_final_message():
      return False

    print("Secure session established")
    return True

  def encrypt_message(self, msg):
    mid = token_bytes(16)
    message_id = int(mid[:2].hex(), 16)
    emid = self.aes_server_msg.encrypt(mid)
    h = HMAC.new(self.server_mac_key, digestmod=SHA3_384)
    h.update(emid)
    emid += h.digest()
    aes = AES.new(self.server_key, AES.MODE_GCM, nonce=iv_at_idx(self.server_iv, message_id))
    emsg, tag = aes.encrypt_and_digest(pad(msg.encode(), 16))
    return emid + emsg + tag

  def decrypt_message(self, enc):
    emid = enc[:16]
    hmac = enc[16:64]
    emsg = enc[64:-16]
    tag = enc[-16:]

    h = HMAC.new(self.client_mac_key, digestmod=SHA3_384)
    h.update(emid)
    try:
      h.verify(hmac)
    except:
      return False
    mid = self.aes_client_msg.decrypt(emid)
    message_id = int(mid[:2].hex(), 16)
    aes = AES.new(self.client_key, AES.MODE_GCM, nonce=iv_at_idx(self.client_iv, message_id))
    msg = ""
    try:
      pt = aes.decrypt_and_verify(emsg, tag)
      msg = unpad(pt, 16).decode()
    except:
      return False
    return msg

  def close(self):
    self.connection.close()

  def send_msg(self, msg):
    self.connection.send(wrap_len(msg + b'\0\0\0\0', 0xd0))

  def can_recv(self):
    if self.connection is None:
      return False
    return self.connection.can_recv()

  def recv_msg(self):
    msg, data = ByteStream.recv(self.connection, 0xd0, b'\0\0\0\0')
    return msg.data


class UI(tk.Frame):
  def __init__(self, master=None):
    super().__init__(master, bg=None)
    self.master = master
    self.conn = None
    self.connected = None
    self.grid(column=0, row=0, sticky=(tk.N, tk.S, tk.W, tk.E))
    self.text = tk.Text(self, bg=None, height=1, width=60)
    self.text.grid(column=1, row=1, padx=5)
    self.text.bind("<Return>", self.send_message)
    self.btn = tk.Button(self, text="Connect", command=self.connect)
    self.btn.grid(column=0, row=1)
    self.btn2 = tk.Button(self, text="Send", command=self.send_message)
    self.btn2.grid(column=2, row=1)
    self.messages = tk.Listbox(self, bg=None, height=20, width=100)
    self.messages.grid(column=0, row=0, columnspan=3)
    self.master.protocol("WM_DELETE_WINDOW", self.close)
    self.exited = False

  def close(self):
    try:
      self.conn.close()
    except:
      self.conn = 1

    self.exited = True
    self.connected = False
    self.master.destroy()

  def add_message(self, msg, whom):
    self.messages.insert(tk.END, f"{whom}: {msg}")

  def send_message(self, *args, **kwargs):
    txt = self.text.get(1.0, "end-1c") 
    self.text.delete("1.0", "end")
    self.add_message(txt, "You")
    if self.conn is None or not self.connected:
      self.add_message("You haven't connected to the server", "Debug")
    else:
      enc = self.conn.encrypt_message(txt)
      self.conn.send_msg(enc)

  def connect(self):
    self.conn = Client('127.0.0.1', 4433)
    self.connected = self.conn.connect()
    if not self.connected:
      self.conn = None
      self.connected = None
      messagebox.showerror(title="Connection error", message="There's an error in negociation")
    else:
      self.master.title("Client - connected")


def recv_message(app):
  while not app.exited:
    sleep(0.1)
    if app.conn is None:
      continue
    if app.exited:
      break

    if app.conn.can_recv() and app.conn.secured:
      data = app.conn.recv_msg()
      print(data)
      msg = app.conn.decrypt_message(data)
      if msg == False:
        messagebox.showerror(title="Security error", message="Compromission attempt detected")
        app.conn.close()
        break

      app.add_message(msg, "Other")


if __name__ == '__main__':
  root = tk.Tk()
  root.title("Client")
  root.resizable(False,False)
  app = UI(root)
  thread = threading.Thread(target=recv_message, args=(app,))
  thread.start()
  app.mainloop()
# client = Client('127.0.0.1', 4433)
# client.connect()
