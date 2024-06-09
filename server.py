from ml_kem import ML_KEM, params as mlkem_params
from ml_dsa import ML_DSA, sign, pemDecode, params as mldsa_params
from pwn import listen
from Crypto.Cipher import AES
from hashlib import shake_256, sha384, md5, sha1
from secrets import token_bytes
from struct import pack
from byte_stream import ByteStream
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

def iv_at_idx(iv, id):
  return iv[id:id+12]


class Server:
  def __init__(self, listen_ip, port, priority_suite=None):
    self.listen_ip = listen_ip
    self.port = port
    self.priority_suite = priority_suite
    self.mldsa = ML_DSA(**mldsa_params[signature])
    self.handshake_msg = b""
    self.secured = False
    self.connection = None

  def listen(self):
    self.connection = listen(port=self.port, bindaddr=self.listen_ip)
    self.connection.wait_for_connection()
    if not self.establish_secure_session():
      self.connection.close()
      return False
    self.secured = True
    return True

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


  def receive_client_final_message(self):
    data, _ = ByteStream.recv(self.connection, 0x14, b"\0\0\0\0")
    if data is None:
      return False

    data = data.data
    final_msg = shake_256(self.master_secret + b"client finished" + md5(self.handshake_msg).digest() + sha1(self.handshake_msg).digest()).digest(16)

    ef, tag = data[:-16], data[-16:]
    try:
      aes_server = AES.new(self.server_key, AES.MODE_GCM, nonce=self.server_final_iv)
      pt = aes_server.decrypt_and_verify(ef, tag)
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
    aes_client = AES.new(self.client_key, AES.MODE_GCM, nonce=self.client_final_iv)
    final_msg, tag = aes_client.encrypt_and_digest(final_msg)
    final_msg += tag

    self.connection.send(wrap_len(final_msg + b"\0\0\0\0", 0x14))
    print("Secure session established")
    return True

  def decrypt_message(self, enc):
    emid = enc[:16]
    hmac = enc[16:64]
    emsg = enc[64:-16]
    tag = enc[-16:]

    h = HMAC.new(self.server_mac_key, digestmod=SHA3_384)
    h.update(emid)
    try:
      h.verify(hmac)
    except:
      return False
    mid = self.aes_server_msg.decrypt(emid)
    message_id = int(mid[:2].hex(), 16)
    aes = AES.new(self.server_key, AES.MODE_GCM, nonce=iv_at_idx(self.server_iv, message_id))
    msg = ""
    try:
      pt = aes.decrypt_and_verify(emsg, tag)
      msg = unpad(pt, 16).decode()
    except:
      return False
    return msg

  def close(self):
    self.connection.close()

  def encrypt_message(self, msg):
    mid = token_bytes(16)
    message_id = int(mid[:2].hex(), 16)
    emid = self.aes_client_msg.encrypt(mid)
    h = HMAC.new(self.client_mac_key, digestmod=SHA3_384)
    h.update(emid)
    emid += h.digest()
    aes = AES.new(self.client_key, AES.MODE_GCM, nonce=iv_at_idx(self.client_iv, message_id))
    emsg, tag = aes.encrypt_and_digest(pad(msg.encode(), 16))
    return emid + emsg + tag

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
    self.text = tk.Text(self, bg=None, height=1, width=69)
    self.text.grid(column=0, row=1, columnspan=2, padx=5)
    self.text.bind("<Return>", self.send_message)
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
      self.add_message("You haven't been connected by client", "Debug")
    else:
      enc = self.conn.encrypt_message(txt)
      self.conn.send_msg(enc)


def recv_message(app):
  while not app.exited:
    sleep(0.1)
    if app.conn is None:
      continue
    if app.exited:
      break

    if app.conn.can_recv() and app.conn.secured:
      data = app.conn.recv_msg()
      msg = app.conn.decrypt_message(data)
      if msg == False:
        messagebox.showerror(title="Security error", message="Compromission attempt detected")
        app.conn.close()
        break

      app.add_message(msg, "Other")
    

def listener(ui):
  while True:
    ui.conn = server = Server("0.0.0.0", 4433, priority_suite=1)
    ui.connected = server.listen()
    if not ui.connected:
      print("Client's connection failed")
      continue
    ui.master.title("Server - connected")
    break


# server = Server("0.0.0.0", 4433, priority_suite=1)
# server.listen()
if __name__ == '__main__':
  root = tk.Tk()
  root.title("Server")
  root.resizable(False,False)
  app = UI(root)
  thread2 = threading.Thread(target=listener, args=(app,))
  thread2.start()
  thread = threading.Thread(target=recv_message, args=(app,))
  thread.start()
  app.mainloop()