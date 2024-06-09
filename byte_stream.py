from struct import unpack

class ByteStream:
  def __init__(self, data):
    self.data = data
    self.offset = 0

  @staticmethod
  def recv(receiver, id, ending_bytes):
    data = b""
    while len(data) < 5:
      data += receiver.recvuntil(ending_bytes)
    print(data)
    if data[0] != id:
      return None, None
    l = unpack('<l', data[1:5])[0] + 1
    while len(data) < l:
      data += receiver.recvuntil(ending_bytes)
    return ByteStream(data[5:-len(ending_bytes)]), data

  def __len__(self):
    return len(self.data)

  @property
  def remainLen(self):
    return len(self.data) - self.offset

  def sniff(self, l):
    if self.remainLen < l:
      return None
    return self.data[self.offset:][:l]
  
  def extract(self, l):
    k = self.sniff(l)
    if k is not None:
      self.offset += l
    return k

  @property
  def isComplete(self):
    return self.offset == len(self.data)