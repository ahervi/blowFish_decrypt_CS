from Crypto.Cipher import Blowfish
import sys
from struct import pack
import numpy as np

annee = np.int16(2019)
mois = np.int16(3)
jour = np.int16(5)
jourSemaine = np.int16(3)
heure = np.int16(10)
#minute = np.int16(55)
#seconde = np.int16(12)
#ms
bs = Blowfish.block_size
iv =  b'@GPCODE\0'
print("IV : " + str(iv))
with open('index.html', 'rb') as f:
    plaintext = f.read()

plaintext = plaintext[4:]
print("Ciphertext nettoyé : " + str(plaintext))

#plaintext = b'\x00\x00\x00\x22\x4c\xd3\x3b\x9b\x61\x5a\xeb\x24\x6e\x70\xe4\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18\x93\xae\x41\x80\x68\x9c\x9a\xbe\x49\x67\xc5\x0a'
plen = bs - len(plaintext) % bs
padding = [plen]*plen
padding = pack('b'*plen, *padding) 
print("Base de la clé : " + str(np.array([annee, mois, jourSemaine, jour])))
for minIter in range(54, 59):
  #print(minIter)
  minute = np.int16(minIter)
  for secIter in range(60): 
    seconde = np.int16(secIter)
    for msIter in range(1000):
      ms = np.int16(msIter)
      key = np.array([annee, mois, jourSemaine, jour, heure, minute, seconde, ms]).tobytes()

      #print("Test de la clé : " + str(np.frombuffer(key, dtype="int16")))
      cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
      msg = cipher.decrypt(plaintext + padding)
      msgLisible = "".join( chr(x) for x in msg)

      if "test" in msgLisible :

        print("ClearText trouvé :" + str(msgLisible))
        print("Clé trouvée en binaire : " + str(key))
        print("Clé trouvée en sémantique : " + str(np.frombuffer(key, dtype="int16")))
