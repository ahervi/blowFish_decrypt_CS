#!/usr/bin/env python3
from Crypto.Cipher import Blowfish
import sys
from struct import pack
import numpy as np

annee = np.int16(2019)
mois = np.int16(3)
jour = np.int16(5)
jourSemaine = np.int16(3)
heure = np.int16(9)
#minute = np.int16(55)
#seconde = np.int16(12)
#ms
bs = Blowfish.block_size
iv =  b'@GPCODE\0'
print("IV : " + str(iv))
with open('index.html', 'rb') as f:
    ciphertexte = f.read()

ciphertexte = ciphertexte[14:]

print("Ciphertext nettoyé : " + str(ciphertexte))

plen = bs - len(ciphertexte) % bs
padding = [plen]*plen
padding = pack('b'*plen, *padding) 
print("Base de la clé : " + str(np.array([annee, mois, jourSemaine, jour])))
for minIter in range(0, 60):
  #print(minIter)
  minute = np.int16(minIter)
  for secIter in range(60): 
    seconde = np.int16(secIter)
    for msIter in range(1000):
      ms = np.int16(msIter)
      key = np.array([annee, mois, jourSemaine, jour, heure, minute, seconde, ms]).tobytes()

      #print("Test de la clé : " + str(np.frombuffer(key, dtype="int16")))
      cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
      msg = cipher.decrypt(ciphertexte + padding)
      msgLisible = "".join( chr(x) for x in msg)

      if "test" in msgLisible :

        print("ClearText trouvé :" + str(msgLisible))
        print("Clé trouvée en binaire : " + str(key))
        print("Clé trouvée en sémantique : " + str(np.frombuffer(key, dtype="int16")))
