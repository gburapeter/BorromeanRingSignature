from builtins import int,pow

import hashlib
import random
import binascii
import secrets

from ecpy.curves     import Curve,Point
from ecpy.keys       import ECPublicKey, ECPrivateKey
from ecpy            import ecrand
from ecpy.curves     import ECPyException
from pprint import pprint


def _borromean_hash(m,e,i,j, H):
   
    str = "%s,%s,%X,%X" % (m, e, i, j)
    return int(hashlib.sha256(str.encode()).hexdigest(), 16) 

class Borromean:
   
    def __init__(self,  fmt="BTUPLE") :
        self.fmt = fmt
        self._curve = Curve.get_curve('secp256k1')
        self._hash = hashlib.sha256
        
    def sign(self, msg, rings, pv_keys, pv_keys_index, curve):
       
        G     = self._curve.generator
        order = self._curve.order

        #set up locals
        ring_count = len(rings)
        privkeys = pv_keys
        pubkeys = []
        rsizes = []
        for r in rings:
            pubkeys = pubkeys+r
            rsizes.append(len(r))
        e0 = None
        s  = [None]*len(pubkeys)
        k  = [None]*len(rings)
            
        #step2-3
        r0 = 0
        sha256_e0 = self._hash()
        for i in range (0,ring_count):
            k[i] = random.randint(1,order)
            kiG = k[i]*G
            j0 = pv_keys_index[i]
            e_ij= kiG 
           
            for j in range(j0+1, rsizes[i]):
                s[r0+j] = random.randint(1,order)
                e_ij = _borromean_hash(m,e_ij,i,j, self._hash)
               
                
                part1=curve.mul_point(s[r0+j],G)
                part2=curve.mul_point(e_ij,pubkeys[r0+j].W)
                sG_eP = curve.add_point(part1,part2)
                
                
                
                e_ij = sG_eP
            sha256_e0.update(str(e_ij).encode())
            r0 += rsizes[i]
        sha256_e0.update(m.encode())
        e0 =  sha256_e0.digest()    
        #step 4
        r0 = 0
        for i in range (0, ring_count):
            j0 = pv_keys_index[i]
            e_ij = _borromean_hash(m,e0,i,0, self._hash)
            
            for j in range(0, j0):
                s[r0+j] = random.randint(1,order)  
                part1=curve.mul_point(s[r0+j],G)
                part2=curve.mul_point(e_ij,pubkeys[r0+j].W)
                
                sG_eP = curve.add_point(part1,part2)
             
                e_ij = _borromean_hash(m,sG_eP,i,j+1, self._hash)
               
            s[r0+j0] = (k[i]-privkeys[i].d*e_ij)%order
            r0 += rsizes[i]
            
      
        
        return (e0,s)


    def verify(self, msg, sig, rings,curve):
        
        
        G     = self._curve.generator
       
        ring_count = len(rings)
        pubkeys = []
        rsizes = []
        for r in rings:
            pubkeys = pubkeys+r
            rsizes.append(len(r))
        #verify
        e0 = sig[0]
        s = sig[1]
        sha256_e0 = self._hash()
        r0 = 0
        for i in range (0,ring_count):
            e_ij = _borromean_hash(m,e0,i,0, self._hash) 
            for j in range(0,rsizes[i]):
                #e_ij = int.from_bytes(e_ij,'big')
                s_ij = s[r0+j]
                #sG_eP = s_ij*G + e_ij*pubkeys[r0+j].W
                part1=curve.mul_point(s[r0+j],G)
                part2=curve.mul_point(e_ij,pubkeys[r0+j].W)
                
                sG_eP = curve.add_point(part1,part2)
                e_ij = sG_eP
                if j != rsizes[i]-1:
                    e_ij = _borromean_hash(m,sG_eP,i,j+1, self._hash) 
                else:
                    sha256_e0.update(str(e_ij).encode())
                    
            r0 += rsizes[i]
        sha256_e0.update(m.encode())
        e0x = sha256_e0.digest()
        
        
        return e0 == e0x


borromean = Borromean()
        
cv     = Curve.get_curve('secp256k1')

print(f"Name: {cv.name},  Type: {cv.type}")
print(f"Size: {cv.size}, a={cv.a}")
pprint(f"G={cv.generator}, field={cv.field}, order={cv.order}\n")
print()


seckey0  = ECPrivateKey(secrets.randbits(32*8), cv)
seckey1  = ECPrivateKey(secrets.randbits(32*8), cv)
seckey2  = ECPrivateKey(secrets.randbits(32*8), cv)
seckey3  = ECPrivateKey(secrets.randbits(32*8), cv)
seckey4  = ECPrivateKey(secrets.randbits(32*8), cv)
seckey5  = ECPrivateKey(secrets.randbits(32*8), cv)
seckey6  = ECPrivateKey(secrets.randbits(32*8), cv)
seckey7  = ECPrivateKey(secrets.randbits(32*8), cv)

        
pubkey0 = seckey0.get_public_key()
pubkey1 = seckey1.get_public_key()
pubkey2 = seckey2.get_public_key()
pubkey3 = seckey3.get_public_key()
pubkey4 = seckey4.get_public_key()
pubkey5 = seckey5.get_public_key()
pubkey6 = seckey6.get_public_key()
pubkey7 = seckey7.get_public_key()

pubring1=[pubkey0,pubkey1,pubkey2,pubkey3]
pubring2=[pubkey4,pubkey5,pubkey6,pubkey7]
pubset = (pubring1 , pubring2)
secset = [seckey1 , seckey4]
secidx=[1,0]
m="hello monero"


sigma = borromean.sign(m, pubset, secset, secidx, cv)
validSign = borromean.verify( m, sigma, pubset,cv)



print("Ring 1 has the members:")
for i in pubring1:
  print(i)

print()

print("Ring 2 has the members:")
for i in pubring2:
  print(i)
print()


if(validSign):
  print("The Borromean Ring Signature is valid!")
else:
  print("The Borromean Ring Signature is invalid, something went wrong!")

