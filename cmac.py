from __future__ import division

import math
from xtea import from_bytes, to_bytes, _encrypt, b_ord

class CMAC(object):
    '''
    implementation of CMAC mode for authentication
    as described in NIST Special Publication 800-38B
    '''
    
    blocksize = 8
    bitlength= blocksize*8
    key= None
    k1 = None
    k2 = None
    message = None
    
    def __init__(self, key):
        self.key = bytearray(key)
        self.k1
        self.k2
        self.message = bytearray(0)
        self.generateSubkeys()
    
    def generateSubkeys(self):
        
        rb = bytearray(self.blocksize)
        rb[7]= 0x1B
        
        #encrypt with key input rounds and big endian
        l = _encrypt(self.key, bytearray(8), 32 , "!")

        if (b_ord(l[0])&0b10000000) == 0:
            self.k1 = from_bytes(l, byteorder='big') <<1
        else:
            self.k1 = (from_bytes(l, byteorder='big')<<1) ^ from_bytes(rb, byteorder='big')
            
        if (self.k1& (0b1<<(self.bitlength-1)) == 0):
            self.k2 = self.k1 <<1
        else:
            self.k2 = (self.k1<<1)^ from_bytes(rb, byteorder='big')
        
        self.k1 %= 0b1<<self.bitlength
        self.k2 %= 0b1<<self.bitlength
            
    def update(self, message):
        self.message.extend(message)        
    
    def final(self):
        
        n = None
        if len(self.message)==0:
            n = 1
        else:
            n = int(math.ceil(len(self.message)*8/self.bitlength))
        
        Mn = None
        #make block complete
        if len(self.message)*8%self.bitlength==0:
            Mn = from_bytes(self.message[(n-1)*8:n*8], byteorder='big')
            Mn = Mn^self.k1
        else:
            j = n*self.bitlength-len(self.message)*8-1
            Mn = from_bytes(self.message[(n-1)*8:len(self.message)*8], byteorder='big')
            Mn = Mn << (j+1)
            Mn += (0b1 <<j)
            Mn ^= self.k2
        
        self.message[(n-1)*8:n*8] = to_bytes(Mn, 8, byteorder='big')
        
        c = bytearray(self.blocksize)
        
        for i in range(1,n+1):
            d = from_bytes(c, byteorder='big')^from_bytes(self.message[(i-1)*8:i*8], byteorder='big')
            c = _encrypt(self.key, to_bytes(d, 8, byteorder='big'), 32 , "!")
        
        return c