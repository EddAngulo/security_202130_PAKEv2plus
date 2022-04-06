import random

class FP:

    def __init__(self, rep, p):
        self.p = p
        self.rep = (rep % p)


    def __add__(self, b):
        rep = (self.rep + b.rep) % self.p
        return FP(rep, self.p)


    def __sub__(self, b):
        rep = (self.rep - b.rep) % self.p
        return FP(rep, self.p)


    def get_random_element(self):
        rep = int(random.randint(0, self.p - 1))
        return FP(rep, self.p)


    def get_zero(self):
        return FP(0, self.p)


    def get_one(self):
        return FP(1, self.p)


    def get_minus_one(self):
        return FP(self.p - 1, self.p)


    def get_random_nonzero_element(self):
        element = random.randint(1, self.p - 1)
        return FP(element, self.p)


    def __pow__(self, n):  
        return FP(pow(self.rep, n, self.p), self.p)


    def get_square(self):
        g = self.get_random_nonzero_element()
        one = self.get_one()
        output = g ** ((self.p - 1) // 2)
        while not output.equals(one):
            g = self.get_random_nonzero_element()
            output = g ** ((self.p - 1) // 2)
        return g


    def get_nonsquare(self):
        g = self.get_random_nonzero_element()
        one = self.get_one()
        output = g ** ((self.p - 1) // 2)
        while output.equals(one):
            g = self.get_random_nonzero_element()
            output = g ** ((self.p - 1) // 2)
        return g


    def __truediv__(self, y):
        return self * y.m_inverse()


    def get_order(self):
        return self.p    


    def get_primitive_root(self):
        if self.p == 17:
            g = self.get_random_nonzero_element()
            g8 = g ** 8
            while g8.rep == 1: 
                g = self.get_random_nonzero_element()
                g8 = g ** 8
            gi = g ** 15
            return g, gi


    def a_inverse(self):
       zero = self.get_zero() 
       return zero - self


    def m_inverse(self):
        def egcd(a, b):
            if a == 0:
                return (b, 0, 1)
            g, y, x = egcd(b % a, a)
            return (g, x - (b // a) * y, y)
  
        def modinv(a, m):
            g, x, y = egcd(a, m)
            if g != 1:
                raise Exception('No modular inverse')
            return x % m
        
        return FP(modinv(self.rep, self.p), self.p)
        
    
    def __mul__(self, b):
        rep = (self.rep * b.rep) % self.p
        return FP(rep, self.p)
    

    def equals(self,a):
        if isinstance(a, self.__class__): 
            return self.rep == a.rep and self.p == a.p
        return False
    
    
    def __eq__(self, other):
        return self.equals(other)


    def __str__(self):        
        return str(self.rep)


    def is_one(self):
        return self.rep == 1


    def is_nonzero(self):
        return self.rep != 0