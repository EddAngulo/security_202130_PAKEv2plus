from FP import FP

class ECPoint:

    def __init__(self, a, b, x=None, y=None):
        self.x = x
        self.y = y
        self.a = a
        self.b = b


    def is_identity(self):
        return self.x == None and self.y == None

    
    def equals(self, Q):
        if isinstance(Q, self.__class__):
            if self.is_identity() and Q.is_identity():
                return True
            else:
                if self.is_identity():
                    return False
                else:
                    if Q.is_identity():
                        return False
                    else:
                        return self.x == Q.x and self.y == Q.y and self.a == Q.a and self.b == Q.b
        return False


    def __eq__(self, other):
        return self.equals(other)


    def __add__(self, Q):
        if Q.is_identity(): 
            return self

        if self.is_identity():
            return Q

        if not self.x == Q.x:
            s = self.y - Q.y
            s = s / (self.x - Q.x)
            x = (s * s - self.x) - Q.x     
            y = s * (self.x - x) - self.y
            return ECPoint(self.a, self.b, x, y)  
        else:
            if self.y == Q.y:
                if self.y.rep == 0: # P.y.rep
                    return ECPoint(self.a, self.b)
                three = FP(3, self.a.p)
                two = FP(2, self.a.p)
                s = three * (self.x ** 2)
                s = s + self.a
                s = s / (two*self.y)
                x = (s * s - self.x) - Q.x 
                y = s * (self.x - x) - self.y
                return ECPoint(self.a, self.b, x, y)
            else:
                return ECPoint(self.a, self.b)


    def inverse(self):
        if self.is_identity():
            return ECPoint(self.a, self.b)
        else:
            return ECPoint(self.a, self.b, self.x, self.y.a_inverse())
       
        
    def double(self):
        if  self.is_identity():
            return ECPoint(self.a, self.b)

        if  self.y.rep == 0:
            return ECPoint(self.a, self.b)

        three = FP(3, self.a.p)
        two = FP(2, self.a.p)
        s = three * (self.x ** 2)
        s = s + self.a
        s = s / (two * self.y)
        x = (s * s - self.x) - self.x 
        y = s * (self.x - x) - self.y
        return ECPoint(self.a, self.b, x, y)


    def __sub__(self, P):
        return self + P.inverse()


    def point_multiplication(self, n):
        if n < 0:
            n1 = -n
            P = self.inverse()
        else:
            n1 = n
            P = self
        
        T = ECPoint(self.a, self.b)
        for k in range(n1.bit_length() - 1, -1, -1):
            T = T.double()
            if (n1 >> k) & 1:
                T = T + P
        return T


    def to_bytes(self):
        pp = self.x.p
        cx = self.x.rep
        cy = self.y.rep
        lt = (pp.bit_length() + 7) // 8
        return cx.to_bytes(lt, byteorder='big') + cy.to_bytes(lt, byteorder='big')
    

    @staticmethod
    def point_from_bytes(a, b, f_array):
        lt = (a.p.bit_length() + 7) // 8
        if len(f_array) == 2 * lt:
            x = FP(int.from_bytes(f_array[:lt], byteorder='big'), a.p)
            y = FP(int.from_bytes(f_array[lt:], byteorder='big'), a.p)
            return ECPoint(a, b, x=x, y=y)
        else:
            raise RuntimeError("Array length is not expected")


    def __str__(self): 
        if self.is_identity():
            return "I"       
        return '(' + str(self.x.rep) + ',' + str(self.y.rep) + ')'