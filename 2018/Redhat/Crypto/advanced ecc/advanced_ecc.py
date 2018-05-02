import signal

def extended_gcd(a, b):
    x,y = 0, 1
    lastx, lasty = 1, 0
    while b:
        a, (q, b) = b, divmod(a,b)
        x, lastx = lastx-q*x, x
        y, lasty = lasty-q*y, y
    return (a, lastx, lasty)
    
def modinv(a, m):
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

class Point:
    def __init__(self, x, y):
        self.x, self.y = x, y

    def equals(self, p):
        return (self.x == p.x and self.y == p.y)  

class ECurve:
    # y^2 = x^3 + ax + b mod p
    def __init__(self, a, b, p):
        self.a, self.b, self.p = a, b, p
  
    # The method checks if the point is a valid point
    # and satisfies 4a^3 + 27b^2 != 0  
    def check(self, p):
        l = (p.y * p.y) % self.p
        r = (p.x * p.x * p.x + self.a * p.x + self.b) % self.p
        c = 4 * self.a * self.a * self.a + 27 * self.b * self.b    
        return l == r and c != 0

    # Implements point addition P + Q  
    def add(self, p, q):
        r = Point(0, 0)      
        if p.equals(r): return q
        if q.equals(r): return p           
        # if P = Q     
        if p.equals(q):      
            if p.y != 0:
                l = ((3 * p.x * p.x + self.a) % self.p * modinv(2 * p.y, self.p)) % self.p
                r.x = (l * l - 2 * p.x) % self.p
                r.y = (l * (p.x - r.x) - p.y) % self.p
        # if P != Q
        else:
            if q.x - p.x != 0:
                l = ((q.y - p.y) % self.p * modinv(q.x - p.x, self.p)) % self.p
                r.x = (l * l - p.x - q.x) % self.p
                r.y = (l * (p.x - r.x) - p.y) % self.p
        return r

    # Implements modular multiplication nP
    def multiply(self, p, n):
        ret = Point(0, 0)
        while n > 0:
            if n & 1 == 1:
                ret = self.add(ret, p)
            p = self.add(p, p)
            n >>= 1
        return ret

def check_encrypt(curve, C1, C2, k, key):
    kC2 = curve.multiply(C2, k)
    M = curve.add(C1, Point(kC2.x, curve.p - kC2.y))
    assert(M.x == key)

def advanced_encrypt(curve, M, r, k, G, flag):
    K = curve.multiply(G, k)
    if not curve.check(G) or not curve.check(K) or not curve.check(M):
        return 0
    print 'Public key is : '
    print 'G = (0x%x, 0x%x)' % (G.x, G.y)
    print 'K = (0x%x, 0x%x)' % (K.x, K.y)
    key = M.x
    cipher = key ^ flag
    print 'Flag ciphertext is : 0x%x' % cipher
    level = raw_input('Input the security level of your key : ')
    if level == '1':
        C1 = curve.add(M, curve.multiply(K, r[0]))
        C2 = curve.multiply(G, r[0])
        check_encrypt(curve, C1, C2, k, key)
        print 'Key ciphertext : '
        print 'C1 = (0x%x, 0x%x)' % (C1.x, C1.y)
        print 'C2 = (0x%x, 0x%x)' % (C2.x, C2.y)
    elif level == '2':
        C1 = curve.add(M, curve.multiply(K, r[0] + r[1]))
        C2 = curve.multiply(G, r[0] + r[1])
        check_encrypt(curve, C1, C2, k, key)
        print 'Your key ciphertext : '
        print 'C1 = (0x%x, 0x%x)' % (C1.x, C1.y)
        print 'C2 = (0x%x, 0x%x)' % (C2.x, C2.y)
    elif level == '3':
        C1 = curve.add(M, curve.multiply(K, r[0] + r[1] + r[2]))
        C2 = curve.multiply(G, r[0] + r[1] + r[2])
        check_encrypt(curve, C1, C2, k, key)
        print 'Your key ciphertext : '
        print 'C1 = (0x%x, 0x%x)' % (C1.x, C1.y)
        print 'C2 = (0x%x, 0x%x)' % (C2.x, C2.y)
    else:
        print 'Bye bye'

def welcom():
    signal.alarm(5)
    print r"""
    _    ______     ___    _   _  ____ _____ ____    _____ ____ ____ 
   / \  |  _ \ \   / / \  | \ | |/ ___| ____|  _ \  | ____/ ___/ ___|
  / _ \ | | | \ \ / / _ \ |  \| | |   |  _| | | | | |  _|| |  | |    
 / ___ \| |_| |\ V / ___ \| |\  | |___| |___| |_| | | |__| |__| |___ 
/_/   \_\____/  \_/_/   \_\_| \_|\____|_____|____/  |_____\____\____|
"""

## The main method          
def main(argv=None):
    welcom()
    # parameters of elliptic curve y^2 = x^3 + ax + b  
    a = 0
    b = 7
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

    # base point
    G = Point(
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)

    # elliptic curve over Fp
    curve = ECurve(a, b, p)

    M, k, r = eval(open('./args', 'r').read())
    M = Point(M[0], M[1])
    flag = int(open('./flag', 'r').read().encode('hex'), 16)

    assert(abs(r[0] - r[1]) <= (1 << 20))
    assert(abs(r[0] - r[2]) <= (1 << 20))
    assert(abs(r[1] - r[2]) <= (1 << 20))
    advanced_encrypt(curve, M, r, k, G, flag)

if __name__ == "__main__":
    main()
    