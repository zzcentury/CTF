import random
import signal

def str2arr(str):
    return [[[(ord(str[i * 8 + j]) >> k & 1) for k in xrange(8)] for j in xrange(8)] for i in xrange(8)]

def arr2str(arr):
    ret = ''
    for i in xrange(8):
        for j in xrange(8):
            for k in xrange(8):
                ret += chr(arr[i][j][k])
    return ret

def check(x, y, z):
    if x < 0 or x > 7 or y < 0 or y > 7 or z < 0 or z > 7:
        return False
    return True

def light(arr, i, j, k, x, y, z, power):
    if check(i + x, j + y, k + z):
        arr[i + x][j + y][k + z] += power
    if x != 0 and check(i - x, j + y, k + z):
        arr[i - x][j + y][k + z] += power
    if y != 0 and check(i + x, j - y, k + z):
        arr[i + x][j - y][k + z] += power
    if z != 0 and check(i + x, j + y, k - z):
        arr[i + x][j + y][k - z] += power
    if x != 0 and y != 0 and check(i - x, j - y, k + z):
        arr[i - x][j - y][k + z] += power
    if x != 0 and z != 0 and check(i - x, j + y, k - z):
        arr[i - x][j + y][k - z] += power
    if y != 0 and z != 0 and check(i + x, j - y, k - z):
        arr[i + x][j - y][k - z] += power
    if x != 0 and y != 0 and z != 0 and check(i - x, j - y, k - z):
        arr[i - x][j - y][k - z] += power

def encrypt(flag, power):
    ret = [[[0 for _ in xrange(8)] for _ in xrange(8)] for _ in xrange(8)]
    lights = str2arr(flag)
    for i in range(8):
        for j in range(8):
            for k in range(8):
                if lights[i][j][k] == 1:
                    for x in range(power):
                        for y in range(power - x):
                            for z in range(power - x - y):
                                light(ret, i, j, k, x, y, z, power - x - y - z)
    return arr2str(ret)

def welcom():
    signal.alarm(5)
    print r"""
 _____   ____    _       ___    ____   _   _   _____ 
|___ /  |  _ \  | |     |_ _|  / ___| | | | | |_   _|
  |_ \  | | | | | |      | |  | |  _  | |_| |   | |  
 ___) | | |_| | | |___   | |  | |_| | |  _  |   | |  
|____/  |____/  |_____| |___|  \____| |_| |_|   |_| 

We make a 3d scene model with a lot of lights. They can provide lighting for the surrounding space.
For exmaple, the power of lights is p, one of lights is l(x, y, z) and one position is s(x', y', z').
So, the distance between l and s is d = abs(x - x') + abs(y - y') + abs(z - z'), and l can provide for s with

             |  p - d, p > d
lighting  =  |
             |  0    , p <= d

Now, we transform the flag padded randomly to positions of lights, and you may get the flag ciphertext. Have fun!
"""

def main():
    welcom()
    flag = open('./flag', 'r').read()
    assert(len(flag) == 38)
    for _ in range(64 - 38):
        flag += chr(random.randint(0, 255))
    shuffle_flag = ''.join(flag[0::2][i] + flag[-1::-2][i] for i in xrange(32))
    power = 2
    assert(power > 1)
    assert(power < 6)
    cipher = encrypt(shuffle_flag, power)
    print 'Light power is : %d' % power
    print 'Your flag ciphertext is : %s' % cipher.encode('hex')

if __name__ == '__main__':
    main()
