'''
i = 0

a1 = 'h'
a1 = chr(ord(a1) ^ (i * -110 * i + i * i * -107 * i + 22 * i + 14))
print a1

a1 = -61
a1 = chr(a1 ^ (i * -98 * i + i * i * 104 * i + 86 * i - 73))
print a1

a1 = -85
a1 = chr(a1 ^ (i * 81 * i + i * i * -24 * i - 124 * i - 26))
print a1

a1 = 81;
a1 = chr(a1 ^ (i * -11 * i + i * i * 104 * i + 59 * i + 102))
print a1

a1 = '1'
a1 = chr(ord(a1) ^ (0 * 94 * 0 + 0 * 0 * 116 * 0 - 17 * 0 + 8))
print a1

a1 = 25
a1 = chr(a1 ^ (i * 3 * i + i * i * 38 * i + 119 * i + 114))
print a1

a1 = 114
a1 ^= i * 100 * i + i * i * 109 * i - 81 * i + 17
print chr(a1)

a1 = 70
a1 ^= (i * 45 * i + i * i * -120 * i - 52 * i + 45)
print chr(a1)

i = 1
a1 = -42
a1 ^= (i * 45 * i + i * i * -120 * i - 52 * i + 45)
print chr(a1)


root
{kx 1}  {c 0}
	{7 1}  {t 1}
	{M  2} {9 1} {f 1}
	{k 1}

M->k
t->9
7->M
t->f
c->7
c->t

kx
c7
ct
c7M
c7M
c7Mk
ct9
ctf

flag_0: flag[19]flag[20]flag[21] c7M

flag_1: flag[4]flag[5]flag[6] c7M

flag_2: flag[0]flag[1]   c7

flag_3: flag[13]flag[14]flag[15]  ctf

flag_4: flag[9]flag[10]flag[11]flag[12] c7Mk

flag_5: flag[2]flag[3]  ct

flag_6: flag[7]flag[8]   kx

flag_7: flag[16]flag[17]flag[18]  ct9

flag = c7ctc7Mkxc7Mkctfct9c7M
'''

'''
  if ( (a1[1] ^ *a1) != 84
    || (a2[1] ^ *a2) != 19
    || (*(char *)(a3 + 1) ^ *(char *)(a3 + 2)) != 18
    || (*(char *)(a4 + 2) ^ *(char *)(a4 + 1)) != 77 )

sub_401B80(char *a1, char *a2, int a3, int a4, int a5, int a6)
sub_401B80(&flag_2, &flag_6, (int)&flag_3, (int)&flag_7, a2, a3);
'''

'''
flag_2 = 'c7'
print ord(flag_2[1]) ^ ord(flag_2[0])

flag_6 = 'kx'
print ord(flag_6[1]) ^ ord(flag_6[0])

flag_3 = 'ctf'
print ord(flag_3[1]) ^ ord(flag_3[2])

flag_7 = 'ct9'
print ord(flag_7[2]) ^ ord(flag_7[1])
'''