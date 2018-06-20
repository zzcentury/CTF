str = '437261636b4d654a757374466f7246756e00'
c = ''
for i in str:
	if len(c) == 2:
		print chr(int(c,16)),
		c = ''
		c += i
	else:
		c += i