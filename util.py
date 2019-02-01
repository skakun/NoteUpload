from math import log2
def c_entropy(s):
	N=0
	if any( c.isdigit() for c in s):
		N+=10
	if any( c.islower() for c in s):
		N+=26
	if any( c.isupper() for c in s):
		N+=26
	if any( c.isupper() for c in s):
		N+=26
	special_chars=" !\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"
	if any( c in s for c in special_chars):
		N+=33
	if N=0:
		return 0
	return log2(N)*len(s)
