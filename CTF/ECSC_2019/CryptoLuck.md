# Challenge
```
from __future__ import print_function
import string
import random
import hashlib
import sys
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)
def flag():
    print("ECSC{the flag is on the server ;)}"+"\n")
def random_generator(size=10, chars=string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))
nt = 0
while True:
    token = "ECSC" + random_generator(50)
    eprint("Generated token: " + token + "\r\n")
    sha1 = hashlib.sha1(token.encode())
    sha1 = sha1.hexdigest()[0:6]
    print(sha1)
    data = raw_input("Your token is:")
    eprint("Read from client: " + data + "\r\n")
    if not data: break
    check = hashlib.sha1(data.rstrip("\n\r").encode())
    check = check.hexdigest()[0:6]
    if sha1 == check:
        count = count + 1
        eprint(count)
        if (count >= 10):
            flag()
            break

print('EXIT!')
exit()
```

# Crack
# Method: collision attack, brute-force
The program calculates 6 digest of a string sha1 sum then compares it with a user input. We can
get collisions by applying brute force.
```
from __future__ import print_function
import string
import random
import hashlib
import sys
def eprint(*args, **kwargs):
	print(*args, file=sys.stderr, **kwargs)
def random_generator(size=10, chars=string.ascii_lowercase +
string.digits):
	return ''.join(random.choice(chars) for _ in range(size))
check = raw_input("")
check = check.rstrip("\n\r")
while True:
	token = "ECSC" + random_generator(50)
	sha1 = hashlib.sha1(token.encode())
	sha1 = sha1.hexdigest()[0:6]if sha1 == check:
	eprint( token + "\r\n")
	break
exit()
```