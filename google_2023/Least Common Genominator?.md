# Least Common Genominator?
>"Someone used this program to send me an encrypted message but I can't read it! It uses something called an LCG, do you know what it is? I dumped the first six consecutive values generated from it but what do I do with it?!"

For this challange your given 4 files:
 - a python script: generate.py
 - a public key pem file
 - a dump of 6 values (refrenced in the subtext)
 - the the encrypted flag

Here is the python file:
```python
from secret import config
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, isPrime

class LCG:
    lcg_m = config.m
    lcg_c = config.c
    lcg_n = config.n

    def __init__(self, lcg_s):
        self.state = lcg_s

    def next(self):
        self.state = (self.state * self.lcg_m + self.lcg_c) % self.lcg_n
        return self.state

if __name__ == '__main__':

    assert 4096 % config.it == 0
    assert config.it == 8
    assert 4096 % config.bits == 0
    assert config.bits == 512

    # Find prime value of specified bits a specified amount of times
    seed = 211286818345627549183608678726370412218029639873054513839005340650674982169404937862395980568550063504804783328450267566224937880641772833325018028629959635
    lcg = LCG(seed)
    primes_arr = []

    dump = True
    items = 0
    dump_file = open("dump.txt", "w")

    primes_n = 1
    while True:
        for i in range(config.it):
            while True:
                prime_candidate = lcg.next()
                if dump:
                    dump_file.write(str(prime_candidate) + '\n')
                    items += 1
                    if items == 6:
                        dump = False
                        dump_file.close()
                if not isPrime(prime_candidate):
                    continue
                elif prime_candidate.bit_length() != config.bits:
                    continue
                else:
                    primes_n *= prime_candidate
                    primes_arr.append(prime_candidate)
                    break

        # Check bit length
        if primes_n.bit_length() > 4096:
            print("bit length", primes_n.bit_length())
            primes_arr.clear()
            primes_n = 1
            continue
        else:
            break

    # Create public key 'n'
    n = 1
    for j in primes_arr:
        n *= j
    print("[+] Public Key: ", n)
    print("[+] size: ", n.bit_length(), "bits")

    # Calculate totient 'Phi(n)'
    phi = 1
    for k in primes_arr:
        phi *= (k - 1)

    # Calculate private key 'd'
    d = pow(config.e, -1, phi)

    # Generate Flag
    assert config.flag.startswith(b"CTF{")
    assert config.flag.endswith(b"}")
    enc_flag = bytes_to_long(config.flag)
    assert enc_flag < n

    # Encrypt Flag
    _enc = pow(enc_flag, config.e, n)

    with open ("flag.txt", "wb") as flag_file:
        flag_file.write(_enc.to_bytes(n.bit_length(), "little"))

    # Export RSA Key
    rsa = RSA.construct((n, config.e))
    with open ("public.pem", "w") as pub_file:
        pub_file.write(rsa.exportKey().decode())
```

Working from the bottom up, we see that the the script encrypts the flag using rsa encryption. Looking futher up we see that the original primes used to generate phi are themselves generated with some algorithm using an 'LCG', and e is taken from the secret.config package that we are not given. Though we can recover it from the public.pem (as n and e of the RSA equation make up the public key) by doing:
```python
key = RSA.importKey(open('public.pem', 'r').read())
e = key.e
```
Now we want to extract d (the private key). For this we need to reverse engeneir the erlier algorithm and find m, c and n of the config package. Convinently the first 6 outputs of the lcg are given. LCG's work by a reccurance realation of:
$s_{n+1} = s_n * m + c \mod n$
with some $s_0 < n$ to find n we can use a method described [here](https://security.stackexchange.com/questions/4268/cracking-a-linear-congruential-generator) to recover m with high accuracy

```python 
s =[2166771675595184069339107365908377157701164485820981409993925279512199123418374034275465590004848135946671454084220731645099286746251308323653144363063385,
6729272950467625456298454678219613090467254824679318993052294587570153424935267364971827277137521929202783621553421958533761123653824135472378133765236115,
2230396903302352921484704122705539403201050490164649102182798059926343096511158288867301614648471516723052092761312105117735046752506523136197227936190287,
4578847787736143756850823407168519112175260092601476810539830792656568747136604250146858111418705054138266193348169239751046779010474924367072989895377792,
7578332979479086546637469036948482551151240099803812235949997147892871097982293017256475189504447955147399405791875395450814297264039908361472603256921612,
2550420443270381003007873520763042837493244197616666667768397146110589301602119884836605418664463550865399026934848289084292975494312467018767881691302197]
def t(n, s):
    return s[n+1] - s[n]
def u(n, s):
    return abs(t(n+2,s)*(t(n,s)) - t(n+1, s)**2)
us = []
for i in range(3):
    us.append(u(i, s))
n = math.gcd(us[0], us[1], us[2]) 
```
this gives us n = 8311271273016946265169120092240227882013893131681882078655426814178920681968884651437107918874328518499850252591810409558783335118823692585959490215446923
> note that this value for n isnt neccacerily actually n, just some multiple of n, though the chances of it not being n are very low and checking with the sequence, our n seems to be correct

Now that we have n all we have to do is some arithmetic to get
our c and m. As we have $s_0, s_1, s_2$ we can make 2 simultaneus equations
$$\begin{cases}
    ms_0 + c = s_1 \mod n \\
    ms_1 + c = s_2 \mod n
\end{cases}$$
subtracting the first from the second we get $(s_1 - s_0)m = s_2 - s_1 \mod n$ from this we can just multiply the multiplicative inverse of $(s_1 - s_0)$ mod n on both sides to get m
```python 
m = (((s[2] - s[1]))* pow(s[1]-s[0], -1, n))% n
```
then once we have m gettign c is just an act of subbing it back in the equation
```python
c = s[1] - m*s[0] % n
```
Looking throught the code we also can get the number of primes and thier bit length as they are asserted to be true

```python
assert 4096 % config.it == 0
assert config.it == 8
assert 4096 % config.bits == 0
assert config.bits == 512
```

With that we can edit the code, substituting the variables we found. 

```python
n = math.gcd(us[0], us[1], us[2]) ##tis the modulus
m = (((s[2] - s[1]))* pow(s[1]-s[0], -1, n))% n ##tis the multiplier
c = s[1] - m*s[0] % n

print(m, a, c)
key = RSA.importKey(open('public.pem', 'r').read())
e = key.e

class LCG:
    lcg_m = m
    lcg_c = c
    lcg_n = n
#  ..... skipping unchanged code
if __name__ == '__main__':
    it =  8
    bits = 512
    assert 4096 % it == 0
    assert it == 8
    assert 4096 % bits == 0
    assert bits == 512
```
Now that we will have a value for d when the program is run, all we need to do is apply it to the flag; to do this we load the flag (converting it form little to an intger) raise it to the power of d mod n wich will give us our flag as an integer (due to the property of $c^d = (M^e)^d = M \mod n$, c being the encrypted message, M being decrypted) that we then convert to bytes

```python 
file = open("flag.txt", 'rb')
flag = int.from_bytes(file.read(), "little")
decrypted = pow(flag, d, n)
print(Crypto.Util.number.long_to_bytes(decrypted))
```
aaaand we get our flag output

b'CTF{C0nGr@tz_RiV35t_5h4MiR_nD_Ad13MaN_W0ulD_b_h@pPy}'
