import sens
import hashlib
import random


'''
Just fooling around in a futile attempt to guess the NIST elliptic curves seed phrase.
Enjoying myself!
But realizing I am -not- an experienced cracker, surely there are better ways than what I'm playing with here.
'''

def sha1_hash(input_string: str) -> str:
    return hashlib.sha1(input_string.encode()).hexdigest().upper()



with open('hash_seeds.txt', 'r') as file:
    seeking = file.readlines()


#seeking.append('3445D0096EFFD5972610A9E29C8B79A9685C284C') # dev!!!


sufxs = ['', '\n', '\n\n', '.', ' ','  ','   ',  '    ',  '        ',  '..','\'', '-', '\t']


sample_names = ["Jerry", "Solinas", "Jerry Solinas", "Dr Solinas", "Dr. Solinas", "Dr J", "Dr. J", "J Solinas", "J. Solinas", "Jerry S", "Jerry S.", "me", "I", "this guy"]
try_sens = sens.generate_sentences(sample_names)


xx= 0
for s in try_sens:
    print(s)
    for j in sufxs:
        for jj in sufxs:
            for i in range(2455):
                if i == 2454:
                    cnt = ''
                else:
                    cnt = str(i)
                for sc in [s   + j   + jj + cnt ,
                           j   + cnt + s  + jj  ,
                           cnt + s   + j  + jj  ,
                           cnt + j   + s  + jj  ]:
                    hh = sha1_hash(sc)
                    if hh in seeking:
                        print ("\n\nSeed found??!?!!\n\n\n\n", hh, sc)
                        print("\n\n\n")
                        with open('hash_seek_out.txt', 'a') as file:
                            file.write("\n\Seed found??\n")
                            file.write(sc)
                            file.write("\n")
                            file.write(hh)                        
                            quit()
                    xx += 1
                    if xx%13001 == 0:
                        print(sc)
                        if xx%10 == 0:
                            print(hh)
