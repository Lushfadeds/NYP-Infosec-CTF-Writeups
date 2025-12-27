from random import seed , randint
flag = 'NYP{EXAMPLE}'
seed(914)
wheel = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ_{}'
EncryptedFlag =''
for i in flag:
    EncryptedFlag += wheel[(wheel.find(i) + randint(0,len(wheel)-1))%(len(wheel))]
print(EncryptedFlag) #This would print out the encoded EXAMPLE flag.

#EncryptedFlag = OELXFGQPYRI}C}DPKGOCASGPZVNJ
