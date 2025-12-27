from Crypto.Util.number import bytes_to_long, getPrime

e = 3
p = getPrime(512)
q = getPrime(512)
n = p * q

m = bytes_to_long(b"NYP{REDACTED}")
ct = pow(m, e, n)

print(f"e={hex(e)}")
print(f"ct={hex(ct)}")

# e=0x3
# ct=0x756b45c7f89ef9544e4fa53bce87946c0b17df562cec738e89562e01a9bda7916785b16a3eee9d3b53c060bfa051851d6c4c9d85ee0a2be1e624d632569e7ec65fd48e632e25b71a44f08f8d9f7fa4e7f5833bec9f865
