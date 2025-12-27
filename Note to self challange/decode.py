import binascii
import base64

# 1. Decode hex string
hex_string = "79 6F 75 20 6A 75 73 74 20 67 6F 74 20 72 69 63 6B 20 72 6F 6C 6C 65 64"
hex_decoded = binascii.unhexlify(hex_string.replace(" ", ""))
print(f"Hex decoded: {hex_decoded.decode()}")

# 2. Decode base64 concatenation
base64_parts = [
    "TllQe3RoZV9hbn",
    "N3ZXJfaXNfaW5fdG",
    "hpc19maWxlfQ=="
]
base64_string = "".join(base64_parts)
print(f"Base64 decoded: {base64.b64decode(base64_string).decode()}")

# 3. Decode S/T/L pattern 
pattern_lines = """S S S T	S S T	T	T	S L
T	L
S S S S S T	S T	T	S S T	L
T	L
S S S S S T	S T	S S S S L
T	L
S S S S S T	T	T	T	S T	T	L
T	L
S S S S S T	T	S S T	S S L
T	L
S S S S S S T	T	S S S T	L
T	L
S S S S S T	T	T	S S T	T	L
T	L
S S S S S T	T	T	S T	S S L
T	L
S S S S S T	T	T	S S T	S L
T	L
S S S S S S T	T	S T	S S L
T	L
S S S S S T	T	S S S T	T	L
T	L
S S S S S T	T	T	S T	S S L
T	L
S S S S S T	T	S T	S S T	L
T	L
S S S S S T	T	S T	T	T	T	L
T	L
S S S S S T	T	S T	T	T	S L
T	L
S S S S S T	T	T	S S T	T	L
T	L
S S S S S T	S T	T	T	T	T	L
T	L
S S S S S T	T	S T	S S S L
T	L
S S S S S T	T	S T	S S T	L
T	L
S S S S S T	T	S S T	S S L
T	L
S S S S S T	T	S S T	S T	L
T	L
S S S S S T	S T	T	T	T	T	L
T	L
S S S S S T	T	T	S T	S S L
T	L
S S S S S T	T	S T	S S S L
T	L
S S S S S T	T	S S T	S T	L
T	L
S S S S S T	S T	T	T	T	T	L
T	L
S S S S S T	T	T	S T	S S L
T	L
S S S S S T	T	T	S S T	S L
T	L
S S S S S T	T	T	S T	S T	L
T	L
S S S S S T	T	T	S T	S S L
T	L
S S S S S T	T	S T	S S S L
T	L
S S S S S T	T	T	T	T	S T	L
T	L
S S L
L
L"""

import binascii
import base64

# Let's look at the actual pattern more carefully
# Each "instruction" is between L markers, containing S's and T's
# The clue says: "Only those who look UP will find the sky"
# Maybe we need to read the pattern differently

pattern_lines = """S S S T	S S T	T	T	S L
T	L
S S S S S T	S T	T	S S T	L
T	L
S S S S S T	S T	S S S S L
T	L
S S S S S T	T	T	T	S T	T	L
T	L
S S S S S T	T	S S T	S S L
T	L
S S S S S S T	T	S S S T	L
T	L
S S S S S T	T	T	S S T	T	L
T	L
S S S S S T	T	T	S T	S S L
T	L
S S S S S T	T	T	S S T	S L
T	L
S S S S S S T	T	S T	S S L
T	L
S S S S S T	T	S S S T	T	L
T	L
S S S S S T	T	T	S T	S S L
T	L
S S S S S T	T	S T	S S T	L
T	L
S S S S S T	T	S T	T	T	T	L
T	L
S S S S S T	T	S T	T	T	S L
T	L
S S S S S T	T	T	S S T	T	L
T	L
S S S S S T	S T	T	T	T	T	L
T	L
S S S S S T	T	S T	S S S L
T	L
S S S S S T	T	S T	S S T	L
T	L
S S S S S T	T	S S T	S S L
T	L
S S S S S T	T	S S T	S T	L
T	L
S S S S S T	S T	T	T	T	T	L
T	L
S S S S S T	T	T	S T	S S L
T	L
S S S S S T	T	S T	S S S L
T	L
S S S S S T	T	S S T	S T	L
T	L
S S S S S T	S T	T	T	T	T	L
T	L
S S S S S T	T	T	S T	S S L
T	L
S S S S S T	T	T	S S T	S L
T	L
S S S S S T	T	T	S T	S T	L
T	L
S S S S S T	T	T	S T	S S L
T	L
S S S S S T	T	S T	S S S L
T	L
S S S S S T	T	T	T	T	S T	L
T	L
S S L
L
L"""

# Maybe T=1, S=0 in binary positions after the first group of S's
# Let's extract just the S/T after the initial S's and convert to binary

lines = pattern_lines.split("\n")
chars = []

for line in lines:
    if line.strip() and 'L' in line:
        line_clean = line.replace("\t", " ")
        tokens = [t for t in line_clean.split() if t in ['S', 'T', 'L']]
        
        if 'L' in tokens:
            # Remove leading S's (they seem to be a prefix)
            # Find the pattern after the first group
            s_count = 0
            remaining = []
            
            for i, token in enumerate(tokens):
                if token == 'S':
                    s_count += 1
                else:
                    remaining = tokens[i:]
                    break
            
            # Now convert remaining to binary (S=0, T=1)
            if remaining and remaining[-1] == 'L':
                binary_str = ""
                for token in remaining[:-1]:  # Exclude the L
                    if token == 'S':
                        binary_str += '0'
                    elif token == 'T':
                        binary_str += '1'
                
                # Convert binary to character
                if binary_str:
                    char_code = int(binary_str, 2)
                    if 32 <= char_code <= 126:  # Printable ASCII
                        chars.append(chr(char_code))
                        print(f"Binary: {binary_str} = {char_code} = '{chr(char_code)}'")

result = "".join(chars)
print(f"\nDecoded: {result}")
