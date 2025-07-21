Summer Daily Tasks Event: Crypto Puzzle Writeup

the task : 
TASK1 
categorie : CRYPTOGRAPHY
level : EASY          Points:100                                                           
author : mohamed hedda 
Description : i found those files in my friend's laptop , ive been looking to them since yesterday , could u explain me what are those random characters about ?

given files : 

`cipher.hex` file : ff10690eea98b832305e19bb847ae6109fb78e288350c8002bac41bcb4d16d604e66390fa786026efb59f28c435d3a7d68e43b36 

`hash.txt` file : 8618b589892a338061a2f9223429516ce55db39af7f1b9c0241fb153e762fb0e

`enc.py` script : 
```python
# challenge.py

# LCG-based XOR decryption tool

m = 2**31
a = 1103515245
c = 12345

def lcg(seed):
    while True:
        seed = (a * seed + c) % m
        yield seed & 0xFF

def decrypt(cipher_hex, password):
    seed = sum(ord(c) for c in password)
    keystream = lcg(seed)
    cipher = bytes.fromhex(cipher_hex)
    decrypted = bytes([b ^ next(keystream) for b in cipher])
    return decrypted

if __name__ == "__main__":
    with open("cipher.hex", "r") as f:
        cipher_hex = f.read().strip()

    password = input("Enter password: ").strip()
    result = decrypt(cipher_hex, password)
    print("Decrypted:", result.decode(errors="ignore"))

``` 

and finaly a big word liste of passwords named `suspecious.txt` is given ; 

Let’s start analyzing this cryptography challenge . Here’s what we had:

- ``: The encrypted flag, as a hex string.
- ``: A SHA-256 hash of the **password** used to seed the LCG.
- ``: A large wordlist (one password per line).

**Goal:** Recover the flag hidden in `cipher.hex`.

---

## Approach 1: Hashcat + Python Decrypt

1. **Crack the password**

   ```bash
   cd ~/daily
   hashcat -m 1400 hash.txt suspicious.txt -O -o found.txt
   cat found.txt
   # Output:
   # 8618b589892a338061a2f9223429516ce55db39af7f1b9c0241fb153e762fb0e:SpongeBoB
   ```

    Password found: **SpongeBoB**

2. **Decrypt the ciphertext**

   - Create `decrypt.py` with this LCG-XOR logic:
     ```python
     m, a, c = 2**31, 1103515245, 12345

     def lcg(seed):
         while True:
             seed = (a*seed + c) % m
             yield seed & 0xFF

     def decrypt(hexstr, pwd):
         ks = lcg(sum(map(ord, pwd)))
         data = bytes.fromhex(hexstr)
         return bytes(b ^ next(ks) for b in data)

     if __name__ == '__main__':
         pwd = 'SpongeBoB'
         cipher = open('cipher.hex').read().strip()
         print(decrypt(cipher, pwd).decode(errors='ignore'))
     ```
   - Run:
     ```bash
     python3 decrypt.py
     ```
   - **Result:**
     ```
     Securinets{H4SH_CR4CK1NG_1S_TH3_B3ST_W4Y_T0_ST4RT!!}
     ```

---

## Approach 2: LCG Seed-Collision Trick
One of the players found an other approach to solve the task be exploiting the weakness of the LCG script ,he spotted that the LCG seed is just the sum of ASCII codes of the password. Different words with the same sum produce the same keystream.

1. **Recover keystream bytes** from the known prefix `Securinets{`:

   ```python
   cipher = bytes.fromhex(open('cipher.hex').read().strip())
   known  = b'Securinets{'
   stream = [c ^ k for c, k in zip(cipher, known)]
   ```

2. **Map ASCII sums to passwords**:

   ```python
   from collections import defaultdict
   sum_map = defaultdict(list)
   for line in open('suspicious.txt'):
       w = line.strip()
       if w:
           sum_map[sum(map(ord, w))].append(w)
   ```

3. **Find collisions** by matching the LCG output to `stream`:

   ```python
   def lcg_bytes(seed, n):
       a, c, m = 1103515245, 12345, 2**31
       x = seed
       for _ in range(n):
           x = (a*x + c) % m
           yield x & 0xFF

   candidates = []
   for s, words in sum_map.items():
       if list(lcg_bytes(s, len(stream))) == stream:
           candidates.extend(words)
   print('Candidates:', candidates)
   ```

   - **Possible passwords:** `['SpongeBoB', 'wishbone', ...]`

4. **Verify** by substituting **wishbone** in `decrypt.py` and rerunning; you get the identical flag.

---

## Final Flag

```
Securinets{H4SH_CR4CK1NG_1S_TH3_B3ST_W4Y_T0_ST4RT!!}
```

**Key Takeaways:**

- Hashcat + decryption is a straightforward method for known hashes.
- Simple LCGs seeded by ASCII sums are prone to collisions.
- Exploring multiple approaches (like Wish’s trick) can save time and uncover hidden shortcuts.

Happy hacking! 

