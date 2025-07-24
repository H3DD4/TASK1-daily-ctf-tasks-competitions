## Write-up: *big\_smoke\_traitor* Challenge

This write-up details the steps to solve the `_big_smoke_traitor_` challenge, which consisted of two files :

```
_big_smoke_traitor_.dat  cj
```

### 1. Initial Reconnaissance

1. **Check file types:**
   ```bash
   file _big_smoke_traitor_.dat
   # Output: data

   file cj
   # Output: ELF 64-bit LSB PIE executable, stripped
   ```
2. The `cj` binary appeared to be a stripped ELF (reverse engineering target). The `.dat` file was likely encrypted or corrupted data that we should recover.

### 2. Inspecting the ELF (`cj`)

#### 2.1 Strings
soo in initial investigations i chekced strings at this elf file , maybe we could find a interresting constant or some valuable .rodata 
Running `strings cj` revealed:

```
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
PTE1
u+UH
Ryder
What does CJ miss the most?
b13s5v3_r10v_17mgr7n3g3ss_
yeah,, indeed!!
bullshit!!
;*3$"
GCC: (Debian 14.2.0-19) 14.2.0
.shstrtab
```

The prompt and the weird constant `b13s5v3_r10v_17mgr7n3g3ss_` hinted at an input check,is seemed to be worthless because it made no sense, thats way we should look for the source code to understand what were facing .

#### 2.2 Decompilation

I used an online decompiler (since the binary was small) and obtained the following key excerpts (check the online_decompiler.png):

```c
// Rolling-hash on "Ryder" to get seed:
unsigned int sub_401240() {
    char *s = "Ryder";
    unsigned int h = 0;
    for (unsigned int i = 0; i < strlen(s); i++) {
        h = s[i] + h * 31;
    }
    return h;
}

// Fisher–Yates shuffle using srand(seed) and rand():
void sub_4011a9(char *buf, unsigned int len, unsigned int seed) {
    if (!buf || len == 0) return;
    srand(seed);
    for (unsigned int i = len - 1; i > 0; i--) {
        unsigned int r = rand();
        unsigned int j = r % (i + 1);
        char tmp = buf[i]; buf[i] = buf[j]; buf[j] = tmp;
    }
}

int main() {
    unsigned int seed = sub_401240();
    puts("What does CJ miss the most?");
    char input[255];
    if (!fgets(input, 0x100, stdin)) return 1;
    input[strcspn(input, "\r\n")] = 0;
    sub_4011a9(input, strlen(input), seed);
    if (!strcmp(input, "b13s5v3_r10v_17mgr7n3g3ss_"))
        puts("yeah,, indeed!!");
    else
        puts("bullshit!!");
    return 0;
}
```

This code:

1. Computes a 32-bit seed from the string "Ryder".
2. Reads user input, shuffles its bytes with `srand(seed)` + `rand()` Fisher–Yates.
3. Compares the shuffled buffer against the constant `"b13s5v3_r10v_17mgr7n3g3ss_"`.

### 3. Solver to Recover the Original Input

We need to reverse the shuffle: record swap indices then invert them. Here’s a Python solver:

```python
#!/usr/bin/env python3
import ctypes

def get_seed(s: str) -> int:
    h = 0
    for c in s:
        h = (ord(c) + h * 31) & 0xFFFFFFFF
    return h

def shuffle_indices(n: int, seed: int):
    libc = ctypes.CDLL("libc.so.6")
    libc.srand(ctypes.c_uint(seed))
    swaps = []
    for i in range(n-1, 0, -1):
        r = libc.rand()
        j = r % (i+1)
        swaps.append((i, j))
    return swaps

def unshuffle(target: str, swaps: list) -> str:
    lst = list(target)
    for i, j in reversed(swaps):
        lst[i], lst[j] = lst[j], lst[i]
    return ''.join(lst)

seed = get_seed("Ryder")
target = "b13s5v3_r10v_17mgr7n3g3ss_"
swaps = shuffle_indices(len(target), seed)
original = unshuffle(target, swaps)
print("Recovered key:", original)
```

After running, we get:

```
Recovered key: m1ss1ng_gr0v3_57r337_v1b3s
```



### 4. Decrypting the Data File

after obtaining a key , i remembered about the `.dat` file so i started thinkin about ways to use this key in the recover and the first idea i though about is that the file was likely XORed with this key, so i tried a simple XOR:

```bash
cat << 'EOF' > xor_decrypt.py
#!/usr/bin/env python3
import sys

def xor_file(in_path, out_path, key):
    k = key.encode()
    klen = len(k)
    i = 0
    with open(in_path, 'rb') as fin, open(out_path, 'wb') as fout:
        while chunk := fin.read(4096):
            out = bytearray(len(chunk))
            for idx, byte in enumerate(chunk):
                out[idx] = byte ^ k[i % klen]
                i += 1
            fout.write(out)

if __name__ == '__main__':
    xor_file('_big_smoke_traitor_.dat', '_big_smoke_traitor_decrypted.png', 'm1ss1ng_gr0v3_57r337_v1b3s')
EOF
chmod +x xor_decrypt.py
./xor_decrypt.py
```

This produces a valid PNG:

```
file _big_smoke_traitor_decrypted.png
# PNG image data, 3840 x 2160, 8-bit/color RGB, non-interlaced 
```

so were succesfully found a png file , and the flag was right in this picture ( open the flag.png file)

