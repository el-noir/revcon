# Python Scramble Reverse Patterns

## Pattern 1: List Pop-and-Merge with Nested Appends

### Original Code Pattern
```python
def scramble(L):
    A = L
    i = 2
    while i < len(A):
        A[i-2] += A.pop(i-1)      # Merge element i-1 into i-2
        A[i-1].append(A[:i-2])     # Append prefix slice to element at i-1
        i += 1
    return L
```

### Forward Trace (input: ['a','b','c','d','e'])
```
Start: A = [['0x61'], ['0x62'], ['0x63'], ['0x64'], ['0x65']]

i=2: A[0] += A.pop(1)  -> A[0] = ['0x61', '0x62'], A = [A[0], ['0x63'], ['0x64'], ['0x65']]
      A[1].append(A[:0]) -> A[1] = ['0x63', []]
      i=3

i=3: A[1] += A.pop(2)  -> A[1] = ['0x63', [], '0x64'], A = [A[0], A[1], ['0x65']]
      A[2].append(A[:1]) -> A[2] = ['0x65', [A[0]]]
      i=4

i=4: len(A)=3, i=4, loop ends (4 < 3 is False)

Final: [['0x61','0x62'], ['0x63',[],'0x64'], ['0x65',[['0x61','0x62']]]]
```

### Key Insight
The hex strings maintain their original relative order in the final structure! The nested lists and empty lists are just wrappers. To reverse:

```python
def extract_hex_strings(obj):
    result = []
    if isinstance(obj, list):
        for item in obj:
            if isinstance(item, str) and item.startswith('0x'):
                result.append(item)
            elif isinstance(item, list):
                result.extend(extract_hex_strings(item))
    return result

hex_strings = extract_hex_strings(scrambled)
flag = ''.join(chr(int(h, 16)) for h in hex_strings)
```

## Pattern 2: Rolling XOR with Incrementing Key

### Original Code Pattern
```python
def scramble(data):
    key = 0x42
    result = []
    for i, byte in enumerate(data):
        result.append(byte ^ (key + i) & 0xff)
    return result
```

### Reverse
```python
def unscramble(scrambled):
    key = 0x42
    result = []
    for i, byte in enumerate(scrambled):
        result.append(byte ^ (key + i) & 0xff)
    return bytes(result)
```

## Pattern 3: Permutation Shuffle

### Original Code Pattern
```python
def scramble(data):
    A = list(data)
    for i in range(len(A)):
        j = (i * 7 + 3) % len(A)
        A[i], A[j] = A[j], A[i]
    return A
```

### Reverse
Apply the same permutation again (if it's an involution) or compute the inverse permutation:

```python
def unscramble(scrambled):
    A = list(scrambled)
    # Compute inverse permutation
    n = len(A)
    inv = [0] * n
    for i in range(n):
        j = (i * 7 + 3) % n
        inv[j] = i
    
    result = [0] * n
    for i in range(n):
        result[inv[i]] = A[i]
    return result
```

## Pattern 4: Recursive Nested List Builder

### Original Code Pattern
```python
def scramble(L):
    if len(L) <= 1:
        return L
    mid = len(L) // 2
    left = scramble(L[:mid])
    right = scramble(L[mid:])
    return [right, left]
```

### Reverse
Recursively flatten, swapping left and right at each level:

```python
def unscramble(nested):
    if not isinstance(nested, list) or len(nested) != 2:
        return [nested] if not isinstance(nested, list) else nested
    right, left = nested
    return unscramble(left) + unscramble(right)
```
