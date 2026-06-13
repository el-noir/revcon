# Quantum Scrambler Pattern

## Source
Encountered in `quantum_scrambler.py` from picoCTF challenge `verbal-sleep.picoctf.net:50118`.

## The Scramble Algorithm
```python
def scramble(L):
  A = L
  i = 2
  while (i < len(A)):
    A[i-2] += A.pop(i-1)
    A[i-1].append(A[:i-2])
    i += 1
  return L
```

## Key Observations

1. **A = L is a reference, not a copy** — the function mutates the input list in place.

2. **A[i-2] += A.pop(i-1)** — pops the element at index `i-1` and extends `A[i-2]` with it. Since elements are lists like `['0x70']`, this concatenates them: `['0x70'] + ['0x69'] = ['0x70', '0x69']`.

3. **A[i-1].append(A[:i-2])** — appends a slice of the entire list (all elements before `i-2`) to the element now at position `i-1`. This creates deep nesting with back-references to earlier parts of the structure.

4. **Original byte order is preserved** — the hex strings appear in the final structure in their original order, just wrapped in nested lists. This is because:
   - Elements are only ever moved forward (popped from higher indices and appended to lower indices)
   - No element ever jumps past another element in the final ordering
   - The DFS pre-order traversal of the final structure yields the original sequence

## Trace with 5-char input `['a','b','c','d','e']`

Start: `[['0x61'], ['0x62'], ['0x63'], ['0x64'], ['0x65']]`

### i=2:
- `A[0] += A.pop(1)` → `A[0] = ['0x61', '0x62']`
- `A = [['0x61','0x62'], ['0x63'], ['0x64'], ['0x65']]`
- `A[1].append(A[:0])` → `A[1] = ['0x63', []]`
- `A = [['0x61','0x62'], ['0x63',[]], ['0x64'], ['0x65']]`

### i=3:
- `A[1] += A.pop(2)` → `A[1] = ['0x63', [], '0x64']`
- `A = [['0x61','0x62'], ['0x63',[],'0x64'], ['0x65']]`
- `A[2].append(A[:1])` → `A[2] = ['0x65', [['0x61','0x62']]]`
- `A = [['0x61','0x62'], ['0x63',[],'0x64'], ['0x65',[['0x61','0x62']]]]`

### i=4:
- `len(A) = 3`, `i = 4`, loop ends.

## Reverse Algorithm

```python
import ast

def reverse_scramble(output_string):
    scrambled = ast.literal_eval(output_string.strip())
    
    hex_strings = []
    
    def extract_in_order(obj):
        if isinstance(obj, list):
            for item in obj:
                if isinstance(item, str) and item.startswith('0x'):
                    hex_strings.append(item)
                elif isinstance(item, list):
                    extract_in_order(item)
    
    extract_in_order(scrambled)
    flag = ''.join(chr(int(h, 16)) for h in hex_strings)
    return flag
```

## Why This Works

The scramble only ever:
1. Concatenates adjacent elements (preserving order within the concatenation)
2. Appends references to earlier parts of the structure (creating back-links, not reordering)

Because no element ever "jumps over" another in the ordering, a simple DFS pre-order traversal of the final nested structure extracts the original bytes in the correct sequence.

## Verification

To verify the reverse is correct:
1. Forward-scramble a known test string
2. Apply the reverse extraction
3. Confirm the output matches the original input
