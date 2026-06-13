---
name: yara_generator
description: Automatically generates a YARA rule based on unique strings or byte patterns extracted from the analyzed binary.
version: 1.0.0
metadata:
  hermes:
    tags: [reversing, yara, threat-hunting, signatures]
    category: re
---
# YARA Rule Generator Skill

## When to Use
Use this skill when you have identified the core logic, unique strings, or custom encryption keys of a malware sample and the user wants to hunt for similar variants.
Trigger: user says "make a yara rule", "generate signature", or "write a rule for this".

## Procedure
1. Review the unique artifacts gathered during the `ghidra_triage` phase:
   - Unique strings (e.g., custom user agents, PDB paths, typo'd error messages).
   - Specific byte patterns (e.g., the exact hex bytes of the custom XOR decryption loop).
   - The VirusTotal findings (malware family name).
2. Construct a valid YARA rule using these indicators.

## YARA Rule Template
Use the following format for the rule:
```yara
rule <Malware_Family_Name> {
    meta:
        description = "Detects <Malware_Family_Name> based on custom decryption loop and strings"
        author = "revcon"
        date = "<CURRENT_DATE>"
        hash = "<SHA256_HASH_IF_KNOWN>"
    
    strings:
        // Use ascii or wide strings
        $s1 = "<UNIQUE_STRING_1>" ascii
        $s2 = "<UNIQUE_STRING_2>" wide
        
        // Hex bytes of unique functions (e.g., decryption loop)
        $hex1 = { <HEX_PATTERN> } 
        // Example: { 8b 45 ?? 33 c1 89 45 ?? } 

    condition:
        uint16(0) == 0x5a4d and // PE File signature
        (all of ($s*) or $hex1)
}
```

## Reporting Format
Present the generated YARA rule in a code block. Explain why you chose those specific strings/byte sequences as indicators.
