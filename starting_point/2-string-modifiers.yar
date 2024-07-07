rule STRING_MODIFIERES {
    strings:
        $a = "HELLo" nocase // No case means the the check for this string will be case insensitive
        $b = "good morning" ascii wide // ascii is a modifier means that the string will only be checked against ascii characters, it is the default behavior and there is no need to specifically use it alone without the wide modifier
        // wide modifier emulates UTF16 by interleaving null (0x00) characters
        $c = "good night" xor // Checks the string against XOR 256 keys
        $d = "base64" base64 // Converts to 3 formats of base64 and checks that
        $e = "the wide base64" base64wide // Same as base64 but then interleaving null characters like the wide modifier
        $f = "fullword" fullword // Only matches if the word is not preceded or followed by an alphanumeric character
        $g = "private" private // The match is not included in the output
    
    condition:
        any of them
}

/*
*Not all modifiers can be used together, you can check the restrictions here: https://yara.readthedocs.io/en/latest/writingrules.html#string-modifier-summary
*/