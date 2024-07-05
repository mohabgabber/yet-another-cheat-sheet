rule STRUCTURE_OF_RULE {
    meta: // The meta section contains data such as the author name, description, reference, and hash
        author = "Mohab Gabber"
        description = "Just an example of a basic rule"
        sha256 = "hashgoeshere"
    strings: // In the strings section we define the strings we want to look for in the file
        $a = "Example Text" // To define a variable, write "$" then the name of the variable
    condition: // Here you define the conditions that if met then the rule is successful
        any of them // Any of them means if any of the variables in the string section were found then the rule is true
}

/*
*The meta and strings sections are optional, the only required section is the condition
*/

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


rule REGULAR_EXPRESSIOB_EXAMPLE_RULE {
    meta:
        author = "Mohab Gabber"
        description = "Teaches Regular Expression"
        Sha256 = "HASHGOESHERE"
    strings:
        $a = /M[A-Z0-9]{5}/i // Regular expression but with static bytes, "/i" means it's case insensitive
    condition:
        $a
}

/*
*Running regular expressions is resource intensive, try to minimize its usage if possible, or use regular expression but with some static bytes
*/

