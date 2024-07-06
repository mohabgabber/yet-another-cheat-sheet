import "pe" //* We have to import the module so that we can use it
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


rule REGULAR_EXPRESSION_EXAMPLE_RULE {
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

rule HEXADECIMAL_EXAMPLE_RULE {
    meta: 
        author = "Mohab Gabber"
        description = "Teaches Hexadecimal in YARA"
        Sha256 = "HASHGOESHERE"
    strings:
        $h1 = { A1 B2 EE F0 } // To write hexadecimal in yara, you have to write it between curly brackets {}
        $h2 = { A? CC ?? D5 } // the question mark "?" is a wildcard for a nibble (half a byte) so this "??" means any byte can be here, and this "A?" means the nibble A then any half a byte
        $h3 = { A2 (C7 | F3) } // this sequence ( HEX | HEX ) means that this byte can be either. so $h3 can be "A2 C7" or "A2 F3"
        $h4 = { D4 00 [1-3] } // the sequence [1-3] means that in this position there can be 1, 2, or 3 bytes.

    condition:
        any of them
}

/*
*Use hexadecimal in your rules if you have data in the file that can't be represented as ascii or wide.
*/

rule MODULES_EXAMPLE_RULE {
    meta:
        author = "Mohab Gabber"
        description = "Teaches how to use modules in YARA"
        Sha256 = "HASHGOESHERE"
    condition:
        pe.is_pe() // To use the module pe, we have to first import it, at the top of the file. then we can access its functionalities.
        // pe.is_pe() checks if a file is a pe file or not. if so the rule will match successfully.
}

