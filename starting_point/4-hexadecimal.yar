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
