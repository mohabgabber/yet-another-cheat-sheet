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
//* you can check more about regular expression in yara from this link: https://yara.readthedocs.io/en/latest/writingrules.html#regular-expressions