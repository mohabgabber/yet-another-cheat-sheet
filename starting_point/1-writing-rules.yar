import "pe"
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

//* rules are valid without the meta section
rule NO_STRINGS_RULE {
    strings:
        $a = "hello"
    condition:
        $a
}

//* and without the strings section too
rule NO_META_STRINGS_RULE {
    condition:
        pe.is_pe()
}