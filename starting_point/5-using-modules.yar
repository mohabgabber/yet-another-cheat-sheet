import "pe"
import "elf"

rule PE_MODULES_EXAMPLE_RULE {
    meta:
        author = "Mohab Gabber"
        description = "Teaches how to use modules in YARA"
        Sha256 = "HASHGOESHERE"
    condition:
        pe.is_pe() // To use the module pe, we have to first import it, at the top of the file. then we can access its functionalities.
        // pe.is_pe() checks if a file is a pe file or not. if so the rule will match successfully.
}

rule ELF_MODULES_EXAMPLE_RULE {
    meta:
        author = "Mohab Gabber"
        description = "Teaches how to use modules in YARA"
        Sha256 = "HASHGOESHERE"
    condition:
        elf.type
        // elf.type Checks the type of file it is scanning, core, executable, no file type, relocatable, or shared object file
}

/*
*There are other modules provided with yara, like the hash module to calculate a file or a portion of it
*And the Console module which prints output to the command line
*Also the elf module to detect linux binaries, etc...
*You can learn more about modules from this link: https://yara.readthedocs.io/en/latest/modules.html
*/