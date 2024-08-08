import "pe"

rule MAL_TROJAN_SINOWAL {
    meta:
        author = "Mohab Gabber"
        description = "Detect the Torpig Sinowal miniloader"
        thezoourl = "https://github.com/ytisf/theZoo/tree/master/malware/Binaries/Trojan.Sinowal"
        sha256 = "70484a2a2ba530d910ca3f3919b2e128579eda1c4f55248d865412d85ddf15cf"
    strings:
        $a1 = "C:\\TEST\\bar.txt"
        $a2 = "D:\\distr\\config.ini"
        $a3 = "paulaner.exe" wide
        $a4 = "040904E4" wide
        $a5 = "Brau" wide
        $b1 = "Paulaner" wide nocase
        $b3 = "4.0.0012" wide
        
    condition:
        pe.is_pe and
        4 of ($a*) and
        $pdb and 
        any of ($b*)
}