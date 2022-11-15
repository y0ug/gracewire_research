import "pe"

rule gracewire_rsrc_names
{
    condition:
        pe.number_of_resources >= 1 and    
        for any y in (0..pe.number_of_resources - 1): (
            pe.resources[y].name_string == "XC\x00\x00\x00")
}

rule gracewire_vfs_header 
{
    strings:
        $magic =  { c4 9d f4 e6 03 00 00 00 }
    condition:
        $magic
}

rule gracewire_packer_01
{
    strings:
        $name = "c.dll"
        $ldrloaddll = { C6 44 ?? ?? 4C
                        C6 44 ?? ?? 64 
                        C6 44 ?? ?? 72 
                        C6 44 ?? ?? 4c 
                        C6 44 ?? ?? 6f 
                        C6 44 ?? ?? 61 
                        C6 44 ?? ?? 64 
                        C6 44 ?? ?? 44 
                        C6 44 ?? ?? 6c 
                        C6 44 ?? ?? 6c }
        
    condition:
        $name and $ldrloaddll

}

// content:"f93j5RFRjhf2ASfy" or content:"er0ewjflk3qrhj81" or content:"c3oeCSIfx0J6UtcV" or content:"kwREgu73245Nwg7842h" or content:{12 20 A5 16 76 E7 79 BD 87 7C BE CA C4 B9 B8 69 6D 1A 93 F3 2B 74 3A 3E 67 90 E4 0D 74 56 93 DE 58 B1 DD 17 F6 59 88 BE FE 1D 6C 62 D5 41 6B 25 BB 78 EF 06 22 B5 F8 21 4C 6B 34 E8 07 BA F9 AA }
rule gracewire_keys
{
    strings:
        $k1 = "f93j5RFRjhf2ASfy"
        $k2 = "er0ewjflk3qrhj81"
        $k3 = "c3oeCSIfx0J6UtcV"
        $k4 = "kwREgu73245Nwg7842h"
        $k5 = "1220A51676E779BD877CBECAC4B9B8696D1A93F32B743A3E6790E40D745693DE58B1DD17F65988BEFE1D6C62D5416B25BB78EF0622B5F8214C6B34E807BAF9AA"
        $k6 = {12 20 A5 16 76 E7 79 BD 87 7C BE CA C4 B9 B8 69 6D 1A 93 F3 2B 74 3A 3E 67 90 E4 0D 74 56 93 DE 58 B1 DD 17 F6 59 88 BE FE 1D 6C 62 D5 41 6B 25 BB 78 EF 06 22 B5 F8 21 4C 6B 34 E8 07 BA F9 AA }
    condition:
        any of them
}
