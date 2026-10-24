rule PE_Executable : filetype
{
    meta:
        description = "Windows PE (MZ header)"
    condition:
        uint16(0) == 0x5A4D and filesize > 64
}

rule ELF_Binary : filetype
{
    meta:
        description = "ELF executable or shared object"
    condition:
        uint32(0) == 0x464C457F
}

rule High_Entropy_Blob : heuristic
{
    meta:
        description = "looks compressed, encrypted or packed"
    strings:
        // archives are high entropy too, don't bother flagging those
        $zip = { 50 4B 03 04 }
        $gz = { 1F 8B 08 }
    condition:
        filesize > 4KB and entropy > 7.5 and not any of them
}
