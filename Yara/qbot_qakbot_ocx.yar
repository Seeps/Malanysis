rule qbot_qakbot_ocx
{
    meta:
        description = "Detects a Qbot/Qakbot PE"
        author = "Deepak Sharma - @rxurien | deepak@coalitioninc.com"
        date = "2023-04-14"

    strings:
        $s1 = "GetProcAddress"
        $s2 = "GetModuleHandle"
        $s3 = "LoadLibrary"
        $s4 = "SetWindowsHookEx"
        $s5 = "VirtualAlloc"
        $s6 = { 30 58 31 66 31 20 32 65 32 34 33 42 33 } // 0X1f1 2e243B3
        $s7 = { 4a 75 6d 70 49 44 28 22 22 2c 22 25 73 22 29 } // JumpID("","%s")
        $s8 = { 49 45 28 41 4c 28 22 25 73 22 2c 34 29 2c 22 41 4c 28 5c 22 25 30 3a 73 5c 22 2c 33 29 22 2c 22 4a 4b 28 5c 22 25 31 3a 73 5c 22 2c 5c 22 25 30 3a 73 5c 22 29 22 29 } // IE(AL("%s",4),"AL(\"%0:s\",3)","JK(\"%1:s\",\"%0:s\")")

    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        all of ($s1, $s2, $s3, $s4, $s5) and
        all of ($s6, $s7, $s8) and
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name == "CODE" or
            pe.sections[i].name == "BSS" or
            pe.sections[i].name == ".idata")
}
