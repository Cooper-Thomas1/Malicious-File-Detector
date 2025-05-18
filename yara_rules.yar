import "pe"
import "math"

//Author: Cooper

rule detect_suspicious_tlds {
    meta:
        description = "detects files to see if they end with a suspicious tlds"
    strings:
        $tld1 = ".xyz" nocase
        $tld2 = ".top" nocase
        $tld3 = ".pw" nocase
        $tld4 = ".cc" nocase
        $tld5 = ".tk" nocase
    condition:
        any of them
}

rule detect_obfuscated_url {
    meta:
        description = "checks urls to see if they are potentially obfuscated"
    strings:
        $regex_url = /http[s]?:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}\/[a-zA-Z0-9\/%&=\?_\-\.]+/ nocase
    condition:
        $regex_url and (#regex_url > 10)
}

rule detect_potential_ransomware_strings {
    meta:
        description = "detects words that are potentially used in ransomware"
    strings:
        $str1 = "payment" nocase
        $str2 = "decrypt" nocase
        $str3 = "encrypted" nocase
        $str4 = "bitcoin" nocase
    condition:
        any of them
}

rule detect_reconnaissance_command_execution {
    meta:
        description = "Detects commands used for hacker reconnaissance"
    strings:
        $recon_cmds = /tasklist|net\s+time|systeminfo|whoami|nbtstat|net\s+start|qprocess|nslookup|nmap|ping|tracert|arp|route|netstat|ipconfig/
        $nmap_variants = /nmap\s+-[A-Za-z]+/
    condition:
        (filesize < 5KB and (4 of them)) and ($recon_cmds at 1 or $nmap_variants)
}

rule detect_suspicious_command_execution {
    meta:
        description = "detects suspicious command execution"
    strings:
        $cmd_exec = "cmd.exe /c" nocase
        $powershell_exec = "powershell.exe -ExecutionPolicy Bypass" nocase
        $suspicious_api = "CreateProcess" nocase
    condition:
        uint16(0) == 0x5A4D and filesize < 500KB and
        ($cmd_exec or $powershell_exec) and $suspicious_api
}

rule add_user_to_administrators_detection {
    meta:
        description = "checks if someone is trying to add a user account to the local administrators group"
    strings:
        $x1 = /net localgroup administrators [a-zA-Z0-9]{1,16} \/add/ nocase ascii
    condition:
        all of them
}

rule detect_portable_executables {
    meta:
        description = "checks if a file is a PE and details about it associated with malware"
    condition:
        pe.is_pe or
        pe.number_of_sections == 1 or
        pe.exports("CPlApplet") or
        pe.characteristics & pe.DLL
}

rule entropy_check {
    meta:
        description= "calculates the entropy of the .text section of a PE file"
    condition:
        for any section in pe.sections : (
            section.name == ".text" and
            math.entropy(section.raw_data_offset, section.raw_data_size) > 7.5
        )
}


rule yara_engine_master {
    meta:
        author = "Cooper"
        description = "yara engine master rule"
    condition:
        any of (detect_suspicious_tlds, detect_obfuscated_url, detect_potential_ransomware_strings, detect_reconnaissance_command_execution,      detect_suspicious_command_execution, add_user_to_administrators_detection, detect_portable_executables, entropy_check)
}