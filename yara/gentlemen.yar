/*
    Bedrock Safeguard Inc. — The Gentlemen Ransomware Detection Rules
    https://github.com/Bedrock-Safeguard/gentlemen-decryptor
*/

rule Gentlemen_Ransomware_Binary
{
    meta:
        author = "Bedrock Safeguard Inc."
        description = "Detects The Gentlemen ransomware binary (Go/Garble)"
        date = "2026-04-20"
        reference = "https://github.com/Bedrock-Safeguard/gentlemen-decryptor"
        tlp = "WHITE"
        severity = "critical"

    strings:
        $footer_marker = "--marker--GENTLEMEN" ascii
        $eph_marker = "--eph--" ascii
        $ransom_note_name = "README-GENTLEMEN" ascii wide
        $tox_id = "88984846080D639C9A4EC394E53BA616D550B2B3AD691942EA2CCD33AA5B9340FD1A8FF40E9A" ascii
        $email = "negotiation_hapvida@proton.me" ascii
        $onion = "tezwsse5czllksjb7cwp65rvnk4oobmzti2znn42i43bjdfd2prqqkad.onion" ascii
        $locker_bg = "LOCKER_BACKGROUND" ascii
        $cynet_check = "Cynet Ransom Protection" ascii
        $gentlemen_bmp = "gentlemen.bmp" ascii
        $chacha_err1 = "chacha20: wrong HChaCha20 key size" ascii
        $chacha_err2 = "chacha20: wrong HChaCha20 nonce size" ascii
        $ecdh_err = "crypto/ecdh: invalid private key size" ascii
        $defender_excl = "Add-MpPreference -ExclusionProcess" ascii
        $prefetch_del = "del /f /q C:\\Windows\\Prefetch\\*.*" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        (
            ($footer_marker and $eph_marker) or
            ($tox_id) or
            ($email and $onion) or
            (3 of ($locker_bg, $cynet_check, $gentlemen_bmp, $defender_excl, $prefetch_del)) or
            ($chacha_err1 and $chacha_err2 and $ecdh_err)
        )
}

rule Gentlemen_Encrypted_File
{
    meta:
        author = "Bedrock Safeguard Inc."
        description = "Detects files encrypted by The Gentlemen ransomware"
        date = "2026-04-20"

    strings:
        $footer = "--marker--GENTLEMEN" ascii
        $eph = "--eph--" ascii
        $fast = "GENTLEMEN--fast--" ascii
        $ultra = "GENTLEMEN--ultra--" ascii
        $super = "GENTLEMEN--super--" ascii

    condition:
        $footer at (filesize - 200..filesize) and
        $eph at (filesize - 300..filesize) and
        any of ($fast, $ultra, $super)
}

rule Gentlemen_Ransom_Note
{
    meta:
        author = "Bedrock Safeguard Inc."
        description = "Detects The Gentlemen ransom note"
        date = "2026-04-20"

    strings:
        $header = "YOUR ID" ascii
        $group = "Gentlemen, your network is under our full control" ascii
        $tox = "Contact us (add via TOX ID)" ascii
        $onion = "tezwsse5czllksjb7cwp65rvnk4oobmzti2znn42i43bjdfd2prqqkad.onion" ascii

    condition:
        filesize < 10KB and
        $header at 33 and
        2 of ($group, $tox, $onion)
}
