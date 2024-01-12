rule unpacked_teslacrypt
{
  strings:
    $shadowcopy = "shadowcopy"
    $delete = "delete"
    $noin = "/noin"
    $teractive = "teractive"
    $recovery = "_RECOVERY_"
    $softwarefolder = "\\S-1-5-18\\Software\\xxxsys\\"
    $xxxsys = "Software\\xxxsys\\"
    $png = "%s\\RECOVERY.png"
    $txt = "%s\\RECOVERY%s"
    $recoveryfile = "%s\\RECOVERY.TXT"
  condition:
    $shadowcopy and
    $delete and
    $noin and
    $teractive and
    $recovery and
    $s-1-5-18 and
    $xxxsys and
    $png and
    $txt and
    $recoveryfile
}
