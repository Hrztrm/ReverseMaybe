# Powershell Flags

## Encoded
Short Flag: -e
Usage: powershell -e <Base64 string>
Analysis:
Using Cyberchef
1. Copy paste the Base64 string
2. Use the recipe: Base64 Decode + Decode Text (UTF-16LE(1200))
3. Script Revelead

Using PowerShell
1. Substitute and use the script below
```
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('<Insert The Binary Here>'))
```

# Interesting Functions to look out for

## Powershell Code Execution
Always look out for `IEX` in every format. Used to execute additional Powershell code. 
Often found to be obfuscated in various of ways

```

```

## Loading DLL into Memory
```
[Reflection.Assembly]::Load($hgh2).GetType('R2').GetMethod('Run').Invoke($null,$YOO)
```

## File Execution
```
saps -FilePath $FileName -ArgumentList $Args -WindowStyle Hidden

# Examples
saps -FilePath $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8AXwAvAFwAXwBfAF8ALwA9AD0AXAAvAFwAXwBfAC8APQB9AA=='))) -ArgumentList $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8AXwAvAFwALwA9AFwALwBcAC8APQA9AFwALwA9AFwAXwB9AA=='))) -WindowStyle Hidden

```

## File Write to File System
```
$base64string = "<Insert Super Long File base64 string here>"
$FilePath = "$Env:AppData\qjMzIzFT.zip"
$FileBytes = [System.Convert]::FromBase64String($base64string)
[System.IO.File]::WriteAllBytes($FilePath, $FileBytes)

```

## Run Registry Edit
```
$FilePath = "$Kacnxifj\Qetto-2-Connect.exe"
$RegistryKey = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$RegistryName = "NetUtilityApp"
if (Get-ItemProperty -Path $RegistryKey -Name $RegistryName -ErrorAction SilentlyContinue) {
  Set-ItemProperty -Path $RegistryKey -Name $RegistryName -Value $FilePath
} else {
  New-ItemProperty -Path $RegistryKey -Name $RegistryName -Value $FilePath -PropertyType "String"
}
```

## File Download
```
# Method 1
${web_httpclient} = New-Object System.Net.WebClient
${web_httpclient}.DownloadFile(${str_url}, ${FileName})

# Method 2
iwr https://example.com/file.zip -OutFile "file.zip"
Invoke-WebRequest https://example.com/file.zip -OutFile "file.zip"

```

## Usage of COM object
```
# Example of using COM Object to copy file
$ShellApp = New-Object -ComObject Shell.Application
$sourceFolder = $ShellApp.NameSpace($sourcePath)
$destinationFolder = $ShellApp.NameSpace($destinationPath)
$destinationFolder.CopyHere($sourceFolder.Items(), 4 + 16)
```

## Common Obfuscation
### Replace
```
# Creates an alias GG that will execute 'IEX'
$t0='JOOOOIEX'.replace('JOOOO','');sal GG $t0;
```

### Obscure Variable Names
```
${__/====\/=\__/===} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcABzADoALwAvAG4AbwBkAGUAagBzAC4AbwByAGcALwBkAGkAcwB0AC8AdgAyADIALgAxADEALgAwAC8AbgBvAGQAZQAtAHYAMgAyAC4AMQAxAC4AMAAtAHcAaQBuAC0AeAA2ADQALgB6AGkAcAA=')))
${/===\/==\/=\/\_/\} = [System.IO.Path]::Combine($env:APPDATA, "")
${___/=\__/==\_/\/=} = [System.IO.Path]::Combine($env:TEMP, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABvAHcAbgBsAG8AYQBkAGUAZAAuAHoAaQBwAA=='))))
```
Change the variable name to a more meaningful variable name.
1. Copy the code in a text editor
2. Use the find and replace with feature, while enabling the "Match Whole Word" option or any of its equivalent.
3. Search the variable name and replace it with a meaningful variable name.


### Base64
```
# Basic Use
$a = [Convert]::FromBase64String(<Base64 String or Variable>)

# Assigning Method to variable
$SSD=[system.Convert].GetMethod("FromBase64String")
$hgh=$SSD.Invoke($null,$obj)
```

A whole bunch of other stuff you can read here:
1. [Powershell Obfuscation Bible](https://github.com/t3l3machus/PowerShell-Obfuscation-Bible)
2. [Invoke Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)
