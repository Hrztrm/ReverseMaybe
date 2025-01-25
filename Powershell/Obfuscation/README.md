# Basic

When doing malware analysis, debugging and code execution is always your best friend when facing some sort of obfuscation. Same goes for Powershell

## Deobfuscation through Full Execution
Warning: This step REQUIRES you to do it in an isolated environment.

For this, you can utilize tools such as [PowerDecode]("https://github.com/Malandrone/PowerDecode") to help with the obfuscation.

You can also opt for a more manual dynamic analysis approach by executing the script with specific settings enabled in your environment.
Settings you would to enable for this would be (Enabled through gpedit.msc [Link]("https://docs.nxlog.co/integrate/powershell-activity.html")):
1. Powershell Transcripts
2. Powershell Script block logging

For Powershell Transcripts:
1. Execute the Powershell script
2. Find the logs in "C:\Users\<user\Documents\<DateOfExecution>" folder
3. It will give logs about the executed powershell but in an already deobfuscated format.

For Powershell Script block logging:
1. Execute the powershell
2. Go to Windows Event Logs
3. Go to Microsoft-Windows-PowerShell/Operational
4. Look for event ids 4104, 4105, and 4106
5. It will show logs of executed Powershell commands both obfuscated and the final unobfuscated version.

## Deobfuscation through Partial Execution



## Decryption through Debugging


