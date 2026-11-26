$SecureToken = Read-Host -Prompt "Enter User Access Token" -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureToken)
$Token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
$Token = $Token -replace '^oauth:', ''

$Uri = "https://id.twitch.tv/oauth2/validate"
$Headers = @{ "Authorization" = "OAuth $Token" }

try {
    $Response = Invoke-RestMethod -Uri $Uri -Method Get -Headers $Headers
    Write-Host "`nToken belongs to User: " -NoNewline; Write-Host $Response.login -ForegroundColor Yellow
    Write-Host "User ID               : " -NoNewline; Write-Host $Response.user_id -ForegroundColor Yellow
    Write-Host "Client ID             : " -NoNewline; Write-Host $Response.client_id -ForegroundColor Yellow
} catch {
    Write-Host "Validation failed. Token may be invalid or expired." -ForegroundColor Red
}
