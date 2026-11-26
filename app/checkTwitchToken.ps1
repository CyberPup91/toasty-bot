# 1. Prompt securely for the token
$SecureToken = Read-Host -Prompt "Enter Twitch OAuth Token (paste without 'oauth:')" -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureToken)
$Token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

# Clean up token if 'oauth:' was accidentally included
$Token = $Token -replace '^oauth:', ''

if ([string]::IsNullOrWhiteSpace($Token)) {
    Write-Host "No token entered. Exiting." -ForegroundColor Red
    exit
}

# 2. Call Twitch Validation Endpoint
$Uri = "https://id.twitch.tv/oauth2/validate"
$Headers = @{
    "Authorization" = "OAuth $Token"
}

try {
    Write-Host "`nValidating token with Twitch..." -ForegroundColor Cyan
    $Response = Invoke-RestMethod -Uri $Uri -Method Get -Headers $Headers

    # 3. Output Formatted Info
    Write-Host "`n================ TOKEN INFO ================" -ForegroundColor Green
    Write-Host "User Login : " -NoNewline; Write-Host $Response.login -ForegroundColor Yellow
    Write-Host "User ID    : " -NoNewline; Write-Host $Response.user_id -ForegroundColor Yellow
    Write-Host "Client ID  : " -NoNewline; Write-Host $Response.client_id -ForegroundColor Yellow

    $ExpiresInMinutes = [math]::Round($Response.expires_in / 60, 2)
    Write-Host "Expires In : " -NoNewline; Write-Host "$($Response.expires_in) seconds (~$ExpiresInMinutes minutes)" -ForegroundColor Yellow

    Write-Host "`nGranted Scopes:" -ForegroundColor Green
    if ($Response.scopes.Count -gt 0) {
        foreach ($scope in $Response.scopes) {
            Write-Host "  - $scope" -ForegroundColor White
        }
    } else {
        Write-Host "  (None / Basic Read Only)" -ForegroundColor DarkGray
    }
    Write-Host "============================================`n" -ForegroundColor Green

} catch {
    Write-Host "`n[ERROR] Token validation failed!" -ForegroundColor Red
    if ($_.Exception.Response) {
        $StatusCode =$_.Exception.Response.StatusCode.value__
        Write-Host "HTTP Status: $StatusCode" -ForegroundColor Red
        Write-Host "Reason: Invalid or expired token." -ForegroundColor Red
    } else {
        Write-Host $_.Exception.Message -ForegroundColor Red
    }
}
