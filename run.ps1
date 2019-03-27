Param(
    [switch] $Cert
)

& (Join-Path $PSScriptRoot "script\setup_nginx_ssl.ps1") `
    -CommonName www.example.com `
    -Email 'you@example.com' `
    -Cert:$Cert