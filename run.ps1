Param(
    [switch] $Cert
)

# Run setup_nginx_ssl.ps1 simply.
& (Join-Path $PSScriptRoot 'script\setup_nginx_ssl.ps1') `
    -CommonName 'www.example.com' `
    -Email 'you@example.com' `
    -Cert:$Cert

# # Run setup_nginx_ssl.ps1 with all options.
# & (Join-Path $PSScriptRoot 'script\setup_nginx_ssl.ps1') `
#     -CommonName 'www.example.com' `
#     -AlternativeNames 'proxy.example.com,app.example.jp' `
#     -Email 'you@example.com' `
#     -CertStorePath 'C:\SSL\cert\win-acme' `
#     -WebRootPath "$env:PUBLIC\html" `
#     -Cert:$Cert
