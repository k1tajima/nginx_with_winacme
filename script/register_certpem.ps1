# Register Certificate Pem File to nginx_ssl_cert.conf
# %1 : CommonName(FQDN)
# %2 : Certificate Store Path
# See https://github.com/PKISharp/win-acme/wiki/Install-script
Param (
    [Parameter(Mandatory=$true,Position=0)][string] $CommonName,
    [Parameter(Mandatory=$true,Position=1)][string] $CertStorePath
)

$certFullChainName    = "${CommonName}-chain.pem"
$certPrivateKeyName   = "${CommonName}-key.pem"
$nginxSslCertConfPath = Join-Path ${CertStorePath} "nginx_ssl_cert.conf"

# Store certificate to certificate store path.
Write-Host "Store Certificate by ${PSCommandPath}"
Write-Host "CommonName    = ${CommonName}"
Write-Host "CertStorePath = ${CertStorePath}"

Write-Output @"
# DO NOT EDIT THIS FILE.
# This file will be generated by storepem.cmd when renew certificate.
ssl_certificate     `"$(Join-Path ${CertStorePath} ${certFullChainName})`";
ssl_certificate_key `"$(Join-Path ${CertStorePath} ${certPrivateKeyName})`";
"@ | Out-File -Encoding ascii ${nginxSslCertConfPath}

# Restart Nginx
# See https://nssm.cc/usage
nssm stop nginx 2> $null
nssm start nginx