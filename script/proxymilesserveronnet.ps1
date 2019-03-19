powershell -File .\setup_nginx_ssl.ps1 `
    -CommonName proxy.miles.server-on.net `
    -AlternativeNames 'ws-k1t.westus2.cloudapp.azure.com,hyperv.miles.server-on.net' `
    -Email 'k1tajima@mi.to' `
    -NginxRootPath 'C:\nginx' `
    $args