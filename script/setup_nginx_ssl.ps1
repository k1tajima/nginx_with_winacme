# Setup Proxy Server with Nginx for Windows.
Param (
    # Common Name for Certificate: ex. "www.example.com"
    [Parameter(Position=0,Mandatory=$true)]
    [string] $CommonName        = "",
    # AlternativeNames, comma delimited: ex. "proxy.example.com,app.example.com"
    [string] $AlternativeNames  = "",
    # Email for registration on letsencrypt ex. "you@example.com"
    [Parameter(Position=1,Mandatory=$true)]
    [string] $Email             = "",
    # Parent Path to install nginx: "C:\tools" as default
    [string] $NginxRootPath     = "C:\tools",
    # Path to store Certificate Pem Files: "C:\SSL\cert\win-acme" as default
    [string] $CertStorePath     = "C:\SSL\cert\win-acme",
    # Challenge Certificate: default is false. It's just for testing
    [switch]$Cert,
    # win-acme v1 Will be discontinued
    [switch]$WinAcme1,
    # win-acme v2 as default
    [switch]$WinAcme2
)

# Check Parameters
if ( $WinAcme2 -eq $WinAcme1 ) {
    # win-acme v2 as default
    $WinAcme2 = $true
    $WinAcme1 = $false
}

# Please check the latest version of win-acme yourself.
# https://github.com/PKISharp/win-acme/releases/
$WinAcmeUrl = "https://github.com/PKISharp/win-acme/releases/download/v2.0.4.227/win-acme.v2.0.4.227.zip"

# Main
function main {
    Write-Host "HostName: $env:COMPUTERNAME"
    Write-Host "CommonName: $CommonName"

    # Check Installed .NET Framework Version.
    # https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed#ps_a
    $DotNetKey = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\' | Get-ItemPropertyValue -Name Release | Sort-Object -Descending | Select-Object -First 1
    $HasInstalledDotNet472 = ($DotNetKey -ge 461814)

    # Install packages first.
    InstallAll -NginxRootPath $NginxRootPath

    if (! $HasInstalledDotNet472) {
        # Need to reboot Windows.
        Write-Host "------------------------------------------"
        Write-Host ".NET Framework 4.7.2 has installed."
        Write-Host "YOU HAVE TO REBOOT WINDOWS TO ACTIVATE IT."
        Write-Host "Then please run this script again."
        Write-Host "------------------------------------------"
        Restart-Computer -Confirm
        exit
    }

    # Get Nginx Path Set(NginxDir, ConfPath, BinPath)
    $NginxPathSet = Get-NginxPaths -installDir $NginxRootPath

    # Setup Firewall.
    SetupFirewall -Nginx $NginxPathSet.BinPath

    # Make cert store folder secure.
    MakeCertStoreFolder -Path $CertStorePath

    # Make dhparam.pem by openssl.
    MakeDhparam -Path $CertStorePath

    # Drive letsencrypt-win-simple by webroot mode.
    LetsencryptCertificate `
        -CommonName $CommonName `
        -AlternativeNames $AlternativeNames `
        -Email $Email `
        -WebRootPath (Join-Path $NginxPathSet.NginxDir "html") `
        -CertStorePath $(if ( $Cert ) { $CertStorePath } else { "" }) `
        -WinAcme2:$WinAcme2

    # Upgrade nginx.conf for ssl.
    if ( $Cert ) {
        UpgradeNginxConf -ConfPath $NginxPathSet.ConfPath -ServerName $CommonName -Source (Join-Path $PSScriptRoot conf)

        # Restart nginx using port 443 with SSL.
        nssm restart nginx
    }
}

function InstallAll {
    Param (
        # Nginx Location
        [Parameter(Mandatory=$true)][string] $NginxRootPath,
        # Nginx Listen Port
        [string] $NginxPort
    )

    # Chocolatey. It's a package manager for Windows.
    # https://chocolatey.org/install
    $ChocoExe = Get-Command choco -ErrorAction Ignore
    if ( ! $ChocoExe ) {
        Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    } else {
        Write-Host "Chocolatey has already installed."
    }
    $ChocolateyInstall = Convert-Path "$((Get-Command choco).path)\..\.."
    Import-Module "${ChocolateyInstall}\helpers\chocolateyProfile.psm1"

    # OpenSSL and misc.
    choco install -y openssl.light 7zip dotnet4.7.2

    # Nginx
    # https://chocolatey.org/packages/nginx
    if (! $NginxPort ) {
        $NginxPort = "80"
    }
    if ( $NginxRootPath ) {
        $NginParams = "`"/installLocation:$NginxRootPath /Port:$NginxPort`""
        Write-Host "Nginx Location = $NginxRootPath"
        Write-Host "Nginx Listen Port = $NginxPort"
        choco install -y nginx --params $NginParams
    }

    # letsencrypt-win-simple(win-acme v1)
    # https://chocolatey.org/packages/letsencrypt-win-simple
    if ($WinAcme1) {
        choco install -y letsencrypt-win-simple
    }

    # win-acme v2: Install from release package.
    # https://github.com/PKISharp/win-acme/releases
    $WinAcmeInstallPath = Join-Path $env:ProgramFiles "win-acme2"
    ExtractZipUrl -Url $WinAcmeUrl -Destination $WinAcmeInstallPath -Clean
    if ( ! (Get-Command "wacs" -ErrorAction Ignore) ) {
        # Update Path Environment value.
        $SystemPath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
        $UserPath   = [System.Environment]::GetEnvironmentVariable("Path", "User")
        $SystemPath = "${SystemPath};${WinAcmeInstallPath}"
        [System.Environment]::SetEnvironmentVariable("Path", $SystemPath, "Machine")
        $env:Path   = "${SystemPath};${UserPath}"
    }

    # Install .Net Framework 4.7.2.
    choco install -y dotnet4.7.2

    # Apply environment for packages installed by chocolatey.
    refreshenv
}

function SetupFirewall {
    Param (
        # Full-path of nginx.exe
        [Parameter(Mandatory=$true)][string] $Nginx
    )

    # Firewall setting for nginx.
    if ( Test-Path $Nginx ) {
        AllowFirewallRule -Name "nginx" -Program $Nginx
    }

    # Firewall setting for win-acme.
    # The ACME server will always send requests to port 80.
    # https://github.com/PKISharp/win-acme/wiki/Command-line#selfhosting-plugin
    # Note: Windows Firewall can't determine the program listening port 80 for selfhosting.
    # AllowFirewallRule -Name "Letsencrypt ACME" -Port 80
}

# https://github.com/mkevenaar/chocolatey-packages/blob/master/automatic/nginx/tools/helpers.ps1
function Get-NginxPaths {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory)][ValidateNotNullOrEmpty()][string] $installDir
    )

    $nginxDir = Get-ChildItem $installDir -Directory -Filter 'nginx*' | Sort-Object { -join $_.Name.Replace('-','.').Split('.').PadLeft(3) } -Descending | Select-Object -First 1 -ExpandProperty FullName
    $confPath = Join-Path $nginxDir 'conf\nginx.conf'
    $binPath = Join-Path $nginxDir 'nginx.exe'

    return @{ NginxDir = $nginxDir; ConfPath = $confPath; BinPath = $binPath }
}

function LetsencryptCertificate {
    Param (
        [Parameter(Mandatory=$true)][string] $CommonName,
        [string] $AlternativeNames,
        [Parameter(Mandatory=$true)][string] $Email,
        [Parameter(Mandatory=$true)][string] $WebRootPath,
        [string] $CertStorePath,
        [switch] $WinAcme2
    )

    if ( $AlternativeNames ) {
        $HostNames = "$CommonName,$AlternativeNames"
    } else {
        $HostNames = $CommonName
    }

    if ( $CertStorePath -and (Test-Path $CertStorePath) ) {

        Write-Host "Challenge Lets Encrypt Certificate..."

        # Store script for win-acme.
        if ( $WinAcme2 ) {
            $CertStoreScript = "register_certpem.ps1"
        } else {
            $CertStoreScript = "register_certpem_v1.cmd"
        }
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $CertStoreScript) -Destination $CertStorePath
        $Script = Join-Path $CertStorePath $CertStoreScript
    
        # Declare script for installing certificate.
        # https://github.com/PKISharp/win-acme/wiki/Install-script
        if ( $WinAcme2 ) {
            $OptionParams = "--installation", "script",
                            "--store", "pemfiles", `
                            "--pemfilespath", $CertStorePath, `
                            "--script", $Script, `
                            "--scriptparameters", "'{0}' '${CertStorePath}'"
        } else {
            $OptionParams = "--script", $Script,
                            "--scriptparameters", "\`"{0}\`" \`"${CertStorePath}\`" \`"{2}\`" \`"{StorePath}\`""
        }
    } else {

        Write-Host "Test Lets Encrypt Certificate..."

        # Declare baseuri for test.
        if ( $WinAcme2 ) {
            $OptionParams = "--baseuri", "https://acme-staging-v02.api.letsencrypt.org/"
        } else {
            $OptionParams = "--baseuri", "https://acme-staging.api.letsencrypt.org/"
        }
    }

    # Run win-acme(WACS)
    # See https://github.com/PKISharp/win-acme
    # alse wacs --help

    Write-Host "  CommonName    = $CommonName"
    Write-Host "  HostNames     = $HostNames"
    Write-Host "  Email         = $Email"
    Write-Host "  CertStorePath = $CertStorePath"

    if ( $WinAcme2 ) {
        
        # win-acme v2

        Write-Host "wacs --target manual `
            --validation filesystem `
            --commonname ${CommonName} `
            --host ${HostNames} `
            --webroot $WebRootPath `
            --emailaddress ${Email} `
            --accepttos `
            ${OptionParams}"
        wacs --target manual `
            --validation filesystem `
            --commonname ${CommonName} `
            --host ${HostNames} `
            --webroot $WebRootPath `
            --emailaddress ${Email} `
            --accepttos `
            ${OptionParams}
    } else {

        # letsencrypt-win-win-simple v1

        Write-Host "letsencrypt --plugin manual `
        --validation filesystem `
        --commonname ${CommonName} `
        --manualhost ${HostNames} `
        --webroot $WebRootPath `
        --emailaddress ${Email} `
        --accepttos `
        ${OptionParams}"
    
        letsencrypt --plugin manual `
            --validation filesystem `
            --commonname ${CommonName} `
            --manualhost ${HostNames} `
            --webroot $WebRootPath `
            --emailaddress ${Email} `
            --accepttos `
            ${OptionParams}
    }
}

function UpgradeNginxConf {
    param (
        [Parameter(Mandatory=$true)][string] $ConfPath,
        [Parameter(Mandatory=$true)][string] $ServerName,
        [string] $Source
    )

    if ( ! (Test-Path $ConfPath )) {
        return
    }

    Write-Host "Upgrade nginx conf for ssl."
    
    # Copy conf files from source in recurse
    $ConfFolderPath = Split-Path -Path $ConfPath -Parent
    if ( Test-Path $Source ) {
        Copy-Item -LiteralPath $Source -Destination $ConfFolderPath\.. `
            -Recurse -ErrorAction Ignore
    }

    # Include nginx_ssl.conf into nginx.conf and Configure general settings.
    ((Get-Content -Path $ConfPath) -notmatch "# managed") | Set-Content -Path $ConfPath
    $length  = (Get-Content -Path $ConfPath).Length
    $head    =  Get-Content -Path $ConfPath -TotalCount ($length-5)
    $tailcut = (Get-Content -Path $ConfPath -Tail 5) -notmatch "^}[ \t]*$"
    $head + $tailcut | Set-Content -Path $ConfPath
    Write-Output    "    server_names_hash_bucket_size 64; # managed" `
                    "    server_tokens off; # managed" `
                    "    include nginx_ssl.conf; # managed" `
                    "    include conf.d/*.conf;  # managed" `
                    "}" | Add-Content -Path $ConfPath

    # Replace cert store path in nginx_ssl.conf
    $NginxSslConf = Join-Path $ConfFolderPath "nginx_ssl.conf"
    if ( Test-Path $NginxSslConf ) {
        # C:\SSL\cert -> C:/SSL/cert/
        $CertStorePathSlashed = ($CertStorePath -replace "\\","/") -replace "[^/]$","`$0/"
        # include C:/SSL/cert/nginx_ssl_cert.conf; # managed
        (Get-Content $NginxSslConf) -replace "([^ \t]+).*(nginx_ssl_cert.conf);[ \t]*# managed","`$1 $CertStorePathSlashed`$2; # managed" | Set-Content $NginxSslConf
        # ssl_dhparam C:/SSL/cert/dhparam.pem; # managed
        (Get-Content $NginxSslConf) -replace "([^ \t]+).*(dhparam.pem);[ \t]*# managed","`$1 $CertStorePathSlashed`$2; # managed" | Set-Content $NginxSslConf
    }

    # Replace server name in default.conf
    $DefaultConf = Join-Path $ConfFolderPath "conf.d\default.conf"
    if ( Test-Path $DefaultConf ) {
        $ServerNameDirective = "server_name " + ($ServerName -replace ","," ") + "; # managed"
        # server_name www.example.com; # managed
        (Get-Content $DefaultConf) -replace "server_name.*# managed","$ServerNameDirective" | Set-Content $DefaultConf
    }
}

function ExtractZipUrl {
    Param (
        [Parameter(Mandatory=$true)][string] $Url,
        [Parameter(Mandatory=$true)][string] $Destination,
        [switch] $Clean
    )

    # $WinAcmeZip = Join-Path New-TempDirectory "win-acme.zip"
    $ZipFile = Split-Path $Url -Leaf
    $TempZip = Join-Path $env:TEMP $ZipFile

    Write-Host "Extract Zip File...`
        Url = $Url `
        Destination = $Destination"

    # mkdir and clean.
    if ( ! (Test-Path -Path $Destination ) ) {
        New-Item -Type Directory -Path $Destination
    } elseif ( $Clean ) {
        Remove-Item -Path $Destination\* -Recurse -Force -ErrorAction Ignore
    }

    # Download zip from url with TLS1.2.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12,[Net.SecurityProtocolType]::Tls11
    (New-Object System.Net.WebClient).DownloadFile($Url, $TempZip)
    
    # Extract by 7z.
    7z x -o"$Destination" $TempZip
}

function AllowFirewallRule {
    Param (
        [Parameter(Mandatory=$true)][string] $Name,
        [string] $Enabled="True",
        [string] $Port,
        [string] $Program
    )

    Write-Host  "Allow firewall for $Name. `
        Enabled = $Enabled `
        Port    = $Port `
        Program = $Program"

    # Activate the firewall rule if exist.
    # See https://docs.microsoft.com/en-us/powershell/module/netsecurity/Set-NetFirewallRule?view=win10-ps
    $Rule = Get-NetFirewallRule -Name "$Name" -ErrorAction Ignore
    if ( $Rule ) {
        if ( ! $Port ) {
            $Port = ($Rule | Get-NetFirewallPortFilter).LocalPort
        }
        if ( ! $Program ) {
            $Program = ($Rule | Get-NetFirewallApplicationFilter).Program
        }
        Write-Host "Set-NetFirewallRule -Name $Name `
            -Enabled $Enabled `
            -Action Allow `
            -LocalPort $Port `
            -Program $Program"
        Set-NetFirewallRule -Name "$Name" `
            -Enabled $Enabled `
            -Action Allow `
            -LocalPort $Port `
            -Program $Program
        return
    }

    # Add the firewall rule.
    # See https://docs.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule?view=win10-ps
    if ( ! $Port -and ! $Program ) {
        return
    } elseif ( ! $Port ) {
        $Port = "Any"
    }

    if ( $Program ) {

        # Allow specified program.

        Write-Host "New-NetFirewallRule -DisplayName $Name `
            -Name $Name `
            -Enabled $Enabled `
            -Direction Inbound `
            -Action Allow `
            -Program $Program `
            -Protocol TCP `
            -LocalPort $Port"
        New-NetFirewallRule -DisplayName "$Name" `
            -Name "$Name" `
            -Enabled $Enabled `
            -Direction Inbound `
            -Action Allow `
            -Program $Program `
            -Protocol TCP `
            -LocalPort $Port
    } else {

        # Allow specified port.

        Write-Host "New-NetFirewallRule -DisplayName $Name `
            -Name $Name `
            -Enabled $Enabled `
            -Direction Inbound `
            -Action Allow `
            -Protocol TCP `
            -LocalPort $Port"
        New-NetFirewallRule -DisplayName "$Name" `
            -Name "$Name" `
            -Enabled $Enabled `
            -Direction Inbound `
            -Action Allow `
            -Protocol TCP `
            -LocalPort $Port
    }
}

function MakeCertStoreFolder {
    Param (
        # Cert Store Path
        [Parameter(Mandatory=$true)][string] $Path
    )

    if ( Test-Path $Path ) {
        Write-Host "There is certificate store folder."
        Write-Host "TAKE CARE IT SECURE. THE PRIVATE-KEY WILL BE STORED."
        return
    }

    # mkdir
    Write-Host "Mkdir $Path in secure."
    New-Item -Type Directory -Path $Path

    # Make secure.
    $SystemRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule (
        "NT AUTHORITY\SYSTEM", 
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit, [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow)
    $AdminRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule (
        "BUILTIN\Administrators",
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit, [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow)
    $Acl = Get-Acl -Path $Path
    $Acl.SetAccessRuleProtection($true,$false); $Acl.SetAccessRule($SystemRule); $Acl.SetAccessRule($AdminRule)
    $Acl | Set-Acl -Path $Path
}

function MakeDhparam {
    param(
        # Store Folder for dhparam.
        [Parameter(Mandatory=$true)][string] $Path
    )

    if ( ! (Test-Path $Path)) {
        return
    }
    
    # Generate DH parameters for DHE ciphers.
    # https://qiita.com/d2cd-ytakada/items/7ac9ce32c1ed4d01d505
    $dhparam = Join-Path $Path dhparam.pem
    if ( ! (Test-Path $dhparam) ) {
        openssl dhparam -out $dhparam 2048
    } else {
        Write-Host "There is already $dhparam"
    }
}

main
