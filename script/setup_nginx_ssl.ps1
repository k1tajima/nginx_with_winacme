# Setup Proxy Server with Nginx for Windows.
Param (
    # Common Name for Certificate: ex. "www.example.com"
    [Parameter(Position=0,Mandatory=$true)]
    [string] $CommonName,
    # AlternativeNames, comma delimited: ex. "proxy.example.com,app.example.com"
    [string] $AlternativeNames,
    # Email for registration on letsencrypt ex. "you@example.com"
    [Parameter(Position=1,Mandatory=$true)]
    [string] $Email,
    # Path to store Certificate Pem Files: "C:\SSL\cert\win-acme" as default
    [string] $CertStorePath     = "C:\SSL\cert\win-acme",
    # Path to root of html files: "$env:PUBLIC\html" as default
    [string] $WebRootPath = "$env:PUBLIC\html",
    # Challenge Certificate: default is false. It's just for testing
    [switch]$Cert
)

# Web Access with TLS1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# Please check the latest version of win-acme yourself.
# https://github.com/PKISharp/win-acme/releases/
$WinAcmeUrl = "https://github.com/PKISharp/win-acme/releases/download/v2.0.8/win-acme.v2.0.8.356.zip"
# $WinAcmeUrl = (((Invoke-WebRequest -Uri "https://github.com/PKISharp/win-acme/releases/").Links.Href) -match "win-acme.v[0-9\.]+.zip")[0]

# Return value of functions.
$ReturnValue = $null

# Input Pfx Passowrd.
if ($Cert) {
    $PfxPassword = Read-Host "Enter PfxPassword" -AsSecureString
}

function main {
    Write-Host "HostName: $env:COMPUTERNAME"
    Write-Host "CommonName: $CommonName"

    # Check Installed .NET Framework Version.
    # https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed#ps_a
    $DotNetKey = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\' | Get-ItemPropertyValue -Name Release | Sort-Object -Descending | Select-Object -First 1
    $HasInstalledDotNet472 = ($DotNetKey -ge 461814)

    # Install packages first.
    $NginxRootPath = "C:\tools"
    InstallAll -NginxRootPath $NginxRootPath

    if (! $HasInstalledDotNet472) {
        # Reboot Windows after installing .NET Framework.
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

    # Setup firewall for nginx.
    AllowFirewallRule -Name "nginx" -Program $NginxPathSet.BinPath

    # Setup firewall for win-acme selfhosting mode.
    # AllowFirewallRule -Name "Letsencrypt ACME" -Port 80

    # Make cert store folder secure.
    MakeCertStoreFolder -Path $CertStorePath

    # Make dhparam.pem by openssl.
    MakeDhparam -Path $CertStorePath

    # Setup html root path in default.conf
    SetupWebRootPath -WebRootPath $WebRootPath -NginxDir $NginxPathSet.NginxDir

    # Drive Windows ACME Simple(WACS) by webroot mode.
    LetsencryptCertificate `
        -CommonName $CommonName `
        -AlternativeNames $AlternativeNames `
        -Email $Email `
        -WebRootPath $WebRootPath `
        -PfxPassword $PfxPassword `
        -CertStorePath $(if ( $Cert ) { $CertStorePath } else { "" })

    # Upgrade nginx.conf for SSL.
    if ( $ReturnValue -and $Cert ) {
        $ServerNames = $CommonName
        if ($AlternativeNames) {
            $ServerNames += ",$AlternativeNames"
        }

        UpgradeNginxConf -ConfPath $NginxPathSet.ConfPath `
            -CommonName $CommonName -ServerNames $ServerNames `
            -Source (Join-Path $PSScriptRoot conf)

        # Restart nginx using port 443 with SSL.
        nssm restart nginx

        Write-Host ""
        Write-Host "Finished."

    } elseif ( $ReturnValue ) {
        Write-Host ""
        Write-Host "Test was suceeded."
        Write-Host "Please run this script with -Cert option."
        Write-Host ""
        Write-Host "  PS> $(Split-Path -Path $PSCommandPath -Leaf) -Cert"
        Write-Host ""

    } else {
        Write-Host ""
        Write-Host "Test was failed."
        Write-Host "Please check 'CommonName', 'AlternativeNames, and DNS registrations."
    }
}

function InstallAll {
    Param (
        # Nginx Location
        [Parameter(Mandatory=$true)]
        [string] $NginxRootPath,
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
    $NginParams = "`"/installLocation:$NginxRootPath /Port:$NginxPort`""
    Write-Host "Nginx Location = $NginxRootPath"
    Write-Host "Nginx Listen Port = $NginxPort"
    choco install -y nginx --params $NginParams

    # Exclude choco upgrade nginx.
    choco pin add -n=nginx

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

function SetupWebRootPath {
    param (
        [Parameter(Mandatory=$true)]
        [string] $WebRootPath,
        [Parameter(Mandatory=$true)]
        [string] $NginxDir
    )

    # Make html root path if not exist.
    if ( ! (Test-Path $WebRootPath)) {
        # Create html folder.
        New-Item -Path $WebRootPath -ItemType Directory
        # copy some files.
        Copy-Item -Path (Join-Path $NginxDir "html\*") -Destination $WebRootPath

        Write-Host "The html root folder has been created, $WebRootPath"
    }

    # Update root directive in default.conf
    $ConfFile = Join-Path $NginxDir "conf\conf.d\default.conf"
    if ( ! (Test-Path $ConfFile )) {
        return
    }

    # root /C/Users/Public/html; # managed
    $WebRootPathSlashed = ($WebRootPath -replace "^([a-zA-Z]):","/`$1" ).Replace("\","/") -replace "/$",""
    $RootDirective = "root " + $WebRootPathSlashed + "; # managed"
    (Get-Content $ConfFile) -replace "root.*# managed","$RootDirective" | Set-Content $ConfFile

    Write-Host "The root directive has been updated, $ConfFile"
}

function LetsencryptCertificate {
    Param (
        [Parameter(Mandatory=$true)]
        [string] $CommonName,
        [string] $AlternativeNames,
        [Parameter(Mandatory=$true)]
        [string] $Email,
        [Parameter(Mandatory=$true)]
        [string] $WebRootPath,
        [SecureString] $PfxPassword,
        [string] $CertStorePath
    )

    if ( $AlternativeNames ) {
        $HostNames = "$CommonName,$AlternativeNames"
    } else {
        $HostNames = $CommonName
    }

    if ( $CertStorePath -and (Test-Path $CertStorePath) ) {

        Write-Host "Challenge Lets Encrypt Certificate..."

        # Store script for win-acme.
        $CertStoreScript = "register_certpem.ps1"
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $CertStoreScript) -Destination $CertStorePath
        $Script = Join-Path $CertStorePath $CertStoreScript
    
        # Declare script for installing certificate.
        # https://github.com/PKISharp/win-acme/wiki/Install-script
        $planePassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR( $PfxPassword ))
        $OptionParams = "--installation", "script",
                        "--store", "centralssl,pemfiles", `
                        "--pemfilespath", $CertStorePath, `
                        "--centralsslstore", $CertStorePath, `
                        "--pfxpassword", $planePassword, `
                        "--script", $Script, `
                        "--scriptparameters", "'{0}' '${CertStorePath}'"
    } else {

        Write-Host "Test Lets Encrypt Certificate..."

        # Declare baseuri for test.
        $OptionParams = "--baseuri", "https://acme-staging-v02.api.letsencrypt.org/", `
                        "--notaskscheduler"
    }

    # Run win-acme(WACS)
    # See https://github.com/PKISharp/win-acme
    # alse wacs --help

    Write-Host "  CommonName    = $CommonName"
    Write-Host "  HostNames     = $HostNames"
    Write-Host "  Email         = $Email"
    Write-Host "  CertStorePath = $CertStorePath"

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

    $script:ReturnValue = $?
}

function UpgradeNginxConf {
    param (
        [Parameter(Mandatory=$true)]
        [string] $ConfPath,
        [Parameter(Mandatory=$true)]
        [string] $CommonName,
        [string] $ServerNames,
        [string] $Source
    )

    if ( ! (Test-Path $ConfPath )) {
        return
    }

    Write-Host "Upgrading nginx conf for ssl..."

    if ( ! $ServerNames ) {
        $ServerNames = $CommonName
    }
    
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
    Write-Host "    nginx.conf has been upgraded, $ConfPath"

    # Replace cert store path in nginx_ssl.conf
    $NginxSslConf = Join-Path $ConfFolderPath "nginx_ssl.conf"
    if ( Test-Path $NginxSslConf ) {
        # C:\SSL\cert -> C:/SSL/cert/
        $CertStorePathSlashed = ($CertStorePath -replace "\\","/") -replace "[^/]$","`$0/"
        # include C:/SSL/cert/nginx_ssl_cert.conf; # managed
        (Get-Content $NginxSslConf) -replace "([^ \t]+).*(nginx_ssl_cert.conf);[ \t]*# managed","`$1 $CertStorePathSlashed`$2; # managed" | Set-Content $NginxSslConf
        # ssl_dhparam C:/SSL/cert/dhparam.pem; # managed
        (Get-Content $NginxSslConf) -replace "([^ \t]+).*(dhparam.pem);[ \t]*# managed","`$1 $CertStorePathSlashed`$2; # managed" | Set-Content $NginxSslConf

        Write-Host "    nginx_ssl.conf has been upgraded, $NginxSslConf"
    }

    # Replace server name default.conf
    $DefaultConf = Join-Path $ConfFolderPath "conf.d\default.conf"
    if ( Test-Path $DefaultConf ) {
        # server_name www.example.com; # managed(CommonName)
        $ServerNameDirective = "server_name ${CommonName}; # managed(CommonName)"
        (Get-Content $DefaultConf) -replace "server_name.*# managed\(CommonName\)","$ServerNameDirective" | Set-Content $DefaultConf
        # server_name www.example.com app.example.com www.example.jp; # managed(ServerNames)
        $ServerNameDirective = "server_name " + ($ServerNames -replace ","," ") + "; # managed(ServerNames)"
        (Get-Content $DefaultConf) -replace "server_name.*# managed\(ServerNames\)","$ServerNameDirective" | Set-Content $DefaultConf

        Write-Host "    default.conf has been upgraded, $DefaultConf"
    }
}

# Reference https://github.com/mkevenaar/chocolatey-packages/blob/master/automatic/nginx/tools/helpers.ps1
function Get-NginxPaths {
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory)][ValidateNotNullOrEmpty()][string] $installDir
    )

    $nginxDir = Get-ChildItem $installDir -Directory -Filter 'nginx*' | Sort-Object { -join $_.Name.Replace('-','.').Split('.').PadLeft(3) } -Descending | Select-Object -First 1 -ExpandProperty FullName
    $confPath = Join-Path $nginxDir 'conf\nginx.conf'
    $binPath = Join-Path $nginxDir 'nginx.exe'

    return @{ NginxDir = $nginxDir; ConfPath = $confPath; BinPath = $binPath }
}

function ExtractZipUrl {
    Param (
        [Parameter(Mandatory=$true)]
        [string] $Url,
        [Parameter(Mandatory=$true)]
        [string] $Destination,
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

    # Download zip from url
    (New-Object System.Net.WebClient).DownloadFile($Url, $TempZip)
    
    # Extract by 7z.
    7z x -o"$Destination" $TempZip
}

function AllowFirewallRule {
    Param (
        [Parameter(Mandatory=$true)]
        [string] $Name,
        [string] $Enabled="True",
        [string] $Port,
        [string] $Program
    )

    # Write-Host  "Allow firewall for $Name. `
    #     Enabled = $Enabled `
    #     Port    = $Port `
    #     Program = $Program"

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
        [Parameter(Mandatory=$true)]
        [string] $Path
    )

    if ( Test-Path $Path ) {
        Write-Host "----------------------------------------------------"
        Write-Host "There is certificate store folder, $Path"
        Write-Host "TAKE CARE IT SECURE. THE PRIVATE-KEY WILL BE STORED."
        Write-Host "----------------------------------------------------"
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
        [Parameter(Mandatory=$true)]
        [string] $Path
    )

    if ( ! (Test-Path $Path)) {
        return
    }
    
    $dhparam = Join-Path $Path "dhparam.pem"
    if (Test-Path $dhparam) {
        Write-Host "There is already $dhparam"
        return
    }

    # Generate DH parameters for DHE ciphers.
    # https://qiita.com/d2cd-ytakada/items/7ac9ce32c1ed4d01d505
    openssl dhparam -out $dhparam 2048
}

main
