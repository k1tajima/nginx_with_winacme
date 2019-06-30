# nginx + Windows ACME Simple と PowerShell で TLS1.2 対応サイトを自動構築

> https://qiita.com/k1tajima/items/6c20adb3a09fc21009bf

## はじめに

自分では Linux + nginx + certbot でプロキシサーバーを構築して利用しているが、職場で Windows ベースでプロキシサーバーを構築することになり、それがきっかけとなった。

Windows ベースではあるが、プロキシサーバーなら IIS よりも nginx。そして、Windows 用の ACME クライアントとしては、Pem 形式の証明書を出力でき nginx にも使える [Windows ACME Simple][win-acme] を採用することにした。

Windows ACME Simple は、以前まで [letsencript-win-simple][lews] という名前で提供されていた ACME クライアント。ネット検索してみると、対話形式で証明書を取得する手順が書かれたものがほとんどだが、[CLI][cli] もちゃんと備えている。

そして、今後の保守のためにセットアップの手順書を書き起こすのも非効率なので、PowerShell スクリプトで自動化することにした。スクリプトのコメントを読めば概要はわかるし、再現性も保証できる。

[win-acme]: https://github.com/PKISharp/win-acme/blob/master/README.md
[lews]: https://chocolatey.org/packages/letsencrypt-win-simple
[cli]: https://github.com/PKISharp/win-acme/wiki/Command-line

## システム構成

* Windows Server 2016
* [Chocolatey](https://chocolatey.org/)
* [nginx](https://chocolatey.org/packages/nginx)
* [Windows ACME Simple][win-acme]
* [.NET Framework 4.7.2](https://chocolatey.org/packages/dotnet4.7.2)
* [OpenSSL lite](https://chocolatey.org/packages/OpenSSL.Light)
* [7zip](https://chocolatey.org/packages/OpenSSL.Light)
* [Let's Encrypt 証明書](https://letsencrypt.org/)

## 手動でサイト構築する場合の手順

* 必要なソフトウェアのインストール
* Firewall での受信許可（ポート番号指定ではなく、プログラム `nginx.exe` 指定）
* 証明書格納先フォルダのアクセス権限設定（秘密鍵もここに格納）
* Let's Encrypt からの証明書取得
* 証明書を定期更新するためのタスクスケジュール
* nginx の設定変更による証明書の組込み・暗号化方式の指定ほか

## PowerShell による自動化

### スクリプトの取得

* GitHubリポジトリから取得

    > https://github.com/tajimak/nginx_with_winacme

* ZIPファイルとして一式を取得

    > https://github.com/tajimak/nginx_with_winacme/archive/master.zip

### 事前準備

* 対象ホストのFQDN(CommonName)をDNSに登録しておく。

* 管理者権限付きで PowerShell を起動して、PowerShell スクリプトの実行を許可する。

    ```powershell
    PS> Set-ExecutionPolicy Bypass -Force
    もしくは
    PS> Set-ExecutionPolicy RemoteSigned -Force
    ```

    詳しくは、[こちら](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy)を参照。

### 本スクリプトの使用方法

* run.ps1 を編集して、CommonName, Email ほかを設定する。

    ```powershell
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
    #     -NginxRootPath 'C:\tools' `
    #     -CertStorePath 'C:\SSL\cert\win-acme' `
    #     -Cert:$Cert
    ```

* 管理者権限付きで PowerShell を起動して、run.ps1 をオプションなしで実行する。これにより、必要なプログラムが一通りインストールされ、Let's Encrypt サーバーとの接続テストが行われる。

    ```powershell
    PS> run.ps1
    ```

* 接続テストに成功したら、run.ps1 を -Cert オプション付きで実行する。これにより Let's Encrypt サーバーから正式な証明書が取得され、nginx に組み込まれる。

    ```powershell
    PS> run.ps1 -Cert
    ```

* ブラウザから CommonName(FQDN) で自サイトに https 接続できることを確認する。
    * AlternativeNames による https 接続は未設定のため、接続確認には別途追加設定が必要。

* wacs を対話モードで実行して、証明書の定期更新がスケジュールされていることを確認する。

    ```
    PS> wacs
     [INFO] A simple Windows ACMEv2 cl
     [INFO] Software version 2.0.5.246
     [INFO] IIS not detected
     [INFO] Please report issues at ht


     M: Create new certificate with ad
     L: List scheduled renewals
     R: Renew scheduled
     S: Renew specific
     A: Renew *all*
     O: More options...
     Q: Quit
    
     Please choose from the menu: L
    
     1: [Manual] xxx.yourdomain.com - renewed 1 times, due after 2019/6/2 22:29:12
     <Enter>: Back

     Show details for renewal?: 1
    ```

* 次のサイトなどで、セキュリティレベルを検証する。A+ 評価が得られるはず。

    > https://www.ssllabs.com/ssltest/

## 本スクリプトでの nginx 設定ファイル構成

* 本スクリプトを使用すると証明書が取得されると共に、nginx の設定ファイルが次の構成に更新され、nginx に証明書が自動的に組み込まれる。

| ファイルまたはフォルダ | 内容 |
|----|----|
| 設定ファイル格納先フォルダ | C:\tools\nginx-x.x.x\conf |
| [nginx.conf][nginx-conf] | nginx 標準の設定ファイル，http://localhost アクセスに対する設定 |
| [nginx_ssl.conf][nginx-ssl-conf] | 暗号化方式ほか SSL 関連の設定 |
| C:\SSL\cert\win-acme\nginx_ssl_cert.conf | 証明書と秘密鍵のファイルパス（証明書定期更新時に上書きされるため編集禁止） |
| [conf.d\default.conf][default-conf] | http 接続から https 接続へのリダイレクト設定，https://{CommonName} アクセスに対する設定 |

[nginx-conf]: https://github.com/nginx/nginx/blob/master/conf/nginx.conf
[nginx-ssl-conf]: https://github.com/tajimak/nginx_with_winacme/blob/master/script/conf/nginx_ssl.conf
[default-conf]: https://github.com/tajimak/nginx_with_winacme/blob/master/script/conf/conf.d/default.conf

* nginx.conf の書き換え内容
    * [nginx 標準の nginx.conf][nginx-conf] の末尾に、次の行を追加している。

        ```
        http {
            ...
            server_names_hash_bucket_size 64; # managed
            server_tokens off; # managed
            include nginx_ssl.conf; # managed
            include conf.d/*.conf;  # managed
        }
        ```

* 想定している運用方法
    * 基本的に、基底となる `nginx.conf` ファイルには、提供コンテンツやアプリに依存しない不変的な項目のみを設定する。
    * `conf\conf.d` フォルダには、サブドメイン(AlternativeNames)や、コンテキスト、ポート番号ごとに `*.conf` ファイルを用意して設定する
    * 設定ファイルの構成例
        * default.conf ･･･ https://{CommonName} の設定
        * subdomain.example.com.conf ･･･ https://subdomain.example.com の設定
        * context.conf ･･･ https://{CommonName}/context の設定
        * 8080.conf ･･･ https://{CommonName}:8080 の設定

## nginx 設定の更新手順

* Chocolatey で提供されている [nginx パッケージ][nginx-choco]では、nginx をサービスとして動作させるために [nssm][nssm] が利用されている。nginx サービスの実行状態確認や実行制御は [nssm のコマンド][nssm-cli]で行える。

[nginx-choco]: https://chocolatey.org/packages/nginx
[nssm]: https://nssm.cc/
[nssm-cli]: https://nssm.cc/commands

    * 例えば、nginx サービスの実行状態は次のコマンドで確認できる。

        ```
        nssm status nginx
        ```

* nginx の設定を変更するときの基本的な手順は次の通り。

    * nginx の設定ファイル(*.conf)をエディタで変更する。

    * 設定変更内容に構文エラーがないことを事前テストする。

        ```
        cd C:\nginx\nginx-x.x.x
        .\nginx.exe -t
        ```

    * nssm で nginx サービスをリスタートする。

        ```
        nssm restart nginx
        ```

## 注意事項：choco upgrade 非対応

* choco upgrade nginx の現時点の課題

    2019-04-26 現在、Chocolatey の nginx パッケージを旧バージョンからバージョンアップしようと、 `choco upgrade nginx` を実行すると、次の状態となり、従来通り機能しなくなる。

    * nginx 設定が継承されず、初期設定状態になってしまう。
    * nginx.exe のパスがバージョンごとに変更されるため、ファイアウォールの設定変更が別途必要になる。
    * 以前のインストール先フォルダは考慮されず、常に `C:\tools` フォルダ以下のサブフォルダにインストールされる。

* 暫定対策

    暫定的な対処として、本スクリプトでインストールした場合、Chocolatey の pin 機能を使用して、nginx パッケージの upgrade を抑制してある。（これにより `choco upgrade all` を実行時に nginx パッケージは除外される）

    手動で `choco upgrade nginx` を実行する場合、次の処置を行う。

    * nginx パッケージに対する pin を解除する。
    * nginx パッケージを upgrade する。必要に応じてインストール先フォルダを指定する。
    * nginx 設定ファイルをコピーする。
    * 「nginx 設定の更新手順」に従って、nginx 設定を反映する。
    * ファイアウォールの受信の規則で対象プログラム(nginx.exe)のパスを変更し、外部からのアクセスを確認する。
    * nginx パッケージに対する pin を再設定する。

## その他の留意事項

* CommonName, AlternativeNames の DNS 登録必要

    FQDN として CommonName が DNS 登録済みで、インターネットから対象ホストの 80, 443 Port に到達可能になっている必要がある。なお、対象ホストのファイアウォール設定はスクリプトによって自動更新されるため、受信規則の事前変更は不要。

    AlternativeNames を使用してサブドメインを使い分けたりする場合、それらも FQDN として DNS 登録が必要。

* ワイルドカード証明書 非対応

    Windows ACME Simple v2 はワイルドカード証明書に対応しているが、本スクリプトでは対応しない。ワイルドカード証明書を発行するには、DNS-01 Challenge 方式による認証が必要となる。

    * https://free-ssl.jp/docs/acme-v2-wildcards.html
    * https://community.letsencrypt.org/t/acme-v2-production-environment-wildcards/55578
    * https://github.com/PKISharp/win-acme/wiki/DNS-validation-plugins

* クリーン環境での動作確認済み

    本スクリプトは 80, 443 Port が未使用の状態であれば動作するはずだが、スクリプトの動作確認はクリーンな Windows Server 2016 環境(Windows Update済み)で実施している。スクリプトを繰り返し実行しても問題ないことは確認済み。

* IIS は無効化または停止

    nginx が 80, 443 Port を使用するため、IIS は無効化または停止させておくこと。

* .NET Framework 4.7.2 インストール後に再起動必要

    Windows ACME Simple には .NET Framework 4.7.2 が必要だが、Windows Server 2016 標準では .NET Framework 4.7.2 がインストールされていない。そのインストールもスクリプトで自動実行されるが、インストール後にはOS再起動が必要となる。スクリプトは再起動の確認メッセージを表示していったん終了するため、再起動した後にスクリプトを再実行する。なお、.NET Framework 4.7.2 以降が事前にインストール済みであれば再起動の必要なし。

* Windows ACME Simple のバージョン決め打ち ･･･ 改修案求む

    Windows ACME Simple v2 はまだ Chocolatey に登録されていないため、リリースページから直接ダウンロードしてインストールしている。その際、インストールする Windows ACME Simple のバージョンをスクリプト内で URL 指定しており、決め打ちになってしまっている[^1]。
    最新バージョンは次のリリースページから確認し、必要に応じて URL を変更のこと。
    
    > https://github.com/PKISharp/win-acme/releases
    > 2019-04-14 現在の最新バージョン: v2.0.5

    [^1]: リリースページから最新版をピックアップしようと実装を試みたが、Windows Server では Internet Explorer セキュリティ強化によってブロックされ、スクリプト実行が中断されてしまうため、対応保留中。（[該当箇所][issue]、改修案求む）
   [issue]:https://github.com/tajimak/nginx_with_winacme/blob/41080f8d8b1ee6de073650813a3429c23fee6a21/script/setup_nginx_ssl.ps1#L25

* 暗号化方式(Chiper Suite)について

    SSL通信で許可する暗号化方式は、https://nginxconfig.io の Modern Browser 向け設定に従っている。よって、古いブラウザは切り捨てられアクセス拒否される。GitHub や巷のサイトと比較しても強めの暗号化のみ対応となっているため、必要に応じて `conf/nginx_ssl.conf` の設定を見直しのこと。（[該当箇所][chipersuite]）

[chipersuite]: https://github.com/tajimak/nginx_with_winacme/blob/65587e5dda94aa3854ccee28ff3745c605423214/script/conf/nginx_ssl.conf#L16

以上
