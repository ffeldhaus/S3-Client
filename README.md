S3 Client PowerShell Module
===========================

[![Build status](https://ci.appveyor.com/api/projects/status/od89v0qb7dmblkcx?svg=true)](https://ci.appveyor.com/project/ffeldhaus/s3-client)

The S3 Client Module contains Cmdlets for interacting with an S3 endpoint. It was developed to simplify usage, debugging and customization of interactions with an S3 Service. Written in pure PowerShell, the Code of the Cmdlets can be extracted and run interactively.

While the Cmdlets are working for any S3 object storage, they provide several enhancements to make S3 management easier for StorageGRID Webscale users. As an alternative, use the offical [AWS Cmdlets which include S3 Cmdlets](https://aws.amazon.com/de/powershell/).

See the sections below for [Installation](#Installation) and [Update](#Update) Instructions see the sections below. For more information check out the [S3 Client PowerShell Cmdlet Tutorial](S3-Client-Tutorial.md).

Installation
------------

The recommended way to install the PowerShell Module is through the Install-Module Cmdlet available since PowerShell 5. Consider installing [PowerShell 5](https://www.microsoft.com/en-us/download/details.aspx?id=50395) or [PowerShell 6](https://github.com/PowerShell/PowerShell#get-powershell). PowerShell 6 now supports Linux, Mac OS X and Windows.

By default PowerShell 5 and later have the official [Microsoft PowerShell Gallery](https://www.powershellgallery.com/) defined as installation source, but it is marked as `Untrusted` by default. To install the Cmdlets you need to trust this installation source using

```powershell
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
```

The StorageGRID Webscale Cmdlets are code signed. PowerShell (**currently only on Windows!**) can verify the code signature and only run code signed with a trusted certificate. To run the Cmdlets you need to ensure that your execution policy is set to either `AllSigned`, `RemoteSigned`, `Unrestricted`, `Bypass`. It is recommended to use `RemoteSigned`.

```powershell
Get-ExecutionPolicy
```

You can change the execution policy using the following command. It is recommended to change it only for the current user and use `RemoteSigned`:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

To install the Cmdlets only for the current user run

```powershell
Install-Module -Name S3-Client -Scope CurrentUser
```

To install the Cmdlets for all users, you need to run PowerShell as Administrator and then install them with

```powershell
Install-Module -Name S3-Client
```

The S3 Client PowerShell Cmdlets require at least PowerShell 5.0 and .NET 4.5.

If the Module can't be installed via `Install-Module` then the latest version can be downloaded from the [GitHub Release page](https://github.com/ffeldhaus/S3-Client/releases/latest) for manual installation. For manual installation, the S3-Client.zip file needs to be extracted to the preferred PowerShell Module location. For the current user the S3-Client folder needs to be copied to

    $HOME\Documents\WindowsPowerShell\Modules

To make the module available for all users the folder S3-Client needs to be copied to the folder

    C:\Windows\System32\WindowsPowerShell\v1.0\Modules

Update
------

If the Module was installed with `Install-Module`, it can be upgraded with

```powershell
Update-Module -Name S3-Client
```

If the Module was installed by downloading the ZIP file, then the Module can be updated by replacing the S3-Client folder with the content of the new release ZIP file.

Usage
-----

Check if S3-Client Module can be found by PowerShell

```powershell
    Get-Module -ListAvailable S3-Client
```

Import PowerShell Module

```powershell
    Import-Module S3-Client
```

List all Cmdlets included in the S3-Client Module

```powershell
    Get-Command -Module S3-Client
```

Show help for Cmdlet to list all buckets

```powershell
    Get-Help Get-S3Buckets -Detailed
```