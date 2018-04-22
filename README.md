S3 Client PowerShell Module
===========================

[![Build status](https://ci.appveyor.com/api/projects/status/od89v0qb7dmblkcx?svg=true)](https://ci.appveyor.com/project/ffeldhaus/s3-client)

The S3 Client Module contains Cmdlets for interacting with an S3 endpoint. While the Cmdlets are working for any S3 object storage, they provide several enhancements to make S3 management easier for StorageGRID Webscale users. For a [feature rich, performance optimized S3 Client in PowerShell use the official AWS Cmdlets](https://aws.amazon.com/de/powershell/).

See the sections below for [Installation](#Installation) and [Update](#Update) Instructions see the sections below. For more information check out the [S3 Client PowerShell Cmdlet Tutorial](S3-Client-Tutorial.md).

Installation
------------

The recommended way to install the PowerShell Module is through the new Install-Module Cmdlet available since PowerShell 5. Consider installing [PowerShell 5](https://www.microsoft.com/en-us/download/details.aspx?id=50395) or [PowerShell 6](https://github.com/PowerShell/PowerShell#get-powershell). PowerShell 6 now supports Linux, Mac OS X and Windows. 

To install the Cmdlets only for the current user run

```powershell
Install-Module -Name S3-Client -Scope CurrentUser
```

To install the Cmdlets for all users, you need to run PowerShell as Administrator and then install them with

```powershell
Install-Module -Name S3-Client
```

The S3 Client PowerShell Cmdlets require at least PowerShell 4.0 and .NET 4.5. 

If you can't install via `Install-Module` you can download the latest version of S3-Client.zip from the [GitHub Release page](https://github.com/ffeldhaus/S3-Client/releases/latest). Then extract S3-Client.zip to your preferred PowerShell Module location. For the current user to 
    
    $HOME\WindowsPowershell\Documents\WindowsPowerShell\Modules
    
For all users copy the folder to 

    C:\Windows\System32\WindowsPowerShell\v1.0\Modules
    
Update
------

If the Module was installed with `Install-Module`, it can be upgraded with

```powershell
Update-Module -Name S3-Client
```

If the Module was installed by downloading the ZIP file, then update the Module by replacing the S3-Client folder with the content of the new release ZIP file.

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