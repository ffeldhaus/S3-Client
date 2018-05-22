S3 Client Tutorial
==================

This S3 Client allows to run S3 Operations against any S3 endpoint, but it includes some shortcuts for [NetApp StorageGRID](https://netapp.com/storagegrid) users to handle S3 credentials.

If you are using the Cmdlets together with StorageGRID, proceed with the next section, otherwise skip to the [Configuration and Credential Management](#Configuration-and-Credential-Management)

## StorageGRID specific simplifications

If a StorageGRID administrator is connected, then the Cmdlets automatically create temporary AWS Access Key and Secret Access Key for all tenants where an operation is performed. If a StorageGRID tenant user is connected, the temporary S3 credentials will be automatically created for the tenant user. All temporary credentials have an expiry time of 60 minutes by default.

For grid administrators the Cmdlets automatically query the configured domain endpoints and check if connections via S3 are possible. The endpoints are then stored in the S3EndpointUrl parameter of the server object (e.g. `$CurrentSgwServer.S3EndpointUrl`). As the domain endpoints cannot be queried as tenant user, you must provide the `-S3EndpointUrl` parameter when connecting to the StorageGRID server or you can add the `-EndpointUrl` parameter when executing S3 commands.

```powershell
Connect-SgwServer -Name $Name -Credential $Credential -S3EndpointUrl "https://s3.example.org:8082"
```

Automatic Access Key generation can be disabled when connecting to the StorageGRID server with

```powershell
Connect-SgwServer -Name $Name -Credential $Credential -SkipCertificateCheck -DisableAutomaticAccessKeyGeneration
```

The default expiry time of 60 minutes for temporary access keys can be changed when connecting to the StorageGRID Server with

```powershell
Connect-SgwServer -Name $Name -Credential $Credential -SkipCertificateCheck -TemporaryAccessKeyExpirationTime 300
```

All newly created credentials including temporary credentials will be stored per Account ID in the AccessKeyStore of the server object. Check it out with e.g.

```powershell
$CurrentSgwServer.AccessKeyStore
```

The grid administrator must be able to create S3 credentials for individual tenant accounts. This is only possible if the StorageGRID Webscale API Version 1 is enabled. For new installations of StorageGRID 10.4 or later, this is disabled by default. You can enable API Version 1 as grid administrator with

```powershell
Update-SgwConfigManagement -MinApiVersion 1
```

## Configuration and Credential Management

The S3-Client Cmdlets use the AWS configuration files in the same way the AWS SDK or AWS CLI does. The available configuration options are defined in the [AWS CLI S3 Configuration](https://docs.aws.amazon.com/cli/latest/topic/s3-config.html) guide. Individual configuration can be specified using separate profiles. The S3-Client Module simplifies adding, modifying and retrieving the configuration by providing several AWS Cmdlets.

### Create a new Profile

To create a new profile, specify at least the `ProfileName`, `AccessKey` and `SecretKey`

```powershell
New-AwsProfile -ProfileName "Profile" -AccessKey "ABCDEFGHIJKLMNOPQRST" -SecretKey "abcdefghijklmnopqrst1234567890ABCDEFGHIJ"
```

### Update an existing Profile

An existing profile can be updated using `Update-AwsProfile`, which is an alias to `New-AwsProfile`. If the profile does not yet exist, it will be created.

```powershell
Update-AwsProfile -ProfileName "Profile" -EndpointUrl "https://s3.example.org"
```

### Retrieve all Profiles

To list all available profiles use

```powershell
Get-AwsProfiles
```

### Retrieve a single Profile

A single profile can be retrieved using

```powershell
Get-AwsProfile -ProfileName "Profile"
```

### Remove Profile

A profile can be removed using

```powershell
Remove-AwsProfile -ProfileName "Profile
```

## Bucket Cmdlets

As a StorageGRID administrator, listing buckets will return all buckets for all tenants by creating S3 credentials for every tenant and then listing their buckets. For StorageGRID tenant users, only the buckets of the individual tenant will be listed. For all other S3 services, only the Buckets of the current user will be listed.

```powershell
Get-S3Buckets
```

StorageGRID Administrators can list all buckets of an individual StorageGRID tenant by using the tenant account ID:

```powershell
Get-S3Buckets -AccountId $AccountId
```

or

```powershell
$Account = Get-SgwAccount -Tenant "MyTenant"
$Account | Get-S3Buckets
```

A new Bucket can be created with

```powershell
New-S3Bucket -BucketName "MyBucket"
```

A StorageGRID administrator needs to specify for which tenant the bucket should be created either by specifying the Account ID

```powershell
New-S3Bucket -BucketName "MyBucket" -AccountId $AccountId
```

or by retrieving an Account Object via e.g.

```powershell
$Account = Get-SgwAccount -Tenant "MyTenant"
$Account | New-S3Bucket -BucketName "MyBucket"
```

There are some StorageGRID specific S3 calls which are only supported by StorageGRID.

StorageGRID since 10.3 disables last access time updates if an object is retrieved as this causes a lot of updates on the Metadata databases and may cause slower response times if many objects are retrieved per second.

The following Cmdlet checks if the last access time update is enabled for a bucket

```powershell
Get-S3BucketLastAccessTime -BucketName "MyBucket"
```

Updating the last access time for each object can be enabled per bucket with

```powershell
Enable-S3BucketLastAccessTime -BucketName "MyBucket"
```

It can be disabled with

```powershell
Disable-S3BucketLastAccessTime -BucketName "MyBucket"
```

StorageGRID supports different consistency settings for Buckets, which impact availability or integrity of the data. The consistency setting can be retrieved per Bucket with

```powershell
Get-S3BucketConsistency -BucketName "MyBucket"
```

The consistency setting can be changed per Bucket with e.g.

```powershell
Update-S3BucketConsistency -BucketName "MyBucket" -Consistency available
```

## Objects

Objects in a bucket can be listed with

```powershell
Get-S3Objects -BucketName "MyBucket"
```

Uploading objects can be done with the `Write-S3Object` for objects smaller 5GB. To improve performance and to upload files larger than 5GB up to 5TB, use `Write-S3MultipartUpload` which uploads several parts in parallel.

Simple file upload

```powershell
Write-S3Object -BucketName "MyBucket" -InFile "$HOME\test"
```

Multipart File upload

```powershell
Write-S3MultipartUpload -BucketName "MyBucket"
```

Downloading objects can be done with

```powershell
Read-S3Object -BucketName "MyBucket" -Key "test" -OutFile "$HOME\test"
```

## Platform Services

### CloudMirror - Bucket Replication

Connected as a grid administrator, create a new tenant which is has S3 capabilities and is allowed to use platform services

```powershell
$Credential = Get-Credential -UserName "root"
$Account = New-SgwAccount -Name "platformservices" -Capabilities "s3","management" -Password $Credential.GetNetworkCredential().Password -AllowPlatformServices $true
```

Connect as tenant root user

```powershell
$Account | Connect-SgwServer -Name $Name -Credential $Credential
```

Create a bucket on StorageGRID to be mirrored to AWS. It is best practice to start bucket names with a random prefix

```powershell
$RandomPrefix = -join ((97..122) | Get-Random -Count 8 | % {[char]$_})
$SourceBucket = "$RandomPrefix-replication-source"
New-S3Bucket -Name $SourceBucket
Get-S3Buckets
```

To create a bucket on AWS the AWS credentials are required. If there is no AWS Profile yet, create a new profile configuration and add AWS Credentials retrieved from AWS IAM and a preferred region with
```powershell
Add-AwsConfig -Profile "AWS" -AccessKey "REPLACEME" -SecretAccessKey "REPLACEME" -Region "us-east-1"
```

Create the destination bucket on AWS using the AWS Profile

```powershell
$RandomPrefix = -join ((97..122) | Get-Random -Count 8 | % {[char]$_})
$DestinationBucket = "$RandomPrefix-replication-destination"
New-S3Bucket -Name $DestinationBucket -Profile "AWS"
Get-S3Buckets -Profile "AWS"
```

Configure the AWS destination bucket as Endpoint in StorageGRID

```powershell
Add-SgwS3Endpoint -DisplayName "AWS S3 endpoint" -BucketName $DestinationBucket -Profile "AWS"
```

Add a bucket replication rule which defines which source bucket (on StorageGRID) should be replicated to which destination bucket (on AWS)

```powershell
Add-SgwBucketReplicationRule -BucketName $SourceBucket -DestinationBucket $DestinationBucket -Id "AWS Replication of bucket $SourceBucket"
```

Write an object to the source bucket on StorageGRID

```powershell
$Key = "testobject"
$Content = "Hello World!"
Write-S3Object -BucketName $SourceBucket -Key $Key -Content $Content
```

Read the object from the source bucket

```powershell
Read-S3Object -BucketName $SourceBucket -Key $Key
```

Read the object from the destination bucket (you can add `-verbose` to verify that the REST call is indeed sent to AWS)

```powershell
Read-S3Object -BucketName $DestinationBucket -Key $Key -Profile "AWS"
```

## Creating AWS Signatures

To learn more about the AWS signing process, these Cmdlets can output helpful information in verbose and debug mode.

### Version 2

To see the detailed signing steps of the AWS V2 signing process, as shown in the examples of [Signing and Authenticating REST Requests](https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html) run

```powershell
$VerbosePreference = "Continue"
$DebugPreference = "Continue"
# Examples from
$AccessKey = "AKIAIOSFODNN7EXAMPLE"
$SecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
# Object GET
$Signature = New-AwsSignatureV2 -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -EndpointUrl "johnsmith.s3.amazonaws.com" -HTTPRequestMethod "GET" -DateTime "Tue, 27 Mar 2007 19:36:42 +0000" -BucketName "johnsmith" -Uri "/photos/puppy.jpg"
$Signature -eq "bWq2s1WEIj+Ydj0vQ697zp+IXMU="
# Object GET
$Signature = New-AwsSignatureV2 -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -EndpointUrl "johnsmith.s3.amazonaws.com" -HTTPRequestMethod "PUT" -DateTime "Tue, 27 Mar 2007 21:15:45 +0000" -BucketName "johnsmith" -Uri "/photos/puppy.jpg" -ContentType "image/jpeg"
$Signature -eq "MyyxeRY7whkBe+bq8fHCL/2kKUg="
# List
$Signature = New-AwsSignatureV2 -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -EndpointUrl "johnsmith.s3.amazonaws.com" -HTTPRequestMethod "GET" -DateTime "Tue, 27 Mar 2007 19:42:41 +0000" -BucketName "johnsmith"
$Signature -eq "htDYFYduRNen8P9ZfE/s9SuKy0U="
# Fetch
$Signature = New-AwsSignatureV2 -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -EndpointUrl "johnsmith.s3.amazonaws.com" -HTTPRequestMethod "GET" -DateTime "Tue, 27 Mar 2007 19:44:46 +0000" -BucketName "johnsmith" -QueryString "?acl"
$Signature -eq "c2WLPFtWHVgbEmeEG93a4cG37dM="
# Delete
$Signature = New-AwsSignatureV2 -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -EndpointUrl "s3.amazonaws.com" -HTTPRequestMethod "DELETE" -DateTime "Tue, 27 Mar 2007 21:20:26 +0000" -BucketName "johnsmith" -Uri "/johnsmith/photos/puppy.jpg"
$Signature -eq "$Signature -eq "
# Upload
$Signature = New-AwsSignatureV2 -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -EndpointUrl "static.johnsmith.net" -HTTPRequestMethod "PUT" -DateTime "Tue, 27 Mar 2007 21:06:08 +0000" -BucketName "static.johnsmith.net" -Uri "/db-backup.dat.gz" -ContentType "application/x-download" -ContentMD5 "4gJE4saaMU4BqNR0kLY+lw==" -Headers @{"x-amz-acl"="public-read";"content-type"="application/x-download";"Content-MD5"="4gJE4saaMU4BqNR0kLY+lw==";"X-Amz-Meta-ReviewedBy"="joe@johnsmith.net,jane@johnsmith.net";"X-Amz-Meta-FileChecksum"="0x02661779";"X-Amz-Meta-ChecksumAlgorithm"="crc32";"Content-Disposition"="attachment; filename=database.dat";"Content-Encoding"="gzip";"Content-Length"="5913339"}
$Signature -eq "ilyl83RwaSoYIEdixDQcA4OnAnc="
# List All My Buckets
$Signature = New-AwsSignatureV2 -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -EndpointUrl "s3.amazonaws.com" -HTTPRequestMethod "GET" -DateTime "Wed, 28 Mar 2007 01:29:59 +0000"
$Signature -eq "qGdzdERIC03wnaRNKh6OqZehG9s="
# Unicode Keys
$Signature = New-AwsSignatureV2 -AccessKey $AccessKey -SecretAccessKey $SecretAccessKey -EndpointUrl "s3.amazonaws.com" -HTTPRequestMethod "GET" -DateTime "Wed, 28 Mar 2007 01:49:49 +0000" -Uri "/dictionary/fran%C3%A7ais/pr%c3%a9f%c3%a8re"
$Signature -eq "qGdzdERIC03wnaRNKh6OqZehG9s="
$VerbosePreference = "SilentlyContinue"
$DebugPreference = "SilentlyContinue"
```

### Version 4

To see the detailed signing steps of the AWS V4 signing process, as shown in the examples of [Authenticating Requests: Using Query Parameters (AWS Signature Version 4)](http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html) run

```powershell
$VerbosePreference = "Continue"
$DebugPreference = "Continue"
New-AwsSignatureV4 -AccessKey "test" -SecretAccessKey "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY" -EndpointUrl "iam.amazonaws.com" -HTTPRequestMethod GET -Uri '/' -Query @{Action="ListUsers";Version="2010-05-08"} -ContentType "application/x-www-form-urlencoded; charset=utf-8" -DateTime "20150830T123600Z" -DateString "20150830" -Service "iam"
$VerbosePreference = "SilentlyContinue"
$DebugPreference = "SilentlyContinue"
```