PARAM(
    [Parameter(Mandatory=$false)][string]$ProfileName
)

Import-Module "$PSScriptRoot\S3-Client" -Force

# suppress warnings which occur e.g. for uppercase bucketnames
$WarningPreference="SilentlyContinue"

$BucketName = (Get-Date -Format "yyyy-MM-dd-HHmmss") + "-Bucket"
$UnicodeBucketName = [System.Globalization.IdnMapping]::new().GetUnicode("xn--9csy79e60h") + "-$BucketName"
$Key = "Key"
$UnicodeKey = [System.Globalization.IdnMapping]::new().GetUnicode("xn--9csy79e60h") + "-$Key"
$Content = "Hello World!"
$CustomMetadata = @{"MetadataKey"="MetadataValue"}

if (!$ProfileName) {
    Write-Warning "No Profilename specified for this test, falling back to default"
    $ProfileName = "default"
}

Write-Host "Running S3 Client tests for profile $ProfileName"

# create temporary small file
$SmallFileSize = 1MB
$SmallFile = New-TemporaryFile
# Note: block size must be a factor of 1MB to avoid rounding errors :)
$BlockSize = 8KB
$ByteBuffer = [Byte[]]::new($BlockSize)
$Random = [System.Random]::new()
$Stream = [System.IO.FileStream]::new($SmallFile, [System.IO.FileMode]::Open)
for ($i = 0; $i -lt ($SmallFileSize / $BlockSize); $i++) {
    $Random.NextBytes($ByteBuffer)
    $Stream.Write($ByteBuffer, 0, $ByteBuffer.Length)
}
$Stream.Close()
$Stream.Dispose()
$SmallFileHash = $SmallFile | Get-FileHash

# create temporary large file
$LargeFileSize = 6MB
$LargeFile = New-TemporaryFile
# Note: block size must be a factor of 1MB to avoid rounding errors :)
$BlockSize = 8KB
$ByteBuffer = [Byte[]]::new($BlockSize)
$Random = [System.Random]::new()
$Stream = [System.IO.FileStream]::new($LargeFile, [System.IO.FileMode]::Open)
for ($i = 0; $i -lt ($LargeFileSize / $BlockSize); $i++) {
    $Random.NextBytes($ByteBuffer)
    $Stream.Write($ByteBuffer, 0, $ByteBuffer.Length)
}
$Stream.Close()
$Stream.Dispose()
$LargeFileHash = $LargeFile | Get-FileHash

function Setup() {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory=$True,
                Position=0,
                HelpMessage="Bucket Name")][String]$BucketName,
        [parameter(
                Mandatory=$False,
                Position=1,
                HelpMessage="Enable versioning on Bucket")][Switch]$Versioning,
        [parameter(
                Mandatory=$False,
                Position=2,
                HelpMessage="Bucket Region")][String]$Region=$null,
        [parameter(
                Mandatory=$False,
                Position=3,
                HelpMessage="Object Key")][String]$Key,
        [parameter(
                Mandatory=$False,
                Position=2,
                HelpMessage="Bucket Region")][String]$ProfileName=$ProfileName
    )

    New-S3Bucket -ProfileName $ProfileName -BucketName $BucketName -Region $Region
    foreach ($i in 1..60) {
        sleep 1
        if (Test-S3Bucket -ProfileName $ProfileName -BucketName $BucketName -Region $Region) {
            break
        }
    }

    if ($Versioning.IsPresent) {
        Enable-S3BucketVersioning -ProfileName $ProfileName -BucketName $BucketName -Region $Region
    }

    if ($Key) {
        Write-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $Key -Region $Region
    }
}

function Cleanup() {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory=$True,
                Position=0,
                HelpMessage="Bucket Name")][String]$BucketName,
        [parameter(
                Mandatory=$False,
                Position=1,
                HelpMessage="Bucket Region")][String]$Region=$null,
        [parameter(
                Mandatory=$False,
                Position=2,
                HelpMessage="Bucket Region")][String]$ProfileName=$ProfileName
    )

    try {
        Remove-S3Bucket -ProfileName $ProfileName -BucketName $BucketName -Region $Region -Force
        # wait until bucket is really deleted
        foreach ($i in 1..60) {
            sleep 1
            if (!(Test-S3Bucket -ProfileName $ProfileName -BucketName $BucketName -Region $Region)) {
                sleep 1
                break
            }
        }
    }
    catch {}
}

Describe "AWS Configuration and Credential Management" {
    Context "Add a new Profile" {
        $ProfileName = "test"
        $AccessKey = "ABCDEFGHIJKLMNOPQRST"
        $SecretKey = "abcdefghijklmnopqrst1234567890ABCDEFGHIJ"
        $Region = "eu-central-1"
        $EndpointUrl = "https://s3.example.org"
        $MaxConcurrentRequest = 1234
        $MultipartThreshold = "256MB"
        $MultipartChunksize = "128MB"
        $MaxBandwidth = "10MB/s"
        $UseAccelerateEndpoint = $true
        $UseDualstackEndpoint = $false
        $AddressingStyle = "path"
        $PayloadSigningEnabled = $true

        It "Given -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -Region $Region -EndpointUrl $EndpointUrl -MaxConcurrentRequests $MaxConcurrentRequest -MultipartThreshold $MultipartThreshold -MultipartChunksize $MultipartChunksize -MaxBandwidth $MaxBandwidth -UseAccelerateEndpoint $UseAccelerateEndpoint -UseDualstackEndpoint $UseDualstackEndpoint -AddressingStyle $AddressingStyle -PayloadSigningEnabled $PayloadSigningEnabled" {
            New-AwsConfig -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -Region $Region -EndpointUrl $EndpointUrl -MaxConcurrentRequests $MaxConcurrentRequest -MultipartThreshold $MultipartThreshold -MultipartChunksize $MultipartChunksize -MaxBandwidth $MaxBandwidth -UseAccelerateEndpoint $UseAccelerateEndpoint -UseDualstackEndpoint $UseDualstackEndpoint -AddressingStyle $AddressingStyle -PayloadSigningEnabled $PayloadSigningEnabled
            $Config = Get-AwsConfig -ProfileName $ProfileName
            $Config.ProfileName | Should -Be $ProfileName
            $Config.AccessKey | Should -Be $AccessKey
            $Config.SecretKey | Should -Be $SecretKey
            $Config.Region | Should -Be $Region
            $Config.EndpointUrl | Should -Be $EndpointUrl
            $Config.MaxConcurrentRequests | Should -Be $MaxConcurrentRequest
            $Config.MultipartThreshold  | Should -Be $MultipartThreshold
            $Config.MultipartChunksize  | Should -Be $MultipartChunksize
            $Config.MaxBandwidth  | Should -Be $MaxBandwidth
            $Config.UseAccelerateEndpoint  | Should -Be $UseAccelerateEndpoint
            $Config.UseDualstackEndpoint  | Should -Be $UseDualstackEndpoint
            $Config.AddressingStyle  | Should -Be $AddressingStyle
            $Config.PayloadSigningEnabled  | Should -Be $PayloadSigningEnabled
        }

        It "Remove -ProfileName $ProfileName" {
            New-AwsConfig -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey
            $Config = Get-AwsConfig -ProfileName $ProfileName
            $Config.ProfileName | Should -Be $ProfileName
            Remove-AwsConfig -ProfileName $ProfileName
            $Config = Get-AwsConfig -ProfileName $ProfileName
            $Config | Should -BeNullOrEmpty
        }
    }
}

Describe "Get-S3Buckets" {
    Setup -BucketName $BucketName
    Setup -BucketName $UnicodeBucketName

    Context "Retrieve buckets with default parameters" {
        It "Retrieving buckets returns a list of all buckets" {
            $Buckets = Get-S3Buckets -ProfileName $ProfileName
            $Buckets.BucketName | Should -Contain $BucketName
            $Buckets.BucketName | Should -Contain $UnicodeBucketName
        }
    }

    Context "Retrieve buckets with parameter -BucketName" {
        It "Retrieving a specific, existing bucket with parameter -BucketName $BucketName returns only that bucket" {
            $Bucket = Get-S3Buckets -ProfileName $ProfileName -BucketName $BucketName
            $Bucket.BucketName | Should -Be $BucketName
        }

        It "Retrieving a specific, existing bucket with parameter -BucketName $UnicodeBucketName returns only that bucket" {
            $Bucket = Get-S3Buckets -ProfileName $ProfileName -BucketName $UnicodeBucketName
            $Bucket.BucketName | Should -Be $UnicodeBucketName
        }
    }

    Cleanup -BucketName $BucketName
    Cleanup -BucketName $UnicodeBucketName
}

Describe "Test-S3Bucket" {
    Setup -BucketName $BucketName
    Setup -BucketName $UnicodeBucketName

    Context "Test bucket existence with parameter -BucketName" {
        It "Given existing bucket -BucketName $BucketName `$true is returned" {
            Test-S3Bucket -ProfileName $ProfileName -BucketName $BucketName | Should -BeTrue
        }

        It "Given existing bucket -BucketName $UnicodeBucketName `$true is returned" {
            Test-S3Bucket -ProfileName $ProfileName -BucketName $UnicodeBucketName | Should -BeTrue
        }
    }

    Context "Test bucket nonexistence with parameter -BucketName" {
        It "Given non existing bucket -BucketName non-existing-bucket `$false is returned" {
            Test-S3Bucket -ProfileName $ProfileName -BucketName non-existing-bucket | Should -BeFalse
        }
    }

    Cleanup -BucketName $BucketName
    Cleanup -BucketName $UnicodeBucketName
}

Describe "New-S3Bucket" {
    Context "Create new bucket with default parameters" {
        It "Given -BucketName $BucketName it is succesfully created" {
            New-S3Bucket -ProfileName $ProfileName -BucketName $BucketName
            foreach ($i in 1..60) {
                sleep 1
                if (Test-S3Bucket -ProfileName $ProfileName -BucketName $BucketName) {
                    break
                }
            }
            $NewBucket = Get-S3Buckets -ProfileName $ProfileName -BucketName $BucketName
            $NewBucket.BucketName | Should -Be $BucketName
        }

        It "Given -BucketName $UnicodeBucketName it is succesfully created" {
            New-S3Bucket -ProfileName $ProfileName -BucketName $UnicodeBucketName
            foreach ($i in 1..60) {
                sleep 1
                if (Test-S3Bucket -ProfileName $ProfileName -BucketName $UnicodeBucketName) {
                    break
                }
            }
            $NewBucket = Get-S3Buckets -ProfileName $ProfileName -BucketName $UnicodeBucketName
            $NewBucket.BucketName | Should -Be $UnicodeBucketName
        }
    }

    Cleanup -BucketName $BucketName
    Cleanup -BucketName $UnicodeBucketName

    Context "Create new bucket with parameter -UrlStyle virtual-hosted" {
        if ($ProfileName -eq "Minio") { continue }

        It "Given -BucketName $BucketName and -UrlStyle virtual-hosted it is succesfully created" {
            New-S3Bucket -ProfileName $ProfileName -BucketName $BucketName -UrlStyle virtual-hosted
            foreach ($i in 1..60) {
                sleep 1
                if (Test-S3Bucket -ProfileName $ProfileName -BucketName $BucketName  -UrlStyle virtual-hosted) {
                    break
                }
            }
            $NewBucket = Get-S3Buckets -ProfileName $ProfileName -BucketName $BucketName
            $NewBucket.BucketName | Should -Be $BucketName
            Remove-S3Bucket -ProfileName $ProfileName -BucketName $BucketName -Force  -UrlStyle virtual-hosted
        }
    }

    Cleanup -BucketName $BucketName
}

Describe "Remove-S3Bucket" {
    Setup -BucketName $BucketName
    Setup -BucketName $UnicodeBucketName

    Context "Remove bucket with default parameters" {
        It "Given existing -BucketName $BucketName it is succesfully removed" {
            Remove-S3Bucket -ProfileName $ProfileName -BucketName $BucketName -Force
            $Bucket = Get-S3Buckets -ProfileName $ProfileName -BucketName $BucketName
            $Bucket | Should -BeNullOrEmpty
        }
    }

    Context "Remove bucket with default parameters" {
        It "Given existing -BucketName $UnicodeBucketName it is succesfully removed" {
            Remove-S3Bucket -ProfileName $ProfileName -BucketName $UnicodeBucketName -Force
            $Bucket = Get-S3Buckets -ProfileName $ProfileName -BucketName $UnicodeBucketName
            $Bucket | Should -BeNullOrEmpty
        }
    }

    Cleanup -BucketName $BucketName
    Cleanup -BucketName $UnicodeBucketName
}

Describe "Write-S3Object" {
    Setup -BucketName $BucketName
    Setup -BucketName $UnicodeBucketName

    Context "Upload text" {
        It "Given -Content `"$Content`" it is succesfully created" {
            Write-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $Key -Content $Content
            $Objects = Get-S3Objects -ProfileName $ProfileName -BucketName $BucketName
            $Key | Should -BeIn $Objects.Key
            $ObjectContent = Read-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $Key
            $ObjectContent | Should -Be $Content
        }
    }

    Context "Upload text to object with key containing unicode characters" {
        if ($ProfileName -eq "Minio") { continue }

        It "Given -Content `"$Content`" it is succesfully created" {
            Write-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $UnicodeKey -Content $Content
            $Objects = Get-S3Objects -ProfileName $ProfileName -BucketName $BucketName -Key $UnicodeKey
            $UnicodeKey | Should -BeIn $Objects.Key
            $ObjectContent = Read-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $UnicodeKey
            $ObjectContent | Should -Be $Content
        }
    }

    Context "Upload small file" {
        It "Given file -InFile `"$SmallFile`" it is succesfully uploaded" {
            Write-S3Object -ProfileName $ProfileName -BucketName $BucketName -InFile $SmallFile
            $Objects = Get-S3Objects -ProfileName $ProfileName -BucketName $BucketName
            $SmallFile.Name | Should -BeIn $Objects.Key
            $TempFile = New-TemporaryFile
            sleep 1
            Read-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $SmallFile.Name -OutFile $TempFile.FullName
            $TempFileHash = $TempFile | Get-FileHash
            $TempFileHash.Hash | Should -Be $SmallFileHash.Hash
            $TempFile | Remove-Item
        }
    }

    Cleanup -BucketName $BucketName
    Cleanup -BucketName $UnicodeBucketName
}

Describe "Write-S3MultipartUpload" {

    Context "Upload large file" {
        Setup -BucketName $BucketName

        It "Given file -InFile `"$LargeFile`" it is succesfully uploaded to Bucket $BucketName" {
            Write-S3MultipartUpload -ProfileName $ProfileName -BucketName $BucketName -InFile $LargeFile
            $Objects = Get-S3Objects -ProfileName $ProfileName -BucketName $BucketName
            $LargeFile.Name | Should -BeIn $Objects.Key
            $TempFile = New-TemporaryFile
            sleep 1
            Read-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $LargeFile.Name -OutFile $TempFile.FullName
            $TempFileHash = $TempFile | Get-FileHash
            $TempFileHash.Hash | Should -Be $LargeFileHash.Hash
            $TempFile | Remove-Item
        }

        Cleanup -BucketName $BucketName

        Setup -BucketName $UnicodeBucketName

        It "Given file -InFile `"$LargeFile`" it is succesfully uploaded to Bucket $UnicodeBucketName" {
            Write-S3MultipartUpload -ProfileName $ProfileName -BucketName $UnicodeBucketName -InFile $LargeFile
            $Objects = Get-S3Objects -ProfileName $ProfileName -BucketName $UnicodeBucketName
            $LargeFile.Name | Should -BeIn $Objects.Key
            $TempFile = New-TemporaryFile
            sleep 1
            Read-S3Object -ProfileName $ProfileName -BucketName $UnicodeBucketName -Key $LargeFile.Name -OutFile $TempFile.FullName
            $TempFileHash = $TempFile | Get-FileHash
            $TempFileHash.Hash | Should -Be $LargeFileHash.Hash
            $TempFile | Remove-Item
        }

        Cleanup -BucketName $UnicodeBucketName
    }
}

Describe "Copy-S3Object" {
    Setup -BucketName $BucketName -Key $Key

    Context "Copy object" {
        It "Given -SourceBucket $BucketName and -SourceKey $Key and -BucketName $BucketName and -Key $Key it is copied to itself" {
            $CustomMetadata = Get-S3ObjectMetadata -ProfileName $ProfileName -BucketName $BucketName -Key $Key | Select-Object -ExpandProperty CustomMetadata
            $CustomMetadata["copytest"]="test"
            Copy-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $Key -SourceBucket $BucketName -SourceKey $Key -MetadataDirective "REPLACE" -Metadata $CustomMetadata
            sleep 1
            $CustomMetadata = Get-S3ObjectMetadata -ProfileName $ProfileName -BucketName $BucketName -Key $Key | Select-Object -ExpandProperty CustomMetadata
            $CustomMetadata["copytest"] | Should -Be "test"
        }
    }

    Cleanup -BucketName $BucketName
}

Describe "S3BucketEncryption" {
    if ($ProfileName -eq "webscaledemo") { continue }
    if ($ProfileName -eq "webscaledemonext") { continue }
    if ($ProfileName -eq "Minio") { continue }

    Setup -BucketName $BucketName
    Setup -BucketName $UnicodeBucketName

    Context "Set Bucket encryption" {
        It "Given -BucketName $BucketName and -SSEAlgorithm AES256 server side encryption is enabled" {
            Set-S3BucketEncryption -ProfileName $ProfileName -BucketName $BucketName -SSEAlgorithm AES256
            sleep 15
            $BucketEncryption = Get-S3BucketEncryption -ProfileName $ProfileName -BucketName $BucketName
            $BucketEncryption.SSEAlgorithm | Should -Be "AES256"
            Remove-S3BucketEncryption -ProfileName $ProfileName -BucketName $BucketName
            sleep 15
            $BucketEncryption = Get-S3BucketEncryption -ProfileName $ProfileName -BucketName $BucketName
            $BucketEncryption | Should -BeNullOrEmpty
        }

        It "Given -BucketName $UnicodeBucketName and -SSEAlgorithm AES256 server side encryption is enabled" {
            Set-S3BucketEncryption -ProfileName $ProfileName -BucketName $UnicodeBucketName -SSEAlgorithm AES256
            sleep 15
            $BucketEncryption = Get-S3BucketEncryption -ProfileName $ProfileName -BucketName $UnicodeBucketName
            $BucketEncryption.SSEAlgorithm | Should -Be "AES256"
            Remove-S3BucketEncryption -ProfileName $ProfileName -BucketName $UnicodeBucketName
            sleep 15
            $BucketEncryption = Get-S3BucketEncryption -ProfileName $ProfileName -BucketName $UnicodeBucketName
            $BucketEncryption | Should -BeNullOrEmpty
        }
    }

    Cleanup -BucketName $BucketName
    Cleanup -BucketName $UnicodeBucketName
}

Describe "S3 Bucket Tagging" {
    if ($ProfileName -eq "webscaledemo") { continue }
    if ($ProfileName -eq "webscaledemonext") { continue }
    if ($ProfileName -eq "Minio") { continue }

    $Tags = @(@{Name="Key1";Value="Value1"},@{Name="Key2";Value="Value2"})

    Setup -BucketName $BucketName
    Setup -BucketName $UnicodeBucketName

    Context "Set Bucket tagging" {
        It "Given -BucketName $BucketName and -Tags $(ConvertTo-Json -InputObject $Tags -Compress) tags should be added to bucket" {
            Set-S3BucketTagging -ProfileName $ProfileName -BucketName $BucketName -Tags $Tags
            sleep 3
            $BucketTagging = Get-S3BucketTagging -ProfileName $ProfileName -BucketName $BucketName
            $BucketTagging | Sort-Object -Property Name | Select-Object -First 1 | Should -Be ([System.Collections.DictionaryEntry]$Tags[0])
            $BucketTagging | Sort-Object -Property Name | Select-Object -Last 1 | Should -Be ([System.Collections.DictionaryEntry]$Tags[1])
        }

        It "Given -BucketName $UnicodeBucketName and -Tags $(ConvertTo-Json -InputObject $Tags -Compress) tags should be added to bucket" {
            Set-S3BucketTagging -ProfileName $ProfileName -BucketName $UnicodeBucketName -Tags $Tags
            sleep 3
            $BucketTagging = Get-S3BucketTagging -ProfileName $ProfileName -BucketName $UnicodeBucketName
            $BucketTagging | Sort-Object -Property Name | Select-Object -First 1 | Should -Be ([System.Collections.DictionaryEntry]$Tags[0])
            $BucketTagging | Sort-Object -Property Name | Select-Object -Last 1 | Should -Be ([System.Collections.DictionaryEntry]$Tags[1])
        }
    }

    Cleanup -BucketName $BucketName
    Cleanup -BucketName $UnicodeBucketName
}

Describe "S3 Object Tagging" {
    #if ($ProfileName -eq "webscaledemo") { continue }
    #if ($ProfileName -eq "webscaledemonext") { continue }
    if ($ProfileName -eq "Minio") { continue }

    $Tags = @(@{Name="Key1";Value="Value1"},@{Name="Key2";Value="Value2"})

    Context "Set Object tagging" {
        Setup -BucketName $BucketName -Key $Key
        It "Given -BucketName $BucketName -Key $Key and -Tags $Tags tags should be added to bucket" {
            Set-S3ObjectTagging -ProfileName $ProfileName -BucketName $BucketName -Key $Key -Tags $Tags
            sleep 3
            $ObjectTagging = Get-S3ObjectTagging -ProfileName $ProfileName -BucketName $BucketName -Key $Key
            $ObjectTagging | Sort-Object -Property Name | Select-Object -First 1 | Should -Be ([System.Collections.DictionaryEntry]$Tags[0])
            $ObjectTagging | Sort-Object -Property Name | Select-Object -Last 1 | Should -Be ([System.Collections.DictionaryEntry]$Tags[1])
        }
        Cleanup -BucketName $BucketName

        Setup -BucketName $UnicodeBucketName -Key $Key
        It "Given -BucketName $UnicodeBucketName -Key $Key and -Tags $Tags tags should be added to bucket" {
            Set-S3ObjectTagging -ProfileName $ProfileName -BucketName $UnicodeBucketName -Key $Key -Tags $Tags
            sleep 3
            $ObjectTagging = Get-S3ObjectTagging -ProfileName $ProfileName -BucketName $UnicodeBucketName -Key $Key
            $ObjectTagging | Sort-Object -Property Name | Select-Object -First 1 | Should -Be ([System.Collections.DictionaryEntry]$Tags[0])
            $ObjectTagging | Sort-Object -Property Name | Select-Object -Last 1 | Should -Be ([System.Collections.DictionaryEntry]$Tags[1])
        }
        Cleanup -BucketName $UnicodeBucketName
    }
}

Describe "S3BucketCorsConfiguration" {
    if ($ProfileName -eq "webscaledemo") { continue }
    if ($ProfileName -eq "Minio") { continue }

    $AllowedMethods = "GET","PUT","POST","DELETE"
    $AllowedOrigins = "netapp.com","*.example.org"
    $AllowedHeaders = "x-amz-meta-1","x-amz-meta-2"
    $MaxAgeSeconds = 3000
    $ExposeHeaders = "x-amz-server-side-encryption"

    Setup -BucketName $BucketName
    Setup -BucketName $UnicodeBucketName

    Context "Set Bucket CORS Configuration" {
        It "Given -BucketName $BucketName -Id $BucketName -AllowedMethods $AllowedMethods -AllowedOrigins $AllowedOrigins -AllowedHeaders $AllowedHeaders -MaxAgeSeconds $MaxAgeSeconds -ExposeHeaders $ExposeHeaders a CORS Configuration rule is added" {
            $Id = "BucketName"
            Add-S3BucketCorsConfigurationRule -ProfileName $ProfileName -BucketName $BucketName -Id $Id -AllowedMethods $AllowedMethods -AllowedOrigins $AllowedOrigins -AllowedHeaders $AllowedHeaders -MaxAgeSeconds $MaxAgeSeconds -ExposeHeaders $ExposeHeaders
            sleep 5
            $CorsConfiguration = Get-S3BucketCorsConfiguration -ProfileName $ProfileName -BucketName $BucketName
            $CorsConfiguration.Id | Should -Be $Id
            $CorsConfiguration.AllowedMethod | Should -Be $AllowedMethods
            $CorsConfiguration.AllowedOrigin | Should -Be $AllowedOrigins
            $CorsConfiguration.AllowedHeader | Should -Be $AllowedHeaders
            $CorsConfiguration.MaxAgeSeconds | Should -Be $MaxAgeSeconds
            $CorsConfiguration.ExposeHeader | Should -Be $ExposeHeaders
        }

        It "Given -BucketName $UnicodeBucketName -Id $UnicodeBucketName -AllowedMethods $AllowedMethods -AllowedOrigins $AllowedOrigins a CORS configuration rule is added" {
            $Id = "UnicodeBucketName"
            Add-S3BucketCorsConfigurationRule -ProfileName $ProfileName -BucketName $UnicodeBucketName -Id $Id -AllowedMethods $AllowedMethods -AllowedOrigins $AllowedOrigins
            sleep 5
            $CorsConfiguration = Get-S3BucketCorsConfiguration -ProfileName $ProfileName -BucketName $UnicodeBucketName
            $CorsConfiguration.Id | Should -Be $Id
            $CorsConfiguration.AllowedMethod | Should -Be $AllowedMethods
            $CorsConfiguration.AllowedOrigin | Should -Be $AllowedOrigins
        }

        It "Given -BucketName $BucketName -Id `"remove`" a CORS configuration rule is removed" {
            $Id = "Remove"
            Add-S3BucketCorsConfigurationRule -ProfileName $ProfileName -BucketName $BucketName -Id $Id -AllowedMethods $AllowedMethods -AllowedOrigins $AllowedOrigins
            sleep 5
            $CorsConfigurationRule = Get-S3BucketCorsConfigurationRule -ProfileName $ProfileName -BucketName $BucketName -Id $Id
            $CorsConfigurationRule.Id | Should -Be $Id
            $CorsConfigurationRule | Remove-S3BucketCorsConfigurationRule -ProfileName $ProfileName
            sleep 5
            $CorsConfigurationRule = Get-S3BucketCorsConfigurationRule -ProfileName $ProfileName -BucketName $BucketName -Id $Id
            $CorsConfigurationRule | Should -BeNullOrEmpty
        }

        It "Given -BucketName $BucketName all CORS configuration is removed" {
            $Id = "RemoveAll"
            Add-S3BucketCorsConfigurationRule -ProfileName $ProfileName -BucketName $BucketName -Id $Id -AllowedMethods $AllowedMethods -AllowedOrigins $AllowedOrigins
            sleep 5
            $CorsConfigurationRule = Get-S3BucketCorsConfigurationRule -ProfileName $ProfileName -BucketName $BucketName -Id $Id
            $CorsConfigurationRule.Id | Should -Be $Id
            Remove-S3BucketCorsConfiguration -ProfileName $ProfileName -BucketName $BucketName
            sleep 5
            $CorsConfiguration = Get-S3BucketCorsConfiguration -ProfileName $ProfileName -BucketName $BucketName
            $CorsConfiguration | Should -BeNullOrEmpty
        }
    }

    Cleanup -BucketName $BucketName
    Cleanup -BucketName $UnicodeBucketName
}

Describe "S3 Bucket Replication Configuration" {
    $DestinationBucketName = $BucketName + "-dst"
    $DestinationUnicodeBucketName = $UnicodeBucketName +  "-dst"
    $DestinationRegion = "us-east-2"
    $AwsProfile = Get-AwsConfig -ProfileName "AWS"
    $Role = "arn:aws:iam::953312134057:role/S3-Full-Access"

    # for AWS several steps must be done to prepare the user to be able to use replication
        # see https://docs.aws.amazon.com/AmazonS3/latest/dev/crr.html

    #if ($ProfileName -eq "Minio") { continue }


    Setup -BucketName $BucketName -Versioning
    Setup -BucketName $DestinationBucketName -Versioning -Region $DestinationRegion -ProfileName AWS

    if ($ProfileName -match "webscaledemo") {
        $EndpointConfiguration = Add-SgwEndpoint -ProfileName $ProfileName -DisplayName $DestinationBucketName -EndpointUri "https://s3.us-east-2.amazonaws.com" -EndpointUrn "arn:aws:s3:::$DestinationBucketName" -AccessKey $AwsProfile.AccessKey -SecretAccessKey $AwsProfile.SecretKey -ErrorAction Stop
        sleep 5
    }

    Context "Set Bucket Replication Configuration" {
        It "Given -BucketName $BucketName -Id $BucketName -DestinationBucketUrn arn:aws:s3:::$DestinationBucketName -Role $Role a replication rule should be added" {
            Add-S3BucketReplicationConfigurationRule -ProfileName $ProfileName -BucketName $BucketName -Id $BucketName -DestinationBucketUrn "arn:aws:s3:::$DestinationBucketName" -Role $Role
            sleep 15
            $BucketReplication = Get-S3BucketReplicationConfigurationRule -ProfileName $ProfileName -BucketName $BucketName
            $BucketReplication.BucketName | Should -Be $BucketName
            $BucketReplication.Role | Should -Be $Role
            $BucketReplication.Id | Should -Be $BucketName
            $BucketReplication.Status | Should -Be "Enabled"
            $BucketReplication.DestinationBucketName | Should -Be $DestinationBucketName
            Write-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $Key
            sleep 5
            $DestinationObjects = Get-S3Objects -ProfileName "AWS" -BucketName $DestinationBucketName -Region $DestinationRegion
            $DestinationObjects.Key | Should -Be $Key
        }
    }

    Cleanup -BucketName $BucketName
    Cleanup -BucketName $DestinationBucketName -Region $DestinationRegion -ProfileName AWS

    if ($ProfileName -match "webscaledemo") {
        $EndpointConfiguration | Remove-SgwEndpoint -ProfileName $ProfileName
    }

    Setup -BucketName $UnicodeBucketName -Versioning
    Setup -BucketName $DestinationUnicodeBucketName -Versioning -Region $DestinationRegion -ProfileName AWS

    if ($ProfileName -match "webscaledemo") {
        $UnicodeEndpointConfiguration = Add-SgwEndpoint -ProfileName $ProfileName -DisplayName $DestinationUnicodeBucketName -EndpointUri "https://s3.us-east-2.amazonaws.com" -EndpointUrn "arn:aws:s3:::$DestinationUnicodeBucketName" -AccessKey $AwsProfile.AccessKey -SecretAccessKey $AwsProfile.SecretKey -ErrorAction Stop
        sleep 5
    }

    Context "Set Bucket Replication Configuration for bucket with unicode characters" {
        It "Given -BucketName $UnicodeBucketName -Id $UnicodeBucketName -DestinationBucketName arn:aws:s3:::$DestinationUnicodeBucketName -Role $Role a replication rule should be added" {
            Add-S3BucketReplicationConfigurationRule -ProfileName $ProfileName -BucketName $UnicodeBucketName -Id $UnicodeBucketName -DestinationBucketUrn "arn:aws:s3:::$DestinationUnicodeBucketName" -Role $Role
            sleep 15
            $BucketReplication = Get-S3BucketReplicationConfigurationRule -ProfileName $ProfileName -BucketName $UnicodeBucketName
            $BucketReplication.BucketName | Should -Be $UnicodeBucketName
            $BucketReplication.Role | Should -Be $Role
            $BucketReplication.Id | Should -Be $UnicodeBucketName
            $BucketReplication.Status | Should -Be "Enabled"
            $BucketReplication.DestinationBucketName | Should -Be $DestinationUnicodeBucketName
            Write-S3Object -ProfileName $ProfileName -BucketName $UnicodeBucketName -Key $Key
            sleep 5
            $DestinationObjects = Get-S3Objects -ProfileName "AWS" -BucketName $DestinationUnicodeBucketName -Region $DestinationRegion
            $DestinationObjects.Key | Should -Be $Key
        }
    }

    Cleanup -BucketName $UnicodeBucketName
    Cleanup -BucketName $DestinationUnicodeBucketName -Region $DestinationRegion -ProfileName "AWS"

    if ($ProfileName -match "webscaledemo") {
        $UnicodeEndpointConfiguration | Remove-SgwEndpoint -ProfileName $ProfileName
    }
}

$SmallFile | Remove-Item
$LargeFile | Remove-Item