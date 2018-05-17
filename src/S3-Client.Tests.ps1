PARAM(
    [Parameter(Mandatory=$false)][string]$ProfileName
)

Import-Module "$PSScriptRoot\S3-Client" -Force

$BucketName = Get-Date -Format "yyyy-MM-dd-HHmmss"
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

# create temporary file
$TestFileSize = 5MB
$TestFile = New-TemporaryFile
# Note: block size must be a factor of 1MB to avoid rounding errors :)
$BlockSize = 8KB
$ByteBuffer = [Byte[]]::new($BlockSize)
$Random = [System.Random]::new()
$Stream = [System.IO.FileStream]::new($TestFile, [System.IO.FileMode]::Open)
for ($i = 0; $i -lt ($TestFileSize / $BlockSize); $i++) {
    $Random.NextBytes($ByteBuffer)
    $Stream.Write($ByteBuffer, 0, $ByteBuffer.Length)
}
$Stream.Dispose()
$TestFileHash = $TestFile | Get-FileHash

function Setup() {
    New-S3Bucket -ProfileName $ProfileName -BucketName $BucketName
    New-S3Bucket -ProfileName $ProfileName -BucketName $UnicodeBucketName
    foreach ($i in 1..60) {
        sleep 1
        if (Test-S3Bucket -ProfileName $ProfileName -BucketName $BucketName) {
            break
        }
    }
    foreach ($i in 1..60) {
        sleep 1
        if (Test-S3Bucket -ProfileName $ProfileName -BucketName $UnicodeBucketName) {
            break
        }
    }
}

function Cleanup() {
    try {
        Remove-S3Bucket -ProfileName $ProfileName -BucketName $BucketName -Force
        # wait until bucket is really deleted
        foreach ($i in 1..60) {
            sleep 1
            if (!(Test-S3Bucket -ProfileName $ProfileName -BucketName $BucketName)) {
                break
            }
        }
    }
    catch {}

    try {
        Remove-S3Bucket -ProfileName $ProfileName -BucketName $UnicodeBucketName -Force
        # wait until bucket is really deleted
        foreach ($i in 1..60) {
            sleep 1
            if (!(Test-S3Bucket -ProfileName $ProfileName -BucketName $UnicodeBucketName)) {
                break
            }
        }
    }
    catch {}
}

Describe "Get-S3Buckets" {
    Setup

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

    Cleanup
}

Describe "Test-S3Bucket" {
    Setup

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

    Cleanup
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

    Cleanup

    Context "Create new bucket with parameter -UrlStyle virtual-hosted" {
        It "Given -BucketName $BucketName and -UrlStyle virtual-hosted it is succesfully created" {
            New-S3Bucket -ProfileName $ProfileName -BucketName $BucketName -UrlStyle virtual-hosted
            foreach ($i in 1..60) {
                sleep 1
                if (Test-S3Bucket -ProfileName $ProfileName -BucketName $BucketName) {
                    break
                }
            }
            $NewBucket = Get-S3Buckets -ProfileName $ProfileName -BucketName $BucketName
            $NewBucket.BucketName | Should -Be $BucketName
        }
    }

    Cleanup
}

Describe "Remove-S3Bucket" {
    Setup

    Context "Remove bucket with default parameters" {
        It "Given existing -BucketName $BucketName it is succesfully removed" {
            Remove-S3Bucket -ProfileName $ProfileName -BucketName $BucketName
            $Bucket = Get-S3Buckets -ProfileName $ProfileName -BucketName $BucketName
            $Bucket | Should -BeNullOrEmpty
        }
    }

    Context "Remove bucket with default parameters" {
        It "Given existing -BucketName $UnicodeBucketName it is succesfully removed" {
            Remove-S3Bucket -ProfileName $ProfileName -BucketName $UnicodeBucketName
            $Bucket = Get-S3Buckets -ProfileName $ProfileName -BucketName $UnicodeBucketName
            $Bucket | Should -BeNullOrEmpty
        }
    }

    Cleanup
}

Describe "Write-S3Object" {
    Setup

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
        It "Given -Content `"$Content`" it is succesfully created" {
            Write-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $UnicodeKey -Content $Content
            $Objects = Get-S3Objects -ProfileName $ProfileName -BucketName $BucketName -Key $UnicodeKey
            $UnicodeKey | Should -BeIn $Objects.Key
            $ObjectContent = Read-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $UnicodeKey
            $ObjectContent | Should -Be $Content
        }
    }

    Context "Upload file" {
        It "Given file -InFile `"$TestFile`" it is succesfully created" {
            Write-S3Object -ProfileName $ProfileName -BucketName $BucketName -InFile $TestFile
            $Objects = Get-S3Objects -ProfileName $ProfileName -BucketName $BucketName
            $TestFile.Name | Should -BeIn $Objects.Key
            $TempFile = New-TemporaryFile
            Read-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $TestFile.Name -OutFile $TempFile.FullName
            $TempFileHash = $TempFile | Get-FileHash
            $TempFileHash.Hash | Should -Be $TestFileHash.Hash
            $TempFile | Remove-Item
        }
    }

    Cleanup
}

Describe "Copy-S3Object" {
    Setup

    Context "Copy object" {
        It "Given -SourceBucket $BucketName and -SourceKey $Key and -BucketName $BucketName and -Key $Key it is copied to itself" {
            Write-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $Key -Content $Content -Metadata $CustomMetadata
            $CustomMetadata = Get-S3ObjectMetadata -ProfileName $ProfileName -BucketName $BucketName -Key $Key | Select-Object -ExpandProperty CustomMetadata
            Copy-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $Key -SourceBucket $BucketName -SourceKey $Key -MetadataDirective "REPLACE" -Metadata $CustomMetadata
            Get-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $Key
        }
    }

    Cleanup
}

Describe "S3BucketEncryption" {
    if ($ProfileName -match "webscaledemo") { continue }
    Setup

    Context "Set Bucket encryption" {
        It "Given -BucketName $BucketName and -SSEAlgorithm AWS256 server side encryption is enabled" {
            Set-S3BucketEncryption -ProfileName $ProfileName -BucketName $BucketName -SSEAlgorithm AES256
            sleep 2
            $BucketEncryption = Get-S3BucketEncryption -ProfileName $ProfileName -BucketName $BucketName
            $BucketEncryption.SSEAlgorithm | Should -Be "AES256"
            Remove-S3BucketEncryption -ProfileName $ProfileName -BucketName $BucketName
            $BucketEncryption = Get-S3BucketEncryption -ProfileName $ProfileName -BucketName $BucketName
            $BucketEncryption | Should -BeNullOrEmpty
        }

        It "Given -BucketName $UnicodeBucketName and -SSEAlgorithm AWS256 server side encryption is enabled" {
            Set-S3BucketEncryption -ProfileName $ProfileName -BucketName $UnicodeBucketName -SSEAlgorithm AES256
            sleep 2
            $BucketEncryption = Get-S3BucketEncryption -ProfileName $ProfileName -BucketName $UnicodeBucketName
            $BucketEncryption.SSEAlgorithm | Should -Be "AES256"
            Remove-S3BucketEncryption -ProfileName $ProfileName -BucketName $UnicodeBucketName
            $BucketEncryption = Get-S3BucketEncryption -ProfileName $ProfileName -BucketName $UnicodeBucketName
            $BucketEncryption | Should -BeNullOrEmpty
        }
    }

    Cleanup
}

Describe "S3BucketCorsConfiguration" {
    if ($ProfileName -eq "webscaledemo") { continue }

    $AllowedMethods = "GET","PUT","POST","DELETE"
    $AllowedOrigins = "netapp.com","*.example.org"
    $AllowedHeaders = "x-amz-meta-1","x-amz-meta-2"
    $MaxAgeSeconds = 3000
    $ExposeHeaders = "x-amz-server-side-encryption"

    Setup

    Context "Set Bucket CORS Configuration" {
        It "Given -BucketName $BucketName -Id $BucketName -AllowedMethods $AllowedMethods -AllowedOrigins $AllowedOrigins -AllowedHeaders $AllowedHeaders -MaxAgeSeconds $MaxAgeSeconds -ExposeHeaders $ExposeHeaders a CORS Configuration rule is added" {
            $Id = "BucketName"
            Add-S3BucketCorsConfigurationRule -ProfileName $ProfileName -BucketName $BucketName -Id $Id -AllowedMethods $AllowedMethods -AllowedOrigins $AllowedOrigins -AllowedHeaders $AllowedHeaders -MaxAgeSeconds $MaxAgeSeconds -ExposeHeaders $ExposeHeaders
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
            $CorsConfiguration = Get-S3BucketCorsConfiguration -ProfileName $ProfileName -BucketName $UnicodeBucketName
            $CorsConfiguration.Id | Should -Be $Id
            $CorsConfiguration.AllowedMethod | Should -Be $AllowedMethods
            $CorsConfiguration.AllowedOrigin | Should -Be $AllowedOrigins
        }

        It "Given -BucketName $BucketName -Id `"remove`" a CORS configuration rule is removed" {
            $Id = "Remove"
            Add-S3BucketCorsConfigurationRule -ProfileName $ProfileName -BucketName $BucketName -Id $Id -AllowedMethods $AllowedMethods -AllowedOrigins $AllowedOrigins
            $CorsConfigurationRule = Get-S3BucketCorsConfigurationRule -ProfileName $ProfileName -BucketName $BucketName -Id $Id
            $CorsConfigurationRule.Id | Should -Be $Id
            $CorsConfigurationRule | Remove-S3BucketCorsConfigurationRule -ProfileName $ProfileName
            $CorsConfigurationRule = Get-S3BucketCorsConfigurationRule -ProfileName $ProfileName -BucketName $BucketName -Id $Id
            $CorsConfigurationRule | Should -BeNullOrEmpty
        }

        It "Given -BucketName $BucketName all CORS configuration is removed" {
            $Id = "RemoveAll"
            Add-S3BucketCorsConfigurationRule -ProfileName $ProfileName -BucketName $BucketName -Id $Id -AllowedMethods $AllowedMethods -AllowedOrigins $AllowedOrigins
            $CorsConfigurationRule = Get-S3BucketCorsConfigurationRule -ProfileName $ProfileName -BucketName $BucketName -Id $Id
            $CorsConfigurationRule.Id | Should -Be $Id
            Remove-S3BucketCorsConfiguration -ProfileName $ProfileName -BucketName $BucketName
            $CorsConfiguration = Get-S3BucketCorsConfiguration -ProfileName $ProfileName -BucketName $BucketName
            $CorsConfiguration | Should -BeNullOrEmpty
        }
    }

    Cleanup
}

$TestFile | Remove-Item