PARAM(
    [Parameter(Mandatory=$false)][string]$ProfileName
)

Import-Module "$PSScriptRoot\S3-Client" -Force

$MAX_RETRIES = 3
$MAX_WAIT_TIME = 120

$UnicodeString = [System.Web.HttpUtility]::UrlDecode("%40%c5%93%c3%a6%c3%b6%c3%bc%c3%a4%c3%84%c3%96%c3%9c%2f%3d%c3%a1%c3%aa%3a%2b-_.")
$Tags = @(@{Key=$UnicodeString;Value="valuewithunicodekey"},@{Key="keywithunicodevalue";Value=$UnicodeString})

$BaseBucketName = (Get-Date -Format "yyyyMMdd") + "Bucket"
$BaseUnicodeBucketName = [System.Globalization.IdnMapping]::new().GetUnicode("xn--9csy79e60h") + "$BaseBucketName"
$Key = "dir/dir/dir/dir/dir/dir/Key"
$UnicodeKey = [System.Web.HttpUtility]::UrlDecode("%u842c%u570b%u78bc%2BTesting+%u00ab%u03c4%u03b1%u0411%u042c%u2113%u03c3%u00bb+1%3c2%2B%2B41%3e3%2Bnow%2B20%25%2Boff")
$Content = "Hello World!"
$Metadata = @{"MetadataKey"="MetadataValue"}

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
    foreach ($i in 1..$MAX_WAIT_TIME) {
        sleep 1
        if (Test-S3Bucket -ProfileName $ProfileName -BucketName $BucketName -Region $Region) {
            break
        }
        if ($i -lt $MAX_WAIT_TIME) {
            Write-Warning "Checked $i times but bucket does not yet exist. Waiting 1 second and then trying again."
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
                HelpMessage="Bucket Region")][String]$ProfileName=$ProfileName,
        [parameter(
                Mandatory=$False,
                Position=3,
                HelpMessage="RetryCount")][Int]$RetryCount=1
    )

    try {
        Remove-S3Bucket -ProfileName $ProfileName -BucketName $BucketName -Region $Region -Force
        # wait until bucket is really deleted
        foreach ($i in 1..$MAX_WAIT_TIME) {
            sleep 1
            if (!(Test-S3Bucket -ProfileName $ProfileName -BucketName $BucketName -Region $Region)) {
                sleep 1
                break
            }
            if ($i -lt $MAX_WAIT_TIME) {
                Write-Warning "Checked $i times but bucket still exists. Waiting 1 second and then trying again."
            }
        }
    }
    catch {
        if ($RetryCount -lt $MAX_RETRIES) {
            $RetryCount = $RetryCount + 1
            Cleanup -BucketName $BucketName -Region $Region -ProfileName $ProfileName -RetryCount $RetryCount
        }
    }
}

Describe "AWS Configuration and Credential Management" {

    $ProfileName = "test"
    $AccessKey = "ABCDEFGHIJKLMNOPQRST"
    $SecretKey = "abcdefghijklmnopqrst1234567890ABCDEFGHIJ"
    $Region = "eu-central-1"
    $EndpointUrl = "https://s3.example.org"
    $MaxConcurrentRequest = 1234
    $MaxQueueSize = 1234
    $MultipartThreshold = "256MB"
    $MultipartChunksize = "128MB"
    $MaxBandwidth = "10MB/s"
    $UseAccelerateEndpoint = $true
    $UseDualstackEndpoint = $false
    $AddressingStyle = "path"
    $PayloadSigning= $true

    Context "Add a new Profile" {
        It "Given -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -Region $Region -EndpointUrl $EndpointUrl -MaxConcurrentRequests $MaxConcurrentRequest -MultipartThreshold $MultipartThreshold -MultipartChunksize $MultipartChunksize -MaxBandwidth $MaxBandwidth -UseAccelerateEndpoint $UseAccelerateEndpoint -UseDualstackEndpoint $UseDualstackEndpoint -AddressingStyle $AddressingStyle -PayloadSigning $PayloadSigning creates a new profile with these values" {
            New-AwsConfig -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -Region $Region -EndpointUrl $EndpointUrl -MaxConcurrentRequests $MaxConcurrentRequest -MaxQueueSize $MaxQueueSize -MultipartThreshold $MultipartThreshold -MultipartChunksize $MultipartChunksize -MaxBandwidth $MaxBandwidth -UseAccelerateEndpoint $UseAccelerateEndpoint -UseDualstackEndpoint $UseDualstackEndpoint -AddressingStyle $AddressingStyle -PayloadSigning $PayloadSigning

            $Config = Get-AwsConfig -ProfileName $ProfileName
            $Config.ProfileName | Should -Be $ProfileName
            $Config.AccessKey | Should -Be $AccessKey
            $Config.SecretKey | Should -Be $SecretKey
            $Config.Region | Should -Be $Region
            $Config.EndpointUrl | Should -Be $EndpointUrl
            $Config.MaxConcurrentRequests | Should -Be $MaxConcurrentRequest
            $Config.MaxQueueSize |  Should -Be $MaxQueueSize
            $Config.MultipartThreshold  | Should -Be $MultipartThreshold
            $Config.MultipartChunksize  | Should -Be $MultipartChunksize
            $Config.MaxBandwidth  | Should -Be $MaxBandwidth
            $Config.UseAccelerateEndpoint  | Should -Be $UseAccelerateEndpoint
            $Config.UseDualstackEndpoint  | Should -Be $UseDualstackEndpoint
            $Config.AddressingStyle  | Should -Be $AddressingStyle
            $Config.PayloadSigning  | Should -Be $PayloadSigning

            Remove-AwsConfig -ProfileName $ProfileName
        }

        It "Given -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey creates a profile with default values" {
            New-AwsConfig -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey

            $Config = Get-AwsConfig -ProfileName $ProfileName
            $Config.ProfileName | Should -Be $ProfileName
            $Config.AccessKey | Should -Be $AccessKey
            $Config.SecretKey | Should -Be $SecretKey
            $Config.Region | Should -Be "us-east-1"
            $Config.EndpointUrl | Should -BeNullOrEmpty
            $Config.MaxConcurrentRequests | Should -Be ([Environment]::ProcessorCount * 2)
            $Config.MaxQueueSize |  Should -Be 1000
            $Config.MultipartThreshold | Should -Be "8MB"
            $Config.MultipartChunksize  | Should -BeNullOrEmpty
            $Config.MaxBandwidth  | Should -BeNullOrEmpty
            $Config.UseAccelerateEndpoint | Should -BeFalse
            $Config.UseDualstackEndpoint | Should -BeFalse
            $Config.AddressingStyle | Should -Be "auto"
            $Config.PayloadSigning | Should -Be "auto"

            Remove-AwsConfig -ProfileName $ProfileName
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

    Context "Update an existing profile" {
        It "Given an existing profile $ProfileName and parameters -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -Region $Region -EndpointUrl $EndpointUrl -MaxConcurrentRequests $MaxConcurrentRequest -MultipartThreshold $MultipartThreshold -MultipartChunksize $MultipartChunksize -MaxBandwidth $MaxBandwidth -UseAccelerateEndpoint $UseAccelerateEndpoint -UseDualstackEndpoint $UseDualstackEndpoint -AddressingStyle $AddressingStyle -PayloadSigning $PayloadSigning it updates all values" {
            New-AwsConfig -ProfileName $ProfileName -AccessKey "existing" -SecretKey "existing"

            Update-AwsConfig -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -Region $Region -EndpointUrl $EndpointUrl -MaxConcurrentRequests $MaxConcurrentRequest -MaxQueueSize $MaxQueueSize -MultipartThreshold $MultipartThreshold -MultipartChunksize $MultipartChunksize -MaxBandwidth $MaxBandwidth -UseAccelerateEndpoint $UseAccelerateEndpoint -UseDualstackEndpoint $UseDualstackEndpoint -AddressingStyle $AddressingStyle -PayloadSigning $PayloadSigning

            $Config = Get-AwsConfig -ProfileName $ProfileName
            $Config.ProfileName | Should -Be $ProfileName
            $Config.AccessKey | Should -Be $AccessKey
            $Config.SecretKey | Should -Be $SecretKey
            $Config.Region | Should -Be $Region
            $Config.EndpointUrl | Should -Be $EndpointUrl
            $Config.MaxConcurrentRequests | Should -Be $MaxConcurrentRequest
            $Config.MaxQueueSize |  Should -Be $MaxQueueSize
            $Config.MultipartThreshold  | Should -Be $MultipartThreshold
            $Config.MultipartChunksize  | Should -Be $MultipartChunksize
            $Config.MaxBandwidth  | Should -Be $MaxBandwidth
            $Config.UseAccelerateEndpoint  | Should -Be $UseAccelerateEndpoint
            $Config.UseDualstackEndpoint  | Should -Be $UseDualstackEndpoint
            $Config.AddressingStyle  | Should -Be $AddressingStyle
            $Config.PayloadSigning  | Should -Be $PayloadSigning

            Remove-AwsConfig -ProfileName $ProfileName
        }

        It "Given an existing profile $ProfileName with non default values resetting the values to defaults works" {
            New-AwsConfig -ProfileName $ProfileName -AccessKey $AccessKey -SecretKey $SecretKey -Region $Region -EndpointUrl $EndpointUrl -MaxConcurrentRequests $MaxConcurrentRequest -MaxQueueSize $MaxQueueSize -MultipartThreshold $MultipartThreshold -MultipartChunksize $MultipartChunksize -MaxBandwidth $MaxBandwidth -UseAccelerateEndpoint $UseAccelerateEndpoint -UseDualstackEndpoint $UseDualstackEndpoint -AddressingStyle $AddressingStyle -PayloadSigning $PayloadSigning

            Update-AwsConfig -ProfileName $ProfileName -Region "us-east-1" -MaxConcurrentRequests ([Environment]::ProcessorCount * 2) -MaxQueueSize 1000 -MultipartThreshold "8MB" -MultipartChunksize 0 -MaxBandwidth 0 -UseAccelerateEndpoint $false -UseDualstackEndpoint $false -AddressingStyle "auto" -PayloadSigning "auto"

            $Config = Get-AwsConfig -ProfileName $ProfileName
            $Config.ProfileName | Should -Be $ProfileName
            $Config.AccessKey | Should -Be $AccessKey
            $Config.SecretKey | Should -Be $SecretKey
            $Config.Region | Should -Be "us-east-1"
            $Config.MaxConcurrentRequests | Should -Be ([Environment]::ProcessorCount * 2)
            $Config.MaxQueueSize |  Should -Be 1000
            $Config.MultipartThreshold | Should -Be "8MB"
            $Config.MultipartChunksize  | Should -BeNullOrEmpty
            $Config.MaxBandwidth  | Should -BeNullOrEmpty
            $Config.UseAccelerateEndpoint | Should -BeFalse
            $Config.UseDualstackEndpoint | Should -BeFalse
            $Config.AddressingStyle | Should -Be "auto"
            $Config.PayloadSigning | Should -Be "auto"

            Remove-AwsConfig -ProfileName $ProfileName
        }
    }
}

Describe "List Buckets" {

    BeforeAll {
        $BucketName = $BaseBucketName + "-list-buckets"
        $UnicodeBucketName = $BaseUnicodeBucketName + "-list-buckets"

        Setup -BucketName $BucketName
        Setup -BucketName $UnicodeBucketName
    }

    AfterAll {
        Cleanup -BucketName $BucketName
        Cleanup -BucketName $UnicodeBucketName
    }

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
}

Describe "Test Bucket existence" {

    BeforeAll {
        $BucketName = $BaseBucketName + "-test-bucket-existence"
        $UnicodeBucketName = $UnicodeBucketName + "-test-bucket-existence"

        Setup -BucketName $BucketName
        Setup -BucketName $UnicodeBucketName
    }

    AfterAll {
        Cleanup -BucketName $BucketName
        Cleanup -BucketName $UnicodeBucketName
    }

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
}

Describe "Create Bucket" {

    BeforeAll {
        $BucketName = $BaseBucketName + "-create-bucket"
        $UnicodeBucketName = $UnicodeBucketName + "-create-bucket"
    }

    AfterEach {
        Cleanup -BucketName $BucketName
        Cleanup -BucketName $UnicodeBucketName
    }

    Context "Create new bucket with default parameters" {

        It "Given -BucketName $BucketName it is succesfully created" {
            New-S3Bucket -ProfileName $ProfileName -BucketName $BucketName

            $BucketExists = foreach ($i in 1..$MAX_WAIT_TIME) {
                Start-Sleep -Seconds 1
                $BucketExists = Test-S3Bucket -ProfileName $ProfileName -BucketName $BucketName
                if ($BucketExists) {
                    return $BucketExists
                }
                if ($i -lt $MAX_WAIT_TIME) {
                    Write-Warning "Tried $i times but bucket does not exist yet. Retrying in 1 second."
                }
            }
            $BucketExists | Should -BeTrue
        }

        It "Given -BucketName $UnicodeBucketName it is succesfully created" {
            New-S3Bucket -ProfileName $ProfileName -BucketName $UnicodeBucketName

            $BucketExists = foreach ($i in 1..$MAX_WAIT_TIME) {
                Start-Sleep -Seconds 1
                $BucketExists = Test-S3Bucket -ProfileName $ProfileName -BucketName $UnicodeBucketName
                if ($BucketExists) {
                    return $BucketExists
                }
                if ($i -lt $MAX_WAIT_TIME) {
                    Write-Warning "Tried $i times but bucket does not exist yet. Retrying in 1 second."
                }
            }
            $BucketExists | Should -BeTrue
        }
    }

    Context "Create new bucket with parameter -UrlStyle virtual-hosted" {
        if ($ProfileName -eq "Minio") { continue }

        It "Given -BucketName $BucketName and -UrlStyle virtual-hosted it is succesfully created" {
            New-S3Bucket -ProfileName $ProfileName -BucketName $BucketName -UrlStyle virtual-hosted

            $BucketExists = foreach ($i in 1..$MAX_WAIT_TIME) {
                Start-Sleep -Seconds 1
                $BucketExists = Test-S3Bucket -ProfileName $ProfileName -BucketName $BucketName  -UrlStyle virtual-hosted
                if ($BucketExists) {
                    return $BucketExists
                }
                if ($i -lt $MAX_WAIT_TIME) {
                    Write-Warning "Tried $i times but bucket does not exist yet. Retrying in 1 second."
                }
            }
            $BucketExists | Should -BeTrue
        }
    }
}

Describe "Remove Bucket" {

    BeforeAll {
        $BucketName = $BaseBucketName + "-remove-bucket"
        $UnicodeBucketName = $UnicodeBucketName + "-remove-bucket"

        Setup -BucketName $BucketName
        Setup -BucketName $UnicodeBucketName
    }

    AfterAll {
        Cleanup -BucketName $BucketName
        Cleanup -BucketName $UnicodeBucketName
    }

    Context "Remove bucket with default parameters" {
        It "Given existing -BucketName $BucketName it is succesfully removed" {
            Remove-S3Bucket -ProfileName $ProfileName -BucketName $BucketName -Force
            $Bucket = Get-S3Buckets -ProfileName $ProfileName -BucketName $BucketName
            $Bucket | Should -BeNullOrEmpty
        }

        It "Given existing -BucketName $UnicodeBucketName it is succesfully removed" {
            Remove-S3Bucket -ProfileName $ProfileName -BucketName $UnicodeBucketName -Force
            $Bucket = Get-S3Buckets -ProfileName $ProfileName -BucketName $UnicodeBucketName
            $Bucket | Should -BeNullOrEmpty
        }
    }
}

Describe "Upload Object" {

    BeforeAll {
        $BucketName = $BaseBucketName + "-upload-object"
        $UnicodeBucketName = $UnicodeBucketName + "-upload-object"

        Setup -BucketName $BucketName
        Setup -BucketName $UnicodeBucketName
    }

    AfterAll {
        Cleanup -BucketName $BucketName
        Cleanup -BucketName $UnicodeBucketName
    }

    Context "Upload text" {
        It "Given -BucketName $BucketName -Key $Key -Content `"$Content`" it is succesfully created" {
            Write-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $Key -Content $Content

            $Objects = Get-S3Objects -ProfileName $ProfileName -BucketName $BucketName
            $Key | Should -BeIn $Objects.Key

            Start-Sleep -Seconds 1
            $ObjectContent = Read-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $Key
            $ObjectContent | Should -Be $Content

            Remove-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $Key
        }

        It "Given -BucketName $BucketName -Key $UnicodeKey -Content `"$Content`" it is succesfully created" -Skip:($ProfileName -match "minio") {
            Write-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $UnicodeKey -Content $Content

            $Objects = Get-S3Objects -ProfileName $ProfileName -BucketName $BucketName
            $UnicodeKey | Should -BeIn $Objects.Key

            Start-Sleep -Seconds 1
            $ObjectContent = Read-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $UnicodeKey
            $ObjectContent | Should -Be $Content

            Remove-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $UnicodeKey
        }
    }

    Context "Upload small file" {
        It "Given file -InFile `"$SmallFile`" it is succesfully uploaded" {
            Write-S3Object -ProfileName $ProfileName -BucketName $BucketName -InFile $SmallFile
            $Objects = Get-S3Objects -ProfileName $ProfileName -BucketName $BucketName
            $SmallFile.Name | Should -BeIn $Objects.Key
            $TempFile = New-TemporaryFile
            Start-Sleep -Seconds 1
            Read-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $SmallFile.Name -OutFile $TempFile.FullName
            $TempFileHash = $TempFile | Get-FileHash
            $TempFileHash.Hash | Should -Be $SmallFileHash.Hash
            $TempFile | Remove-Item
            Remove-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $SmallFile.Name
        }
    }

    Context "Upload small file with custom key $UnicodeKey" {
        It "Given file -InFile `"$SmallFile`" and -Key `"$UnicodeKey`" it is succesfully uploaded" -Skip:($ProfileName -match "minio") {
            Write-S3Object -ProfileName $ProfileName -BucketName $BucketName -InFile $SmallFile -Key $UnicodeKey
            $Objects = Get-S3Objects -ProfileName $ProfileName -BucketName $BucketName
            $UnicodeKey | Should -BeIn $Objects.Key
            $TempFile = New-TemporaryFile
            Start-Sleep -Seconds 1
            Read-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $UnicodeKey -OutFile $TempFile.FullName
            $TempFileHash = $TempFile | Get-FileHash
            $TempFileHash.Hash | Should -Be $SmallFileHash.Hash
            $TempFile | Remove-Item
            Remove-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $UnicodeKey
        }
    }
}

Describe "Multipart Upload of Object" {

    BeforeAll {
        $BucketName = $BaseBucketName + "-multipart-upload-object"
        $UnicodeBucketName = $UnicodeBucketName + "-multipart-upload-object"

        Setup -BucketName $BucketName
        Setup -BucketName $UnicodeBucketName
    }

    AfterAll {
        Cleanup -BucketName $BucketName
        Cleanup -BucketName $UnicodeBucketName
    }

    Context "Upload large file" {

        It "Given file -InFile `"$LargeFile`" it is succesfully uploaded to Bucket $BucketName" {
            Write-S3MultipartUpload -ProfileName $ProfileName -BucketName $BucketName -InFile $LargeFile
            $Objects = Get-S3Objects -ProfileName $ProfileName -BucketName $BucketName
            $LargeFile.Name | Should -BeIn $Objects.Key
            $TempFile = New-TemporaryFile
            Start-Sleep -Seconds 1
            Read-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $LargeFile.Name -OutFile $TempFile.FullName
            $TempFileHash = $TempFile | Get-FileHash
            $TempFileHash.Hash | Should -Be $LargeFileHash.Hash
            $TempFile | Remove-Item
            Remove-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $LargeFile.Name
        }

        It "Given file -InFile `"$LargeFile`" it is succesfully uploaded to Bucket $UnicodeBucketName" {
            Write-S3MultipartUpload -ProfileName $ProfileName -BucketName $UnicodeBucketName -InFile $LargeFile
            $Objects = Get-S3Objects -ProfileName $ProfileName -BucketName $UnicodeBucketName
            $LargeFile.Name | Should -BeIn $Objects.Key
            $TempFile = New-TemporaryFile
            Start-Sleep -Seconds 1
            Read-S3Object -ProfileName $ProfileName -BucketName $UnicodeBucketName -Key $LargeFile.Name -OutFile $TempFile.FullName
            $TempFileHash = $TempFile | Get-FileHash
            $TempFileHash.Hash | Should -Be $LargeFileHash.Hash
            $TempFile | Remove-Item
            Remove-S3Object -ProfileName $ProfileName -BucketName $UnicodeBucketName -Key $LargeFile.Name
        }
    }
}

Describe "Copy Object" {

    BeforeAll {
        $BucketName = $BaseBucketName + "-copy-object"

        Setup -BucketName $BucketName -Key $Key
    }

    AfterAll {
        Cleanup -BucketName $BucketName
    }

    Context "Copy object to itself" {
        It "Given -BucketName $BucketName and -Key $Key and -SourceBucket $BucketName and -SourceKey $Key it is copied to itself" -Skip:($ProfileName -match "minio|webscaledemo") {
            $OriginalObjectMetadata = Get-S3ObjectMetadata -ProfileName $ProfileName -BucketName $BucketName -Key $Key

            Start-Sleep -Seconds 2
            Copy-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $Key -SourceBucket $BucketName -SourceKey $Key

            foreach ($i in 1..$MAX_WAIT_TIME) {
                Start-Sleep -Seconds 1
                $ObjectMetadata = Get-S3ObjectMetadata -ProfileName $ProfileName -BucketName $BucketName -Key $Key
                if ($OriginalObjectMetadata.LastModified -lt $ObjectMetadata.LastModified) {
                    break
                }
                if ($i -lt $MAX_WAIT_TIME) {
                    Write-Warning "Tried $i times but object is not copied to itself yet. Trying again in 1 second."
                }
            }
            $OriginalObjectMetadata.LastModified | Should -BeLessThan $ObjectMetadata.LastModified
        }

        It "Given -BucketName $BucketName and -Key $Key it is copied to itself" -Skip:($ProfileName -match "minio|webscaledemo") {
            $OriginalObjectMetadata = Get-S3ObjectMetadata -ProfileName $ProfileName -BucketName $BucketName -Key $Key

            Copy-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $Key

            foreach ($i in 1..$MAX_WAIT_TIME) {
                Start-Sleep -Seconds 1
                $ObjectMetadata = Get-S3ObjectMetadata -ProfileName $ProfileName -BucketName $BucketName -Key $Key
                if ($OriginalObjectMetadata.LastModified -lt $ObjectMetadata.LastModified) {
                    break
                }
                if ($i -lt $MAX_WAIT_TIME) {
                    Write-Warning "Tried $i times but object is not copied to itself yet. Trying again in 1 second."
                }
            }
            $OriginalObjectMetadata.LastModified | Should -BeLessThan $ObjectMetadata.LastModified
        }

        It "Given -BucketName $BucketName and -Key $Key and -SourceBucket $BucketName and -SourceKey $Key and additional metadata it is copied to itself" -Skip:($ProfileName -match "minio|webscaledemo") {
            $Metadata = Get-S3ObjectMetadata -ProfileName $ProfileName -BucketName $BucketName -Key $Key | Select-Object -ExpandProperty Metadata
            $Metadata["copytest"]="test"

            Copy-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $Key -SourceBucket $BucketName -SourceKey $Key -MetadataDirective "REPLACE" -Metadata $Metadata

            foreach ($i in 1..$MAX_WAIT_TIME) {
                Start-Sleep -Seconds 1
                $ObjectMetadata = Get-S3ObjectMetadata -ProfileName $ProfileName -BucketName $BucketName -Key $Key
                if ($OriginalObjectMetadata.LastModified -lt $ObjectMetadata.LastModified) {
                    break
                }
                if ($i -lt $MAX_WAIT_TIME) {
                    Write-Warning "Tried $i times but object is not copied to itself yet. Trying again in 1 second."
                }
            }
            $OriginalObjectMetadata.LastModified | Should -BeLessThan $ObjectMetadata.LastModified
            $ObjectMetadata.Metadata.copytest | Should -Be "test"
        }
    }

    Context "Copy object to a new object" {
        It "Given -BucketName $BucketName and -Key $UnicodeKey and -SourceBucket $BucketName and -SourceKey $Key it is copied to a new object" -Skip:($ProfileName -match "minio") {
            Copy-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $Key -SourceBucket $BucketName -SourceKey $Key

            foreach ($i in 1..$MAX_WAIT_TIME) {
                Start-Sleep -Seconds 1
                $ObjectExists = Test-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $Key
                if ($ObjectExists) {
                    break
                }
                if ($i -lt $MAX_WAIT_TIME) {
                    Write-Warning "Tried $i times but object does not exist yet. Trying again in 1 second."
                }
            }
            $ObjectExists | Should -BeTrue
        }
    }
}

Describe "S3 Bucket Encryption" {

    BeforeAll {
        $BucketName = $BaseBucketName + "-bucket-encryption"
        $UnicodeBucketName = $UnicodeBucketName + "-bucket-encryption"

        Setup -BucketName $BucketName
        Setup -BucketName $UnicodeBucketName
    }

    AfterAll {
        Cleanup -BucketName $BucketName
        Cleanup -BucketName $UnicodeBucketName
    }

    Context "Set Bucket encryption" {
        It "Given -BucketName $BucketName and -SSEAlgorithm AES256 server side encryption is enabled" -Skip:($ProfileName -match "minio|webscaledemo") {
            Set-S3BucketEncryption -ProfileName $ProfileName -BucketName $BucketName -SSEAlgorithm AES256

            foreach ($i in $MAX_WAIT_TIME) {
                Start-Sleep -Seconds 1
                $BucketEncryption = Get-S3BucketEncryption -ProfileName $ProfileName -BucketName $BucketName
                if ($BucketEncryption.SSEAlgorithm -eq "AES256") {
                    break
                }
                Write-Warning "Tried $i times, but bucket encryption not yet active. Retrying in 1 second."
            }
            $BucketEncryption.SSEAlgorithm | Should -Be "AES256"

            Remove-S3BucketEncryption -ProfileName $ProfileName -BucketName $BucketName

            foreach ($i in $MAX_WAIT_TIME) {
                Start-Sleep -Seconds 1
                $BucketEncryption = Get-S3BucketEncryption -ProfileName $ProfileName -BucketName $BucketName
                if (!$BucketEncryption) {
                    break
                }
                Write-Warning "Tried $i times, but bucket encryption still active. Retrying in 1 second."
            }
            $BucketEncryption | Should -BeNullOrEmpty
        }

        It "Given -BucketName $UnicodeBucketName and -SSEAlgorithm AES256 server side encryption is enabled" -Skip:($ProfileName -match "minio|webscaledemo") {
            Set-S3BucketEncryption -ProfileName $ProfileName -BucketName $UnicodeBucketName -SSEAlgorithm AES256

            foreach ($i in $MAX_WAIT_TIME) {
                Start-Sleep -Seconds 1
                $BucketEncryption = Get-S3BucketEncryption -ProfileName $ProfileName -BucketName $UnicodeBucketName
                if ($BucketEncryption.SSEAlgorithm -eq "AES256") {
                    break
                }
                Write-Warning "Tried $i times, but bucket encryption not yet active. Retrying in 1 second."
            }
            $BucketEncryption.SSEAlgorithm | Should -Be "AES256"

            Remove-S3BucketEncryption -ProfileName $ProfileName -BucketName $UnicodeBucketName

            foreach ($i in $MAX_WAIT_TIME) {
                Start-Sleep -Seconds 1
                $BucketEncryption = Get-S3BucketEncryption -ProfileName $ProfileName -BucketName $UnicodeBucketName
                if (!$BucketEncryption) {
                    break
                }
                Write-Warning "Tried $i times, but bucket encryption still active. Retrying in 1 second."
            }
            $BucketEncryption | Should -BeNullOrEmpty
        }
    }
}

Describe "S3 Bucket Tagging" {

    BeforeAll {
        $BucketName = $BaseBucketName + "-bucket-tagging"
        $UnicodeBucketName = $UnicodeBucketName + "-bucket-tagging"

        Setup -BucketName $BucketName
        Setup -BucketName $UnicodeBucketName
    }

    AfterAll {
        Cleanup -BucketName $BucketName
        Cleanup -BucketName $UnicodeBucketName
    }

    Context "Set Bucket tagging" {
        It "Given -BucketName $BucketName and -Tags $(ConvertTo-Json -InputObject $Tags -Compress) tags should be added to bucket" -Skip:($ProfileName -match "minio|webscaledemo") {
            Set-S3BucketTagging -ProfileName $ProfileName -BucketName $BucketName -Tags $Tags

            foreach ($i in 1..$MAX_WAIT_TIME) {
                Start-Sleep -Seconds 1
                $BucketTagging = Get-S3BucketTagging -ProfileName $ProfileName -BucketName $BucketName
                if ($BucketTagging) {
                    break
                }
                Write-Warning "Tried $i times but bucket has not been tagged yet. Retrying in 1 second."
            }

            $BucketTagging | Sort-Object -Property Key | Select-Object -First 1 | Should -Be ([System.Collections.DictionaryEntry]$Tags[0])
            $BucketTagging | Sort-Object -Property Key | Select-Object -Last 1 | Should -Be ([System.Collections.DictionaryEntry]$Tags[1])
        }

        It "Given -BucketName $UnicodeBucketName and -Tags $(ConvertTo-Json -InputObject $Tags -Compress) tags should be added to bucket" -Skip:($ProfileName -match "minio|webscaledemo") {
            Set-S3BucketTagging -ProfileName $ProfileName -BucketName $UnicodeBucketName -Tags $Tags

            foreach ($i in 1..$MAX_WAIT_TIME) {
                Start-Sleep -Seconds 1
                $BucketTagging = Get-S3BucketTagging -ProfileName $ProfileName -BucketName $UnicodeBucketName
                if ($BucketTagging) {
                    break
                }
                Write-Warning "Tried $i times but bucket has not been tagged yet. Retrying in 1 second."
            }
            $BucketTagging | Sort-Object -Property Key | Select-Object -First 1 | Should -Be ([System.Collections.DictionaryEntry]$Tags[0])
            $BucketTagging | Sort-Object -Property Key | Select-Object -Last 1 | Should -Be ([System.Collections.DictionaryEntry]$Tags[1])
        }
    }
}

Describe "S3 Object Tagging" {

    BeforeAll {
        $BucketName = $BaseBucketName + "-object-tagging"
        $UnicodeBucketName = $UnicodeBucketName + "-object-tagging"

        Setup -BucketName $BucketName -Key $Key
        Setup -BucketName $UnicodeBucketName -Key $UnicodeKey
    }

    AfterAll {
        Cleanup -BucketName $BucketName
        Cleanup -BucketName $UnicodeBucketName
    }

    Context "Set Object tagging" {
        It "Given -BucketName $BucketName -Key $Key and -Tags $Tags tags should be added to bucket" -Skip:($ProfileName -match "minio") {
            Set-S3ObjectTagging -ProfileName $ProfileName -BucketName $BucketName -Key $Key -Tags $Tags

            foreach ($i in 1..$MAX_WAIT_TIME) {
                $ObjectTagging = Get-S3ObjectTagging -ProfileName $ProfileName -BucketName $BucketName -Key $Key
                if ($ObjectTagging) {
                    break
                }
                Write-Warning "Tried $i times but object is not yet tagged. Retrying in 1 second."
            }

            $ObjectTagging | Sort-Object -Property Key | Select-Object -First 1 | Should -Be ([System.Collections.DictionaryEntry]$Tags[0])
            $ObjectTagging | Sort-Object -Property Key | Select-Object -Last 1 | Should -Be ([System.Collections.DictionaryEntry]$Tags[1])
        }

        It "Given -BucketName $UnicodeBucketName -Key $UnicodeKey and -Tags $Tags tags should be added to bucket" -Skip:($ProfileName -match "minio") {
            Set-S3ObjectTagging -ProfileName $ProfileName -BucketName $UnicodeBucketName -Key $UnicodeKey -Tags $Tags

            foreach ($i in 1..$MAX_WAIT_TIME) {
                $ObjectTagging = Get-S3ObjectTagging -ProfileName $ProfileName -BucketName $UnicodeBucketName -Key $UnicodeKey
                if ($ObjectTagging) {
                    break
                }
                Write-Warning "Tried $i times but object is not yet tagged. Retrying in 1 second."
            }

            $ObjectTagging | Sort-Object -Property Key | Select-Object -First 1 | Should -Be ([System.Collections.DictionaryEntry]$Tags[0])
            $ObjectTagging | Sort-Object -Property Key | Select-Object -Last 1 | Should -Be ([System.Collections.DictionaryEntry]$Tags[1])
        }
    }
}

Describe "S3 Bucket Versioning" {

    BeforeAll {
        $BucketName = $BaseBucketName + "-bucket-versioning"
        $UnicodeBucketName = $UnicodeBucketName + "-bucket-versioning"

        Setup -BucketName $BucketName
        Setup -BucketName $UnicodeBucketName
    }

    AfterAll {
        Cleanup -BucketName $BucketName
        Cleanup -BucketName $UnicodeBucketName
    }

    Context "Enable and Suspend Bucket Versioning" {

        It "Given -BucketName $BucketName versioning is enabled and then suspended" -Skip:($ProfileName -match "minio") {
            Enable-S3BucketVersioning -ProfileName $ProfileName -BucketName $BucketName

            foreach ($i in 1..$MAX_WAIT_TIME) {
                Start-Sleep -Seconds 1
                $BucketVersioning = Get-S3BucketVersioning -ProfileName $ProfileName -BucketName $BucketName
                if ($BucketVersioning -eq "Enabled") {
                    break
                }
                Write-Warning "Tried $i times but bucket versioning not yet enabled. Retrying in 1 second."
            }
            $BucketVersioning | Should -Be "Enabled"

            Suspend-S3BucketVersioning -ProfileName $ProfileName -BucketName $BucketName

            foreach ($i in 1..$MAX_WAIT_TIME) {
                Start-Sleep -Seconds 1
                $BucketVersioning = Get-S3BucketVersioning -ProfileName $ProfileName -BucketName $BucketName
                if ($BucketVersioning -eq "Suspended") {
                    break
                }
                Write-Warning "Tried $i times but bucket versioning not yet enabled. Retrying in 1 second."
            }
            $BucketVersioning | Should -Be "Suspended"
        }

        It "Given -BucketName $UnicodeBucketName versioning is enabled and then suspended" -Skip:($ProfileName -match "minio") {
            Enable-S3BucketVersioning -ProfileName $ProfileName -BucketName $UnicodeBucketName

            foreach ($i in 1..$MAX_WAIT_TIME) {
                Start-Sleep -Seconds 1
                $BucketVersioning = Get-S3BucketVersioning -ProfileName $ProfileName -BucketName $UnicodeBucketName
                if ($BucketVersioning -eq "Enabled") {
                    break
                }
                Write-Warning "Tried $i times but bucket versioning not yet enabled. Retrying in 1 second."
            }
            $BucketVersioning | Should -Be "Enabled"

            Suspend-S3BucketVersioning -ProfileName $ProfileName -BucketName $UnicodeBucketName

            foreach ($i in 1..$MAX_WAIT_TIME) {
                Start-Sleep -Seconds 1
                $BucketVersioning = Get-S3BucketVersioning -ProfileName $ProfileName -BucketName $UnicodeBucketName
                if ($BucketVersioning -eq "Suspended") {
                    break
                }
                Write-Warning "Tried $i times but bucket versioning not yet enabled. Retrying in 1 second."
            }
            $BucketVersioning | Should -Be "Suspended"
        }
    }

    Context "Create, list and delete 10 Object Versions and Delete Markers in Versioning enabled Bucket" {

        It "Given -BucketName $BucketName and different keys, object versions and delete markers are created, listed and deleted successfully" -Skip:($ProfileName -match "minio") {
            Enable-S3BucketVersioning -ProfileName $ProfileName -BucketName $BucketName

            foreach ($i in 1..$MAX_WAIT_TIME) {
                Start-Sleep -Seconds 1
                $BucketVersioning = Get-S3BucketVersioning -ProfileName $ProfileName -BucketName $BucketName
                if ($BucketVersioning -eq "Enabled") {
                    break
                }
                Write-Warning "Tried $i times but bucket versioning not yet enabled. Retrying in 1 second."
            }
            $BucketVersioning | Should -Be "Enabled"

            foreach ($Key in 1..10) {
                # create object version
                Write-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $Key
                # create delete marker for previously created object version
                Remove-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $Key
            }

            $ObjectVersions = Get-S3ObjectVersions -ProfileName $ProfileName -BucketName $BucketName
            $Versions = $ObjectVersions | Where-Object { $_.Type -eq "Version" }
            $Versions.Count | Should -Be 10
            foreach ($Version in $Versions) {
                $Version.BucketName | Should -Be $BucketName
                $Version.Region | Should -Not -BeNullOrEmpty
                $Version.Key | Should -Not -BeNullOrEmpty
                $Version.VersionId | Should -Not -BeNullOrEmpty
                $Version.IsLatest | Should -BeFalse
                $Version.Type | Should -Be "Version"
                $Version.LastModified | Should -BeOfType DateTime
                $Version.ETag | Should -Not -BeNullOrEmpty
                $Version.Size | Should -BeGreaterOrEqual 0
                $Version.OwnerId | Should -Not -BeNullOrEmpty
                # $Version.OwnerDisplayName may be empty as AWS only retuns this for a few regions
                $Version.StorageClass | Should -Not -BeNullOrEmpty
            }
            $DeleteMarkers = $ObjectVersions | Where-Object { $_.Type -eq "DeleteMarker" }
            $DeleteMarkers.Count | Should -Be 10
            foreach ($DeleteMarker in $DeleteMarkers) {
                $DeleteMarker.BucketName | Should -Be $BucketName
                $DeleteMarker.Region | Should -Not -BeNullOrEmpty
                $DeleteMarker.Key | Should -Not -BeNullOrEmpty
                $DeleteMarker.VersionId | Should -Not -BeNullOrEmpty
                $DeleteMarker.IsLatest | Should -BeTrue
                $DeleteMarker.Type | Should -Be "DeleteMarker"
                $DeleteMarker.LastModified | Should -BeOfType DateTime
                # $DeleteMarker.ETag is usually empty
                $DeleteMarker.Size | Should -BeGreaterOrEqual 0
                $DeleteMarker.OwnerId | Should -Not -BeNullOrEmpty
                # $DeleteMarker.OwnerDisplayName may be empty as AWS only retuns this for a few regions
                # $DeleteMarker.StorageClass is usually empty
            }

            $ObjectVersions | Remove-S3ObjectVersion -ProfileName $ProfileName

            $ObjectVersions = Get-S3ObjectVersions -ProfileName $ProfileName -BucketName $BucketName
            $ObjectVersions | Should -BeNullOrEmpty
        }

        It "Given -BucketName $UnicodeBucketName and different keys, object versions and delete markers are created, listed and deleted successfully" -Skip:($ProfileName -match "minio") {
            Enable-S3BucketVersioning -ProfileName $ProfileName -BucketName $UnicodeBucketName

            foreach ($i in 1..$MAX_WAIT_TIME) {
                Start-Sleep -Seconds 1
                $BucketVersioning = Get-S3BucketVersioning -ProfileName $ProfileName -BucketName $BucketName
                if ($BucketVersioning -eq $Enabled) {
                    break
                }
                Write-Warning "Tried $i times but bucket versioning not yet enabled. Retrying in 1 second."
            }
            $BucketVersioning | Should -Be "Enabled"

            foreach ($Key in 1..10) {
                # create object version
                Write-S3Object -ProfileName $ProfileName -BucketName $UnicodeBucketName -Key $Key
                # create delete marker for previously created object version
                Remove-S3Object -ProfileName $ProfileName -BucketName $UnicodeBucketName -Key $Key
            }

            $ObjectVersions = Get-S3ObjectVersions -ProfileName $ProfileName -BucketName $UnicodeBucketName
            $Versions = $ObjectVersions | Where-Object { $_.Type -eq "Version" }
            $Versions.Count | Should -Be 10
            foreach ($Version in $Versions) {
                $Version.BucketName | Should -Be $UnicodeBucketName
                $Version.Region | Should -Not -BeNullOrEmpty
                $Version.Key | Should -Not -BeNullOrEmpty
                $Version.VersionId | Should -Not -BeNullOrEmpty
                $Version.IsLatest | Should -BeFalse
                $Version.Type | Should -Be "Version"
                $Version.LastModified | Should -BeOfType DateTime
                $Version.ETag | Should -Not -BeNullOrEmpty
                $Version.Size | Should -BeGreaterOrEqual 0
                $Version.OwnerId | Should -Not -BeNullOrEmpty
                # $Version.OwnerDisplayName may be empty as AWS only retuns this for a few regions
                $Version.StorageClass | Should -Not -BeNullOrEmpty
            }
            $DeleteMarkers = $ObjectVersions | Where-Object { $_.Type -eq "DeleteMarker" }
            $DeleteMarkers.Count | Should -Be 10
            foreach ($DeleteMarker in $DeleteMarkers) {
                $DeleteMarker.BucketName | Should -Be $UnicodeBucketName
                $DeleteMarker.Region | Should -Not -BeNullOrEmpty
                $DeleteMarker.Key | Should -Not -BeNullOrEmpty
                $DeleteMarker.VersionId | Should -Not -BeNullOrEmpty
                $DeleteMarker.IsLatest | Should -BeTrue
                $DeleteMarker.Type | Should -Be "DeleteMarker"
                $DeleteMarker.LastModified | Should -BeOfType DateTime
                # $DeleteMarker.ETag is usually empty
                $DeleteMarker.Size | Should -BeGreaterOrEqual 0
                $DeleteMarker.OwnerId | Should -Not -BeNullOrEmpty
                # $DeleteMarker.OwnerDisplayName may be empty as AWS only retuns this for a few regions
                # $DeleteMarker.StorageClass is usually empty
            }

            $ObjectVersions | Remove-S3ObjectVersion -ProfileName $ProfileName

            $ObjectVersions = Get-S3ObjectVersions -ProfileName $ProfileName -BucketName $UnicodeBucketName
            $ObjectVersions | Should -BeNullOrEmpty
        }
    }
}

Describe "S3 Bucket CORS Configuration" {

    BeforeAll {
        $BucketName = $BaseBucketName + "-bucket-cors"
        $UnicodeBucketName = $UnicodeBucketName + "-bucket-cors"

        $AllowedMethods = "GET","PUT","POST","DELETE"
        $AllowedOrigins = "netapp.com","*.example.org"
        $AllowedHeaders = "x-amz-meta-1","x-amz-meta-2"
        $MaxAgeSeconds = 3000
        $ExposeHeaders = "x-amz-server-side-encryption"

        Setup -BucketName $BucketName
        Setup -BucketName $UnicodeBucketName
    }

    AfterAll {
        Cleanup -BucketName $BucketName
        Cleanup -BucketName $UnicodeBucketName
    }

    Context "Set Bucket CORS Configuration" {
        It "Given -BucketName $BucketName -Id $BucketName -AllowedMethods $AllowedMethods -AllowedOrigins $AllowedOrigins -AllowedHeaders $AllowedHeaders -MaxAgeSeconds $MaxAgeSeconds -ExposeHeaders $ExposeHeaders a CORS Configuration rule is added" -Skip:($ProfileName -match "mini") {
            $Id = "BucketName"
            Add-S3BucketCorsConfigurationRule -ProfileName $ProfileName -BucketName $BucketName -Id $Id -AllowedMethods $AllowedMethods -AllowedOrigins $AllowedOrigins -AllowedHeaders $AllowedHeaders -MaxAgeSeconds $MaxAgeSeconds -ExposeHeaders $ExposeHeaders

            foreach ($i in 1..120) {
                Start-Sleep -Seconds 1
                $CorsConfiguration = Get-S3BucketCorsConfiguration -ProfileName $ProfileName -BucketName $BucketName
                if ($CorsConfiguration) {
                    break
                }
                Write-Warning "Tried $i times but CORS configuration does not exist yet. Retrying in 1 second."
            }
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

            foreach ($i in 1..120) {
                Start-Sleep -Seconds 1
                $CorsConfiguration = Get-S3BucketCorsConfiguration -ProfileName $ProfileName -BucketName $UnicodeBucketName
                if ($CorsConfiguration) {
                    break
                }
                Write-Warning "Tried $i times but CORS configuration does not exist yet. Retrying in 1 second."
            }
            $CorsConfiguration.Id | Should -Be $Id
            $CorsConfiguration.AllowedMethod | Should -Be $AllowedMethods
            $CorsConfiguration.AllowedOrigin | Should -Be $AllowedOrigins
        }

        It "Given -BucketName $BucketName -Id `"remove`" a CORS configuration rule is removed" {
            $Id = "Remove"
            Add-S3BucketCorsConfigurationRule -ProfileName $ProfileName -BucketName $BucketName -Id $Id -AllowedMethods $AllowedMethods -AllowedOrigins $AllowedOrigins

            foreach ($i in 1..120) {
                Start-Sleep -Seconds 1
                $CorsConfigurationRule = Get-S3BucketCorsConfigurationRule -ProfileName $ProfileName -BucketName $BucketName -Id $Id
                if ($CorsConfigurationRule) {
                    break
                }
                Write-Warning "Tried $i times but CORS configuration does not exist yet. Retrying in 1 second."
            }
            $CorsConfigurationRule.Id | Should -Be $Id
            $CorsConfigurationRule | Remove-S3BucketCorsConfigurationRule -ProfileName $ProfileName

            foreach ($i in 1..120) {
                Start-Sleep -Seconds 1
                $CorsConfigurationRule = Get-S3BucketCorsConfigurationRule -ProfileName $ProfileName -BucketName $BucketName -Id $Id
                if (!$CorsConfigurationRule) {
                    break
                }
                Write-Warning "Tried $i times but CORS configuration does still exist. Retrying in 1 second."
            }
            $CorsConfigurationRule | Should -BeNullOrEmpty
        }

        It "Given -BucketName $BucketName all CORS configuration is removed" {
            $Id = "RemoveAll"
            Add-S3BucketCorsConfigurationRule -ProfileName $ProfileName -BucketName $BucketName -Id $Id -AllowedMethods $AllowedMethods -AllowedOrigins $AllowedOrigins

            foreach ($i in 1..120) {
                Start-Sleep -Seconds 1
                $CorsConfigurationRule = Get-S3BucketCorsConfigurationRule -ProfileName $ProfileName -BucketName $BucketName -Id $Id
                if ($CorsConfigurationRule) {
                    break
                }
                Write-Warning "Tried $i times but CORS configuration does not exist yet. Retrying in 1 second."
            }
            $CorsConfigurationRule.Id | Should -Be $Id

            Remove-S3BucketCorsConfiguration -ProfileName $ProfileName -BucketName $BucketName
            foreach ($i in 1..120) {
                Start-Sleep -Seconds 1
                $CorsConfiguration = Get-S3BucketCorsConfiguration -ProfileName $ProfileName -BucketName $BucketName
                if (!$CorsConfiguration) {
                    break
                }
                Write-Warning "Tried $i times but CORS configuration does not exist yet. Retrying in 1 second."
            }
            $CorsConfiguration | Should -BeNullOrEmpty
        }
    }
}

Describe "S3 Bucket Replication Configuration" {

    BeforeAll {
        $BucketName = $BaseBucketName + "-bucket-replication"
        $UnicodeBucketName = $UnicodeBucketName + "-bucket-replication"

        $DestinationBucketName = $BucketName + "-dst"
        $DestinationUnicodeBucketName = $UnicodeBucketName +  "-dst"
        $DestinationRegion = "us-east-2"
        $AwsProfile = Get-AwsConfig -ProfileName "AWS"
        $Role = "arn:aws:iam::953312134057:role/S3-Full-Access"

        # for AWS several steps must be done to prepare the user to be able to use replication
        # see https://docs.aws.amazon.com/AmazonS3/latest/dev/crr.html

        Setup -BucketName $BucketName -Versioning
        Setup -BucketName $DestinationBucketName -Versioning -Region $DestinationRegion -ProfileName AWS

        Setup -BucketName $UnicodeBucketName -Versioning
        Setup -BucketName $DestinationUnicodeBucketName -Versioning -Region $DestinationRegion -ProfileName AWS

        if ($ProfileName -match "webscaledemo") {
            $EndpointConfiguration = Add-SgwEndpoint -ProfileName $ProfileName -DisplayName $DestinationBucketName -EndpointUri "https://s3.us-east-2.amazonaws.com" -EndpointUrn "arn:aws:s3:::$DestinationBucketName" -AccessKey $AwsProfile.AccessKey -SecretAccessKey $AwsProfile.SecretKey -ErrorAction Stop
            $UnicodeEndpointConfiguration = Add-SgwEndpoint -ProfileName $ProfileName -DisplayName $DestinationUnicodeBucketName -EndpointUri "https://s3.us-east-2.amazonaws.com" -EndpointUrn "arn:aws:s3:::$DestinationUnicodeBucketName" -AccessKey $AwsProfile.AccessKey -SecretAccessKey $AwsProfile.SecretKey -ErrorAction Stop
            sleep 5
        }
    }

    AfterAll {
        Cleanup -BucketName $BucketName
        Cleanup -BucketName $DestinationBucketName -Region $DestinationRegion -ProfileName AWS

        Cleanup -BucketName $UnicodeBucketName
        Cleanup -BucketName $DestinationUnicodeBucketName -Region $DestinationRegion -ProfileName "AWS"

        if ($ProfileName -match "webscaledemo") {
            $EndpointConfiguration | Remove-SgwEndpoint -ProfileName $ProfileName
            $UnicodeEndpointConfiguration | Remove-SgwEndpoint -ProfileName $ProfileName
        }
    }

    Context "Set Bucket Replication Configuration" {
        It "Given -BucketName $BucketName -Id $BucketName -DestinationBucketUrn arn:aws:s3:::$DestinationBucketName -Role $Role a replication rule should be added" -Skip:($ProfileName -match "minio") {
            Add-S3BucketReplicationConfigurationRule -ProfileName $ProfileName -BucketName $BucketName -Id $BucketName -DestinationBucketUrn "arn:aws:s3:::$DestinationBucketName" -Role $Role

            foreach ($i in 1..120) {
                Start-Sleep -Seconds 1
                $BucketReplication = Get-S3BucketReplicationConfigurationRule -ProfileName $ProfileName -BucketName $BucketName
                if ($BucketReplication) {
                    break
                }
                Write-Host "Tried $i times but bucket replication does not exist yet. Retrying in 1 second."
            }
            $BucketReplication.BucketName | Should -Be $BucketName
            $BucketReplication.Role | Should -Be $Role
            $BucketReplication.Id | Should -Be $BucketName
            $BucketReplication.Status | Should -Be "Enabled"
            $BucketReplication.DestinationBucketName | Should -Be $DestinationBucketName

            Write-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $Key

            foreach ($i in 1..120) {
                Start-Sleep -Seconds 1
                $DestinationObject = Get-S3Objects -ProfileName "AWS" -BucketName $DestinationBucketName -Region $DestinationRegion -Key $Key
                if ($DestinationObject) {
                    break
                }
                Write-Host "Tried $i times but destination object does not exist yet. Retrying in 1 second."
            }
            $DestinationObject.Key | Should -Be $Key
        }
    }

    Context "Set Bucket Replication Configuration for bucket with unicode characters"  {
        It "Given -BucketName $UnicodeBucketName -Id $UnicodeBucketName -DestinationBucketName arn:aws:s3:::$DestinationUnicodeBucketName -Role $Role a replication rule should be added" -Skip:($ProfileName -match "minio") {
            Add-S3BucketReplicationConfigurationRule -ProfileName $ProfileName -BucketName $UnicodeBucketName -Id $UnicodeBucketName -DestinationBucketUrn "arn:aws:s3:::$DestinationUnicodeBucketName" -Role $Role

            foreach ($i in 1..120) {
                Start-Sleep -Seconds 1
                $BucketReplication = Get-S3BucketReplicationConfigurationRule -ProfileName $ProfileName -BucketName $UnicodeBucketName
                if ($BucketReplication) {
                    break
                }
                Write-Host "Tried $i times but bucket replication does not exist yet. Retrying in 1 second."
            }

            $BucketReplication.BucketName | Should -Be $UnicodeBucketName
            $BucketReplication.Role | Should -Be $Role
            $BucketReplication.Id | Should -Be $UnicodeBucketName
            $BucketReplication.Status | Should -Be "Enabled"
            $BucketReplication.DestinationBucketName | Should -Be $DestinationUnicodeBucketName

            Write-S3Object -ProfileName $ProfileName -BucketName $UnicodeBucketName -Key $UnicodeKey

            foreach ($i in 1..120) {
                Start-Sleep -Seconds 1
                $DestinationObject = Get-S3Objects -ProfileName "AWS" -BucketName $DestinationUnicodeBucketName -Region $DestinationRegion -Key $UnicodeKey
                if ($DestinationObject) {
                    break
                }
            }

            $DestinationObject.Key | Should -Be $UnicodeKey
        }
    }
}

$SmallFile | Remove-Item
$LargeFile | Remove-Item