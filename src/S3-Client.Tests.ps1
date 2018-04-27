Import-Module "$PSScriptRoot\S3-Client" -Force

Write-Host "Running S3 Client tests"

$SLEEP_SECONDS_AFTER_BUCKET_DELETION = 60

$Bucket = Get-Date -Format "yyyy-MM-dd-HHmmss"
$UnicodeBucket = [System.Globalization.IdnMapping]::new().GetUnicode("xn--9csy79e60h") + "-$Bucket"
$Key = "Key"
$UnicodeKey = [System.Globalization.IdnMapping]::new().GetUnicode("xn--9csy79e60h") + "-$Key"
$Content = "Hello World!"
$CustomMetadata = @{"MetadataKey"="MetadataValue"}
$Profiles = Get-AwsProfiles | Where-Object { $_.ProfileName -match "AWS|webscaledemo" }

function Cleanup() {
    try {
        Remove-S3Bucket -ProfileName $ProfileName -BucketName $Bucket -Force
    }
    catch {}
    # wait until bucket is really deleted
    foreach ($i in 1..$SLEEP_SECONDS_AFTER_BUCKET_DELETION) {
        try {
            Write-Host "test"
            Test-S3Bucket -ProfileName $ProfileName -BucketName $Bucket
            sleep 1
        }
        catch {
            break
        }
    }

    try {
        Remove-S3Bucket -ProfileName $ProfileName -BucketName $UnicodeBucket -Force
    }
    catch {}
    # wait until bucket is really deleted
    foreach ($i in 1..$SLEEP_SECONDS_AFTER_BUCKET_DELETION) {
        try {
            Write-Host "test"
            Test-S3Bucket -ProfileName $ProfileName -BucketName $UnicodeBucket
            sleep 1
        }
        catch {
            break
        }
    }
}

foreach ($ProfileName in $Profiles.ProfileName) {
    Describe "Profile $ProfileName : New-S3Bucket" {
        AfterEach {
            Cleanup
        }

        Context "Create new bucket with default parameters" {
            It "Given -BucketName $Bucket it is succesfully created" {
                New-S3Bucket -ProfileName $ProfileName -BucketName $Bucket
                $NewBucket = Get-S3Buckets -ProfileName $ProfileName -BucketName $Bucket
                $NewBucket.Name | Should -Be $Bucket
            }

            It "Given -BucketName $UnicodeBucket it is succesfully created" {
                New-S3Bucket -ProfileName $ProfileName -BucketName $UnicodeBucket
                $NewBucket = Get-S3Buckets -ProfileName $ProfileName -BucketName $UnicodeBucket
                $NewBucket.Name | Should -Be $UnicodeBucket
            }
        }

        Context "Create new bucket with parameter -UrlStyle virtual-hosted" {
            It "Given -BucketName $Bucket and -UrlStyle virtual-hosted it is succesfully created" {
                New-S3Bucket -ProfileName $ProfileName -BucketName $Bucket -UrlStyle virtual-hosted
                $NewBucket = Get-S3Buckets -ProfileName $ProfileName -BucketName $Bucket
                $NewBucket.Name | Should -Be $Bucket
            }
        }
    }

    Describe "Profile $ProfileName : Get-S3Buckets" {
        AfterEach {
            Cleanup
        }

        Context "Retrieve buckets with default parameters" {
            It "Retrieving buckets returns a list of all buckets" {
                $Buckets = Get-S3Buckets -ProfileName $ProfileName
                $BucketCount = $Buckets.Count
                New-S3Bucket -ProfileName $ProfileName -BucketName $Bucket
                $Buckets = Get-S3Buckets -ProfileName $ProfileName
                $Buckets.Count | Should -Be ($BucketCount + 1)
            }
        }
    }

    Describe "Profile $ProfileName : Remove-S3Bucket" {
        AfterEach {
            Cleanup
        }

        Context "Remove bucket with default parameters" {
            It "Given existing -BucketName $Bucket it is succesfully removed" {
                New-S3Bucket -ProfileName $ProfileName -BucketName $Bucket
                $NewBucket = Get-S3Buckets -ProfileName $ProfileName -BucketName $Bucket
                $NewBucket.Name | Should -Be $Bucket
                Remove-S3Bucket -ProfileName $ProfileName -BucketName $Bucket
                $NewBucket = Get-S3Buckets -ProfileName $ProfileName -BucketName $Bucket
                $NewBucket | Should -BeNullOrEmpty
            }
        }

        Context "Remove bucket with default parameters" {
            It "Given existing -BucketName $UnicodeBucket it is succesfully removed" {
                New-S3Bucket -ProfileName $ProfileName -BucketName $UnicodeBucket
                $NewBucket = Get-S3Buckets -ProfileName $ProfileName -BucketName $UnicodeBucket
                $NewBucket.Name | Should -Be $UnicodeBucket
                Remove-S3Bucket -ProfileName $ProfileName -BucketName $UnicodeBucket
                $NewBucket = Get-S3Buckets -ProfileName $ProfileName -BucketName $UnicodeBucket
                $NewBucket | Should -BeNullOrEmpty
            }
        }
    }

    Describe "Profile $ProfileName : Write-S3Object" {
        New-S3Bucket -ProfileName $ProfileName -BucketName $Bucket

        Context "Upload text" {
            It "Given -Content `"$Content`" it is succesfully created" {
                Write-S3Object -ProfileName $ProfileName -BucketName $Bucket -Key $Key -Content $Content
                $Objects = Get-S3Objects -ProfileName $ProfileName -BucketName $Bucket
                $Key | Should -BeIn $Objects.Key
                $ObjectContent = Read-S3Object -ProfileName $ProfileName -BucketName $Bucket -Key $Key
                $ObjectContent | Should -Be $Content
            }
        }

        Context "Upload text to object with key containing unicode characters" {
            It "Given -Content `"$Content`" it is succesfully created" {
                Write-S3Object -ProfileName $ProfileName -BucketName $Bucket -Key $UnicodeKey -Content $Content
                $Objects = Get-S3Objects -ProfileName $ProfileName -BucketName $Bucket -Key $UnicodeKey
                $UnicodeKey | Should -BeIn $Objects.Key
                $ObjectContent = Read-S3Object -ProfileName $ProfileName -BucketName $Bucket -Key $UnicodeKey
                $ObjectContent | Should -Be $Content
            }
        }

        Cleanup
    }

    Describe "Profile $ProfileName : Copy-S3Object" {
        New-S3Bucket -ProfileName $ProfileName -BucketName $Bucket
        Write-S3Object -ProfileName $ProfileName -BucketName $Bucket -Key $Key -Content $Content -Metadata $CustomMetadata

        Context "Copy object" {
            It "Given -SourceBucket $Bucket and -SourceKey $Key and -BucketName $Bucket and -Key $Key it is copied to itself" {
                $CustomMetadata = Get-S3ObjectMetadata -ProfileName $ProfileName -BucketName $Bucket -Key $Key | Select -ExpandProperty CustomMetadata
                Copy-S3Object -ProfileName $ProfileName -BucketName $Bucket -Key $Key -SourceBucket $Bucket -SourceKey $Key -MetadataDirective "REPLACE" -Metadata $CustomMetadata
                Get-S3Bucket -ProfileName $ProfileName -BucketName $Bucket -Key $Key
            }
        }

        Cleanup
    }
}