Import-Module "$PSScriptRoot\S3-Client" -Force

Write-Host "Running S3 Client tests"

$BucketName = Get-Date -Format "yyyy-MM-dd-HHmmss"
$UnicodeBucketName = [System.Globalization.IdnMapping]::new().GetUnicode("xn--9csy79e60h") + "-$BucketName"
$Key = "Key"
$UnicodeKey = [System.Globalization.IdnMapping]::new().GetUnicode("xn--9csy79e60h") + "-$Key"
$Content = "Hello World!"
$CustomMetadata = @{"MetadataKey"="MetadataValue"}
$Profiles = Get-AwsProfiles | Where-Object { $_.ProfileName -match "AWS|webscaledemo" }

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

foreach ($ProfileName in $Profiles.ProfileName) {
    Describe "Profile $ProfileName : Get-S3Buckets" {
        Setup

        Context "Retrieve buckets with default parameters" {
            It "Retrieving buckets returns a list of all buckets" {
                $BucketNames = Get-S3Buckets -ProfileName $ProfileName
                $BucketNames.BucketName | Should -Contain $BucketName
                $BucketNames.BucketName | Should -Contain $UnicodeBucketName
            }
        }

        Context "Retrieve buckets with parameter -BucketName" {
            It "Retrieving a specific, existing bucket with parameter -BucketName $BucketName returns only that bucket" {
                $BucketNames = Get-S3Buckets -ProfileName $ProfileName -BucketName $BucketName
                $BucketNames.Count | Should -Be 1
                $BucketNames.BucketName | Should -Be $BucketName
            }

            It "Retrieving a specific, existing bucket with parameter -BucketName $UnicodeBucketName returns only that bucket" {
                $BucketNames = Get-S3Buckets -ProfileName $ProfileName -BucketName $UnicodeBucketName
                $BucketNames.Count | Should -Be 1
                $BucketNames.BucketName | Should -Be $UnicodeBucketName
            }
        }

        Cleanup
    }

    Describe "Profile $ProfileName : Test-S3Bucket" {
        AfterEach {
            Cleanup
        }

        Context "Test bucket existance with default parameters" {
            It "Given existing bucket -BucketName $BucketName `$true is returned" {
                New-S3Bucket -ProfileName $ProfileName -BucketName $BucketName
                Test-S3Bucket -ProfileName $ProfileName -BucketName $BucketName | Should -BeTrue
            }
        }
    }

    Describe "Profile $ProfileName : New-S3Bucket" {
        AfterEach {
            Cleanup
        }

        Context "Create new bucket with default parameters" {
            It "Given -BucketName $BucketName it is succesfully created" {
                New-S3Bucket -ProfileName $ProfileName -BucketName $BucketName
                $NewBucket = Get-S3Buckets -ProfileName $ProfileName -BucketName $BucketName
                $NewBucket.BucketName | Should -Be $BucketName
            }

            It "Given -BucketName $UnicodeBucketName it is succesfully created" {
                New-S3Bucket -ProfileName $ProfileName -BucketName $UnicodeBucketName
                $NewBucket = Get-S3Buckets -ProfileName $ProfileName -BucketName $UnicodeBucketName
                $NewBucket.BucketName | Should -Be $UnicodeBucketName
            }
        }

        Context "Create new bucket with parameter -UrlStyle virtual-hosted" {
            It "Given -BucketName $BucketName and -UrlStyle virtual-hosted it is succesfully created" {
                New-S3Bucket -ProfileName $ProfileName -BucketName $BucketName -UrlStyle virtual-hosted
                $NewBucket = Get-S3Buckets -ProfileName $ProfileName -BucketName $BucketName
                $NewBucket.BucketName | Should -Be $BucketName
            }
        }
    }

    Describe "Profile $ProfileName : Remove-S3Bucket" {
        AfterEach {
            Cleanup
        }

        Context "Remove bucket with default parameters" {
            It "Given existing -BucketName $BucketName it is succesfully removed" {
                New-S3Bucket -ProfileName $ProfileName -BucketName $BucketName
                $NewBucket = Get-S3Buckets -ProfileName $ProfileName -BucketName $BucketName
                $NewBucket.BucketName | Should -Be $BucketName
                Remove-S3Bucket -ProfileName $ProfileName -BucketName $BucketName
                $NewBucket = Get-S3Buckets -ProfileName $ProfileName -BucketName $BucketName
                $NewBucket | Should -BeNullOrEmpty
            }
        }

        Context "Remove bucket with default parameters" {
            It "Given existing -BucketName $UnicodeBucketName it is succesfully removed" {
                New-S3Bucket -ProfileName $ProfileName -BucketName $UnicodeBucketName
                $NewBucket = Get-S3Buckets -ProfileName $ProfileName -BucketName $UnicodeBucketName
                $NewBucket.BucketName | Should -Be $UnicodeBucketName
                Remove-S3Bucket -ProfileName $ProfileName -BucketName $UnicodeBucketName
                $NewBucket = Get-S3Buckets -ProfileName $ProfileName -BucketName $UnicodeBucketName
                $NewBucket | Should -BeNullOrEmpty
            }
        }
    }

    Describe "Profile $ProfileName : Write-S3Object" {
        New-S3Bucket -ProfileName $ProfileName -BucketName $BucketName

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

        Cleanup
    }

    Describe "Profile $ProfileName : Copy-S3Object" {
        New-S3Bucket -ProfileName $ProfileName -BucketName $BucketName
        Write-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $Key -Content $Content -Metadata $CustomMetadata

        Context "Copy object" {
            It "Given -SourceBucket $BucketName and -SourceKey $Key and -BucketName $BucketName and -Key $Key it is copied to itself" {
                $CustomMetadata = Get-S3ObjectMetadata -ProfileName $ProfileName -BucketName $BucketName -Key $Key | Select -ExpandProperty CustomMetadata
                Copy-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $Key -SourceBucket $BucketName -SourceKey $Key -MetadataDirective "REPLACE" -Metadata $CustomMetadata
                Get-S3Object -ProfileName $ProfileName -BucketName $BucketName -Key $Key
            }
        }

        Cleanup
    }
}