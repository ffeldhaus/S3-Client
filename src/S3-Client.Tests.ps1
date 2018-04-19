Import-Module "$PSScriptRoot\S3-Client" -Force

Write-Host "Running S3 Client tests"

$Bucket = Get-Date -Format "yyyy-MM-dd-HHmmss"
$UnicodeBucket = "萬國碼-" + $Bucket
$Key = "Key"
$UnicodeKey = "萬國碼-$Key"
$Content = "Hello World!"
$CustomMetadata = @{"MetadataKey"="MetadataValue"}
$Profiles = Get-AwsProfiles

function Cleanup() {
    try {
        Remove-S3Bucket -Profile $Profile -Bucket $Bucket -Force
    }
    catch {}
    try {
        Remove-S3Bucket -Profile $Profile -Bucket $UnicodeBucket -Force
    }
    catch {}
    # AWS requires some time after buckets have been deleted before they can be recreated
    sleep 10
}

foreach ($Profile in $Profiles.Profile) {
    Describe "Profile $Profile : New-S3Bucket" {
        AfterEach {
            Cleanup
        }

        Context "Create new bucket with default parameters" {
            It "Given -Bucket $Bucket it is succesfully created" {
                New-S3Bucket -Profile $Profile -Bucket $Bucket
                $NewBucket = Get-S3Buckets -Profile $Profile -Bucket $Bucket
                $NewBucket.Name | Should -Be $Bucket
            }

            It "Given -Bucket $UnicodeBucket it is succesfully created" {
                New-S3Bucket -Profile $Profile -Bucket $UnicodeBucket
                $NewBucket = Get-S3Buckets -Profile $Profile -Bucket $UnicodeBucket
                $NewBucket.Name | Should -Be $UnicodeBucket
            }
        }

        Context "Create new bucket with parameter -UrlStyle virtual-hosted" {
            It "Given -Bucket $Bucket and -UrlStyle virtual-hosted it is succesfully created" {
                New-S3Bucket -Profile $Profile -Bucket $Bucket -UrlStyle virtual-hosted
                $NewBucket = Get-S3Buckets -Profile $Profile -Bucket $Bucket
                $NewBucket.Name | Should -Be $Bucket
            }
        }
    }

    Describe "Profile $Profile : Get-S3Buckets" {
        AfterEach {
            Cleanup
        }

        Context "Retrieve buckets with default parameters" {
            It "Retrieving buckets returns a list of all buckets" {
                $Buckets = Get-S3Buckets -Profile $Profile
                $BucketCount = $Buckets.Count
                New-S3Bucket -Profile $Profile -Bucket $Bucket
                $Buckets = Get-S3Buckets -Profile $Profile
                $Buckets.Count | Should -Be ($BucketCount + 1)
            }
        }
    }

    Describe "Profile $Profile : Remove-S3Bucket" {
        AfterEach {
            Cleanup
        }

        Context "Remove bucket with default parameters" {
            It "Given existing -Bucket $Bucket it is succesfully removed" {
                New-S3Bucket -Profile $Profile -Bucket $Bucket
                $NewBucket = Get-S3Buckets -Profile $Profile -Bucket $Bucket
                $NewBucket.Name | Should -Be $Bucket
                Remove-S3Bucket -Profile $Profile -Bucket $Bucket
                $NewBucket = Get-S3Buckets -Profile $Profile -Bucket $Bucket
                $NewBucket | Should -BeNullOrEmpty
            }
        }

        Context "Remove bucket with default parameters" {
            It "Given existing -Bucket $UnicodeBucket it is succesfully removed" {
                New-S3Bucket -Profile $Profile -Bucket $UnicodeBucket
                $NewBucket = Get-S3Buckets -Profile $Profile -Bucket $UnicodeBucket
                $NewBucket.Name | Should -Be $UnicodeBucket
                Remove-S3Bucket -Profile $Profile -Bucket $UnicodeBucket
                $NewBucket = Get-S3Buckets -Profile $Profile -Bucket $UnicodeBucket
                $NewBucket | Should -BeNullOrEmpty
            }
        }
    }

    Describe "Profile $Profile : Write-S3Object" {
        BeforeEach {
            New-S3Bucket -Profile $Profile -Bucket $Bucket
        }

        AfterEach {
            Cleanup
        }

        Context "Upload text" {
            It "Given -Content `"$Content`" it is succesfully created" {
                Write-S3Object -Profile $Profile -Bucket $Bucket -Key $Key -Content $Content
                $Objects = Get-S3Objects -Profile $Profile -Bucket $Bucket
                $Key | Should -BeIn $Objects.Key
                $ObjectContent = Read-S3Object -Profile $Profile -Bucket $Bucket -Key $Key
                $ObjectContent | Should -Be $Content
            }
        }

        Context "Upload text to object with key containing unicode characters" {
            It "Given -Content `"$Content`" it is succesfully created" {
                Write-S3Object -Profile $Profile -Bucket $Bucket -Key $UnicodeKey -Content $Content
                $Objects = Get-S3Objects -Profile $Profile -Bucket $Bucket -Key $UnicodeKey
                $UnicodeKey | Should -BeIn $Objects.Key
                $ObjectContent = Read-S3Object -Profile $Profile -Bucket $Bucket -Key $UnicodeKey
                $ObjectContent | Should -Be $Content
            }
        }
    }

    Describe "Profile $Profile : Copy-S3Object" {
        BeforeEach {
            New-S3Bucket -Profile $Profile -Bucket $Bucket
            Write-S3Object -Profile $Profile -Bucket $Bucket -Key $Key -Content $Content -Metadata $CustomMetadata
        }

        AfterEach {
            Cleanup
        }

        Context "Copy object" {
            It "Given -SourceBucket $Bucket and -SourceKey $Key and -Bucket $Bucket and -Key $Key it is copied to itself" {
                $CustomMetadata = Get-S3ObjectMetadata -Profile $Profile -Bucket $Bucket -Key $Key | Select -ExpandProperty CustomMetadata
                Copy-S3Object -Profile $Profile -Bucket $Bucket -Key $Key -SourceBucket $Bucket -SourceKey $Key -MetadataDirective "REPLACE" -Metadata $CustomMetadata
                Get-S3Bucket -Profile $Profile -Bucket $Bucket -Key $Key
            }
        }
    }
}