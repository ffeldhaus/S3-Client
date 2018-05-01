$AWS_PROFILE_PATH = "$HOME/.aws/"
$AWS_CREDENTIALS_FILE = $AWS_PROFILE_PATH + "credentials"

# workarounds for PowerShell issues
if ($PSVersionTable.PSVersion.Major -lt 6) {
    Add-Type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
           public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem) {
                return true;
            }
        }
"@

    # Using .NET JSON Serializer as JSON serialization included in Invoke-WebRequest has a length restriction for JSON content
    Add-Type -AssemblyName System.Web.Extensions
    $global:javaScriptSerializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $global:javaScriptSerializer.MaxJsonLength = [System.Int32]::MaxValue
    $global:javaScriptSerializer.RecursionLimit = 99
}
else {
    # unfortunately AWS Authentication is not RFC-7232 compliant (it is using semicolons in the value) 
    # and PowerShell 6 enforces strict header verification by default
    # therefore disabling strict header verification until AWS fixed this
    $PSDefaultParameterValues.Add("Invoke-WebRequest:SkipHeaderValidation",$true)
}

### Helper Functions ###

function ParseErrorForResponseBody($Error) {
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        if ($Error.Exception.Response) {  
            $Reader = New-Object System.IO.StreamReader($Error.Exception.Response.GetResponseStream())
            $Reader.BaseStream.Position = 0
            $Reader.DiscardBufferedData()
            $ResponseBody = $Reader.ReadToEnd()
            if ($ResponseBody.StartsWith('{')) {
                $ResponseBody = $ResponseBody | ConvertFrom-Json | ConvertTo-Json
            }
            return $ResponseBody
        }
    }
    else {
        return $Error.ErrorDetails.Message
    }
}

function ConvertTo-SortedDictionary($HashTable) {
    $SortedDictionary = New-Object 'System.Collections.Generic.SortedDictionary[string, string]'
    foreach ($Key in $HashTable.Keys) {
        $SortedDictionary[$Key]=$HashTable[$Key]
    }
    Write-Output $SortedDictionary
}

function Get-SignedString {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory=$True,
                    Position=0,
                    ValueFromPipeline=$True,
                    ValueFromPipelineByPropertyName=$True,
                    HelpMessage="Key in Bytes.")][Byte[]]$Key,
        [parameter(Mandatory=$False,
                    Position=1,
                    ValueFromPipeline=$True,
                    ValueFromPipelineByPropertyName=$True,
                    HelpMessage="Unit of timestamp.")][String]$Message="",
        [parameter(Mandatory=$False,
                    Position=2,
                    HelpMessage="Algorithm to use for signing.")][ValidateSet("SHA1","SHA256")][String]$Algorithm="SHA256"
    )

    PROCESS {
        if ($Algorithm -eq "SHA1") {
            $Signer = New-Object System.Security.Cryptography.HMACSHA1
        }
        else {
            $Signer = New-Object System.Security.Cryptography.HMACSHA256
        }

        $Signer.Key = $Key
        $Signer.ComputeHash([Text.Encoding]::UTF8.GetBytes($Message))
    }
}

function Sign($Key,$Message) {
    $hmacsha = New-Object System.Security.Cryptography.HMACSHA256
    $hmacsha.Key = $Key
    $hmacsha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Message))
}

function GetSignatureKey($Key, $Date, $Region, $Service) {
    $SignedDate = sign ([Text.Encoding]::UTF8.GetBytes(('AWS4' + $Key).toCharArray())) $Date
    $SignedRegion = sign $SignedDate $Region
    $SignedService = sign $SignedRegion $Service
    sign $SignedService "aws4_request"
}

function ConvertFrom-AwsConfigFile {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="AWS Config File")][String]$AwsConfigFile
    )

    Process {
        if (!(Test-Path $AwsConfigFile))
        {
            throw "Config file $AwsConfigFile does not exist!"
        }

        Write-Verbose "Reading AWS Configuration from $AwsConfigFile"

        $Content = Get-Content -Path $AwsConfigFile -Raw
        # replace all carriage returns
        $Content = $Content -replace "`r",""
        # remove empty lines
        $Content = $Content -replace "(`n$)*", ""
        # convert to JSON structure
        $Content = $Content -replace "profile ", ""
        $Content = $Content -replace "`n([^\[])", ',$1'
        $Content = $Content -replace "\[", "{`"ProfileName = "
        $Content = $Content -replace "]", ""
        $Content = $Content -replace "\s*=\s*", "`":`""
        $Content = $Content -replace ",", "`",`""
        $Content = $Content -replace "`n", "`"},"
        $Content = $Content -replace "^", "["
        $Content = $Content -replace "$", "`"}]"
        $Content = $Content -replace "{`"}", "{}"

        # parse JSON
        Write-Debug "Content to convert:`n$Content"

        if ($Content -match "{.*}") {
            $Config = ConvertFrom-Json -InputObject $Content
            $Config = $Config | Select-Object -Property ProfileName, aws_access_key_id, aws_secret_access_key, region, endpoint_url
            Write-Output $Config
        }
    }
}

function ConvertTo-AwsConfigFile {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="Config to store in config file")][PSObject[]]$Config,
        [parameter(
            Mandatory=$True,
            Position=1,
            HelpMessage="AWS Config File")][String]$AwsConfigFile
    )

    Process {
        if (!(Test-Path $AwsConfigFile)) {
            New-Item -Path $AwsConfigFile -ItemType File -Force
        }

        Write-Verbose "Writing AWS Configuration to $AwsConfigFile"

        $Output = ""
        if ($AwsConfigFile -match "credentials$")
        {
            foreach ($ConfigEntry in $Config) {
                $Output += "[$( $ConfigEntry.ProfileName )]`n"
                $Output += "aws_access_key_id = $($ConfigEntry.aws_access_key_id)`n"
                $Output += "aws_secret_access_key = $($ConfigEntry.aws_secret_access_key)`n"
            }
        }
        else {
            foreach ($ConfigEntry in $Config) {
                if ($ConfigEntry.ProfileName -eq "default")
                {
                    $Output += "[$( $ConfigEntry.ProfileName )]`n"
                }
                else
                {
                    $Output += "[profile $( $ConfigEntry.ProfileName )]`n"
                }
                $Properties = $Config | Select-Object -ExcludeProperty aws_access_key_id, aws_secret_access_key, ProfileName | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
                foreach ($Property in $Properties)
                {
                    if ($ConfigEntry.$Property)
                    {
                        $Output += "$Property = $( $ConfigEntry.$Property )`n"
                    }
                }
            }
        }
        Write-Debug "Output:`n$Output"
        $Output | Out-File -FilePath $AwsConfigFile -NoNewline
    }
}

# helper function to convert datetime to unix timestamp
function ConvertTo-UnixTimestamp {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory=$True,
                Position=0,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Date to be converted.")][DateTime[]]$Date,
        [parameter(Mandatory=$True,
                Position=1,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Unit of timestamp.")][ValidateSet("Seconds","Milliseconds")][String]$Unit="Milliseconds"
    )

    BEGIN {
        $epoch = Get-Date -Year 1970 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0
    }

    PROCESS {
        if ($Unit="Seconds") {
            Write-Output ([math]::truncate($Date.ToUniversalTime().Subtract($epoch).TotalSeconds))
        }
        else {
            Write-Output ([math]::truncate($Date.ToUniversalTime().Subtract($epoch).TotalMilliSeconds))
        }
    }
}

# helper function to convert unix timestamp to datetime
function ConvertFrom-UnixTimestamp {
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory=$True,
                Position=0,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Timestamp to be converted.")][String]$Timestamp,
        [parameter(Mandatory=$True,
                Position=0,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Unit of timestamp.")][ValidateSet("Seconds","Milliseconds")][String]$Unit="Milliseconds",
        [parameter(Mandatory=$False,
                Position=1,
                HelpMessage="Optional Timezone to be used as basis for Timestamp. Default is system Timezone.")][System.TimeZoneInfo]$Timezone=[System.TimeZoneInfo]::Local
    )

    PROCESS {
        $Timestamp = @($Timestamp)
        foreach ($Timestamp in $Timestamp) {
            if ($Unit -eq "Seconds") {
                $Date = [System.TimeZoneInfo]::ConvertTimeFromUtc(([datetime]'1/1/1970').AddSeconds($Timestamp),$Timezone)
            }
            else {
                $Date = [System.TimeZoneInfo]::ConvertTimeFromUtc(([datetime]'1/1/1970').AddMilliseconds($Timestamp),$Timezone)
            }
            Write-Output $Date
        }
    }
}

### AWS Cmdlets ###

<#
    .SYNOPSIS
    Retrieve SHA256 Hash for Payload
    .DESCRIPTION
    Retrieve SHA256 Hash for Payload
#>
function Global:Get-AwsHash {
    [CmdletBinding(DefaultParameterSetName="string")]

    PARAM (
        [parameter(
            Mandatory=$False,
            Position=0,
            ParameterSetName="string",
            HelpMessage="String to hash")][String]$StringToHash="",
        [parameter(
            Mandatory=$True,
            Position=1,
            ParameterSetName="file",
            HelpMessage="File to hash")][System.IO.FileInfo]$FileToHash
    )
 
    Process {
        $Hasher = [System.Security.Cryptography.SHA256]::Create()

        if ($FileToHash) {
            $Hash = Get-FileHash -Algorithm SHA256 -Path $FileToHash | select -ExpandProperty Hash
        }
        else {
            $Hash = ([BitConverter]::ToString($Hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($StringToHash))) -replace '-','').ToLower()
        }

        Write-Output $Hash
    }
}

<#
    .SYNOPSIS
    Create AWS Authentication Signature Version 2 for Request
    .DESCRIPTION
    Create AWS Authentication Signature Version 2 for Request
#>
function Global:New-AwsSignatureV2 {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
            Mandatory=$True,
            Position=1,
            HelpMessage="S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            Mandatory=$True,
            Position=2,
            HelpMessage="Endpoint hostname and optional port")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory=$False,
            Position=3,
            HelpMessage="HTTP Request Method")][ValidateSet("OPTIONS","GET","HEAD","PUT","DELETE","TRACE","CONNECT")][String]$Method="GET",
        [parameter(
            Mandatory=$False,
            Position=4,
            HelpMessage="URI")][String]$Uri="/",
        [parameter(
            Mandatory=$False,
            Position=6,
            HelpMessage="Content MD5")][String]$ContentMD5="",
        [parameter(
            Mandatory=$False,
            Position=7,
            HelpMessage="Content Type")][String]$ContentType="",
        [parameter(
            Mandatory=$False,
            Position=8,
            HelpMessage="Date")][String]$DateTime,
        [parameter(
            Mandatory=$False,
            Position=9,
            HelpMessage="Headers")][Hashtable]$Headers=@{},
        [parameter(
            Mandatory=$False,
            Position=10,
            HelpMessage="Bucket")][String]$BucketName,
        [parameter(
            Mandatory=$False,
            Position=11,
            HelpMessage="Query String (unencoded)")][String]$QueryString
    )
 
    Process {
        # this Cmdlet follows the steps outlined in https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html

        # initialization
        if (!$DateTime) {
            $DateTime = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")
        }

        Write-Debug "Task 1: Constructing the CanonicalizedResource Element "

        $CanonicalizedResource = ""
        Write-Debug "1. Start with an empty string:`n$CanonicalizedResource"

        if ($BucketName -and $EndpointUrl.Host -match "^$BucketName") {
            $CanonicalizedResource += "/$BucketName"
            Write-Debug "2. Add the bucketname for virtual host style:`n$CanonicalizedResource" 
        }
        else {
            Write-Debug "2. Bucketname already part of Url for path style therefore skipping this step"
        }

        # TODO: Think of a better way to get the properly encoded relative URI
        $CanonicalURI = ([System.UriBuilder]"$EndpointUrl$($Uri -replace '^/','')").Uri.PathAndQuery

        $CanonicalizedResource += $CanonicalURI
        Write-Debug "3. Append the path part of the un-decoded HTTP Request-URI, up-to but not including the query string:`n$CanonicalizedResource" 

        if ($QueryString) {
            $CanonicalizedResource += "?$QueryString"
        }
        Write-Debug "4. Append the query string unencoded for signing:`n$CanonicalizedResource" 

        Write-Debug "Task 2: Constructing the CanonicalizedAmzHeaders Element"

        Write-Debug "1. Filter for all headers starting with x-amz and are not x-amz-date"
        $AmzHeaders = $Headers.Clone()
        # remove all headers which do not start with x-amz
        $Headers.Keys | % { if ($_ -notmatch "x-amz" -or $_ -eq "x-amz-date") { $AmzHeaders.Remove($_) } }
        
        Write-Debug "2. Sort headers lexicographically"
        $SortedAmzHeaders = ConvertTo-SortedDictionary $AmzHeaders
        $CanonicalizedAmzHeaders = ($SortedAmzHeaders.GetEnumerator()  | % { "$($_.Key.toLower()):$($_.Value)" }) -join "`n"
        if ($CanonicalizedAmzHeaders) {
            $CanonicalizedAmzHeaders = $CanonicalizedAmzHeaders + "`n"
        }
        Write-Debug "3. CanonicalizedAmzHeaders headers:`n$CanonicalizedAmzHeaders"

        Write-Debug "Task 3: String to sign"

        $StringToSign = "$Method`n$ContentMD5`n$ContentType`n$DateTime`n$CanonicalizedAmzHeaders$CanonicalizedResource"

        Write-Debug "1. StringToSign:`n$StringToSign"

        Write-Debug "Task 4: Signature"

        $SignedString = Get-SignedString -Key ([Text.Encoding]::UTF8.GetBytes($SecretKey)) -Message $StringToSign -Algorithm SHA1
        $Signature = [Convert]::ToBase64String($SignedString)

        Write-Debug "1. Signature:`n$Signature" 

        Write-Output $Signature
    }
}

<#
    .SYNOPSIS
    Create AWS Authentication Signature Version 4 for Request
    .DESCRIPTION
    Create AWS Authentication Signature Version 4 for Request
#>
function Global:New-AwsSignatureV4 {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
            Mandatory=$True,
            Position=1,
            HelpMessage="S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            Mandatory=$True,
            Position=2,
            HelpMessage="Endpoint hostname and optional port")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory=$False,
            Position=3,
            HelpMessage="HTTP Request Method")][ValidateSet("OPTIONS","GET","HEAD","PUT","DELETE","TRACE","CONNECT")][String]$Method="GET",
        [parameter(
            Mandatory=$False,
            Position=4,
            HelpMessage="URI")][String]$Uri="/",
        [parameter(
            Mandatory=$False,
            Position=5,
            HelpMessage="Canonical Query String")][String]$CanonicalQueryString,
        [parameter(
            Mandatory=$False,
            Position=6,
            HelpMessage="Date Time (yyyyMMddTHHmmssZ)")][String]$DateTime,
        [parameter(
            Mandatory=$False,
            Position=7,
            HelpMessage="Date String (yyyyMMdd)")][String]$DateString,
        [parameter(
            Mandatory=$False,
            Position=8,
            HelpMessage="Request payload hash")][String]$RequestPayloadHash,
        [parameter(
            Mandatory=$False,
            Position=9,
            HelpMessage="Region")][String]$Region="us-east-1",
        [parameter(
            Mandatory=$False,
            Position=10,
            HelpMessage="Region")][String]$Service="s3",
        [parameter(
            Mandatory=$False,
            Position=11,
            HelpMessage="Headers")][Hashtable]$Headers=@{},
        [parameter(
            Mandatory=$False,
            Position=12,
            HelpMessage="Content type")][String]$ContentType
    )

    Process {
        # this Cmdlet follows the steps outlined in http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html

        # initialization
        if (!$RequestPayloadHash) {
            $RequestPayloadHash = Get-AwsHash -StringToHash ""
        }
        if (!$DateTime) {
            $DateTime = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")        
        }
        if (!$DateString) {
            $DateString = [DateTime]::UtcNow.ToString('yyyyMMdd')
        }

        Write-Debug "Task 1: Create a Canonical Request for Signature Version 4"
        # http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

        Write-Debug "1. HTTP Request Method:`n$Method" 

        # TODO: Think of a better way to get the properly encoded relative URI
        $CanonicalURI = ([System.UriBuilder]"$EndpointUrl$($Uri -replace '^/','')").Uri.PathAndQuery
        Write-Debug "2. Canonical URI:`n$CanonicalURI"

        Write-Debug "3. Canonical query string:`n$CanonicalQueryString"

        $SortedHeaders = ConvertTo-SortedDictionary $Headers
        $CanonicalHeaders = (($SortedHeaders.GetEnumerator()  | % { "$($_.Key.toLower()):$($_.Value)" }) -join "`n") + "`n"
        Write-Debug "4. Canonical headers:`n$CanonicalHeaders"

        $SignedHeaders = $SortedHeaders.Keys -join ";"
        Write-Debug "5. Signed headers:`n$SignedHeaders"

        Write-Debug "6. Hashed Payload`n$RequestPayloadHash"

        $CanonicalRequest = "$Method`n$CanonicalURI`n$CanonicalQueryString`n$CanonicalHeaders`n$SignedHeaders`n$RequestPayloadHash"
        Write-Debug "7. CanonicalRequest:`n$CanonicalRequest"

        $hasher = [System.Security.Cryptography.SHA256]::Create()
        $CanonicalRequestHash = ([BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($CanonicalRequest))) -replace '-','').ToLower()
        Write-Debug "8. Canonical request hash:`n$CanonicalRequestHash"

        Write-Debug "Task 2: Create a String to Sign for Signature Version 4"
        # http://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html

        $AlgorithmDesignation = "AWS4-HMAC-SHA256"
        Write-Debug "1. Algorithm designation:`n$AlgorithmDesignation"

        Write-Debug "2. request date value, specified with ISO8601 basic format in the format YYYYMMDD'T'HHMMSS'Z:`n$DateTime"

        $CredentialScope = "$DateString/$Region/$Service/aws4_request"
        Write-Debug "3. Credential scope:`n$CredentialScope"

        Write-Debug "4. Canonical request hash:`n$CanonicalRequestHash"

        $StringToSign = "$AlgorithmDesignation`n$DateTime`n$CredentialScope`n$CanonicalRequestHash"
        Write-Debug "StringToSign:`n$StringToSign"

        Write-Debug "Task 3: Calculate the Signature for AWS Signature Version 4"
        # http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html

        $SigningKey = GetSignatureKey $SecretKey $DateString $Region $Service
        Write-Debug "1. Signing Key:`n$([System.BitConverter]::ToString($SigningKey))"

        $Signature = ([BitConverter]::ToString((sign $SigningKey $StringToSign)) -replace '-','').ToLower()
        Write-Debug "2. Signature:`n$Signature"

        Write-Output $Signature
    }
}

<#
    .SYNOPSIS
    Get AWS URL
    .DESCRIPTION
    Get AWS URL
#>
function Global:Get-AwsRequest {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory=$False,
                Position=0,
                HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
                Mandatory=$False,
                Position=1,
                HelpMessage="S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
                Mandatory=$False,
                Position=2,
                HelpMessage="HTTP Request Method")][ValidateSet("OPTIONS","GET","HEAD","PUT","DELETE","TRACE","CONNECT")][String]$Method="GET",
        [parameter(
                Mandatory=$False,
                Position=3,
                HelpMessage="Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
                Mandatory=$False,
                Position=4,
                HelpMessage="URL Style")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
                Mandatory=$False,
                Position=5,
                HelpMessage="URI")][String]$Uri="/",
        [parameter(
                Mandatory=$False,
                Position=6,
                HelpMessage="Query")][Hashtable]$Query=@{},
        [parameter(
                Mandatory=$False,
                Position=7,
                HelpMessage="Request payload")][String]$RequestPayload="",
        [parameter(
                Mandatory=$False,
                Position=8,
                HelpMessage="Region")][String]$Region="us-east-1",
        [parameter(
                Mandatory=$False,
                Position=9,
                HelpMessage="Use the dualstack endpoint of the specified region. S3 supports dualstack endpoints which return both IPv6 and IPv4 values.")][Switch]$UseDualstackEndpoint,
        [parameter(
                Mandatory=$False,
                Position=10,
                HelpMessage="Service")][String]$Service="s3",
        [parameter(
                Mandatory=$False,
                Position=11,
                HelpMessage="AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)")][String][ValidateSet("S3","AWS4")]$SignerType="AWS4",
        [parameter(
                Mandatory=$False,
                Position=12,
                HelpMessage="Headers")][Hashtable]$Headers=@{},
        [parameter(
                Mandatory=$False,
                Position=13,
                HelpMessage="Content type")][String]$ContentType,
        [parameter(
                Mandatory=$False,
                Position=14,
                HelpMessage="Bucket name")][String]$BucketName,
        [parameter(
                Mandatory=$False,
                Position=15,
                HelpMessage="Date")][DateTime]$Date=[DateTime]::Now,
        [parameter(
                Mandatory=$False,
                Position=16,
                HelpMessage="File to read data from")][System.IO.FileInfo]$InFile,
        [parameter(
                Mandatory=$False,
                Position=17,
                HelpMessage="Presign URL")][Switch]$Presign,
        [parameter(
                Mandatory=$False,
                Position=18,
                HelpMessage="Presign URL Expiration Date")][DateTime]$Expires=(Get-Date).AddHours(1)
    )

    Begin {
        if (!$EndpointUrl) {
            if ($Region -eq "us-east-1" -or !$Region) {
                if ($UseDualstackEndpoint) {
                    $EndpointUrl = [System.UriBuilder]::new("https://s3.dualstack.amazonaws.com")
                }
                else {
                    $EndpointUrl = [System.UriBuilder]::new("https://s3.amazonaws.com")
                }
            }
            else {
                if ($UseDualstackEndpoint) {
                    $EndpointUrl = [System.UriBuilder]::new("https://s3.dualstack.$Region.amazonaws.com")
                }
                else {
                    $EndpointUrl = [System.UriBuilder]::new("https://s3.$Region.amazonaws.com")
                }
            }
        }
        else {
            # as we are modifying the endpoint URL, make sure to work on a new object and not modify the origianl object
            $EndpointUrl = [System.UriBuilder]::new($EndpointUrl.ToString())
        }

        if ($UrlStyle -eq "virtual-hosted" -and $BucketName) {
            Write-Verbose "Using virtual-hosted style URL"
            $EndpointUrl.host = $BucketName + '.' + $EndpointUrl.host
        }
        elseif ($BucketName) {
            Write-Verbose "Using path style URL"
            $Uri = "/$BucketName" + $Uri
        }
    }

    Process {
        $DateTime = $Date.ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
        $DateString = $Date.ToUniversalTime().ToString('yyyyMMdd')

        if ($InFile) {
            $RequestPayloadHash=Get-AwsHash -FileToHash $InFile
        }
        else {
            $RequestPayloadHash=Get-AwsHash -StringToHash $RequestPayload
        }

        if (!$Headers["host"]) { $Headers["host"] = $EndpointUrl.Uri.Authority }

        if (!$Presign.IsPresent) {
            if ($SignerType -eq "AWS4") {
                if (!$Headers["x-amz-date"]) { $Headers["x-amz-date"] = $DateTime }
            }
            else {
                if (!$Headers["date"]) { $Headers["date"] = $DateTime }
            }
            if (!$Headers["x-amz-content-sha256"] -and $SignerType -eq "AWS4") { $Headers["x-amz-content-sha256"] = $RequestPayloadHash }
            if (!$Headers["content-type"] -and $ContentType) { $Headers["content-type"] = $ContentType }
        }

        $SortedHeaders = ConvertTo-SortedDictionary $Headers
        $SignedHeaders = $SortedHeaders.Keys -join ";"

        if ($Presign.IsPresent) {
            # TODO: Investigate why Presigning with AWS4 does not work when a query like e.g. location is specified
            if ($SignerType -eq "AWS4" -and $Query.Keys.Count -ge 1) {
                Write-Warning "AWS4 Signer Type with Presigned URLs does not support query parameters, therfore falling back to S3 Signer Type"
                $SignerType = "S3"
            }
            if ($SignerType -eq "AWS4") {
                $RequestPayloadHash = "UNSIGNED-PAYLOAD"
                $ExpiresInSeconds = [Math]::Ceiling(($Expires - $Date).TotalSeconds)
                $CredentialScope = "$DateString/$Region/$Service/aws4_request"
                $Query["Action"] = $Method
                $Query["X-Amz-Algorithm"] = "AWS4-HMAC-SHA256"
                $Query["X-Amz-Credential"] = "$($AccessKey)/$($CredentialScope)"
                $Query["X-Amz-Date"] = $DateTime
                $Query["X-Amz-Expires"] = $ExpiresInSeconds
                $Query["X-Amz-SignedHeaders"] = $SignedHeaders
            }
            else {
                $ExpiresUnixTime = $Expires | ConvertTo-UnixTimestamp -Unit Seconds
                $Query["Expires"] = $ExpiresUnixTime
                $Query["AWSAccessKeyId"] = $AccessKey
                $DateTime = $ExpiresUnixTime
            }
        }

        $QueryString = ""
        $CanonicalQueryString = ""
        if ($Query.Keys.Count -ge 1) {
            # using Sorted Dictionary as query need to be sorted by encoded keys
            $SortedQuery = New-Object 'System.Collections.Generic.SortedDictionary[string, string]'

            foreach ($Key in $Query.Keys) {
                # Key and value need to be URL encoded separately
                $SortedQuery[$Key]=$Query[$Key]
            }
            foreach ($Key in $SortedQuery.Keys) {
                # AWS V2 only requires specific queries to be included in signing process
                if ($Key -match "versioning|location|acl|torrent|lifecycle|versionid|response-content-type|response-content-language|response-expires|response-cache-control|response-content-disposition|response-content-encoding") {
                    if ($SortedQuery[$Key]) {
                        $QueryString += "$Key=$($SortedQuery[$Key])&"
                    }
                    else {
                        $QueryString += "$Key&"
                    }
                }
                $CanonicalQueryString += "$([System.Net.WebUtility]::UrlEncode($Key))=$([System.Net.WebUtility]::UrlEncode($SortedQuery[$Key]))&"
            }
            $QueryString = $QueryString -replace "&`$",""
            $CanonicalQueryString = $CanonicalQueryString -replace "&`$",""
        }

        if ($SignerType -eq "AWS4") {
            Write-Verbose "Using AWS Signature Version 4"
            $Signature = New-AwsSignatureV4 -AccessKey $AccessKey -SecretKey $SecretKey -EndpointUrl $EndpointUrl -Region $Region -Uri $Uri -CanonicalQueryString $CanonicalQueryString -Method $Method -RequestPayloadHash $RequestPayloadHash -DateTime $DateTime -DateString $DateString -Headers $Headers
            Write-Debug "Task 4: Add the Signing Information to the Request"
            # http://docs.aws.amazon.com/general/latest/gr/sigv4-add-signature-to-request.html
            if (!$Presign.IsPresent) {
                $Headers["Authorization"]="AWS4-HMAC-SHA256 Credential=$AccessKey/$DateString/$Region/$Service/aws4_request,SignedHeaders=$SignedHeaders,Signature=$Signature"
            }
        }
        else {
            Write-Verbose "Using AWS Signature Version 2"
            $Signature = New-AwsSignatureV2 -AccessKey $AccessKey -SecretKey $SecretKey -EndpointUrl $EndpointUrl -Uri $Uri -Method $Method -ContentMD5 $ContentMd5 -ContentType $ContentType -DateTime $DateTime -Bucket $BucketName -QueryString $QueryString -Headers $Headers
            if (!$Presign.IsPresent) {
                $Headers["Authorization"] = "AWS $($AccessKey):$($Signature)"
            }
        }

        if ($Presign.IsPresent) {
            $UrlEncodedSignature = [System.Net.WebUtility]::UrlEncode($Signature)
            if ($SignerType -eq "AWS4") {
                $CanonicalQueryString += "&X-Amz-Signature=$UrlEncodedSignature"
            }
            else {
                $CanonicalQueryString += "&Signature=$UrlEncodedSignature"
            }
        }

        $EndpointUrl.Path = $Uri
        $EndpointUrl.Query = $CanonicalQueryString

        Write-Verbose "Request URI: $($EndpointUrl.Uri)"
        Write-Verbose "Request Headers: $($Headers | ConvertTo-Json)"

        $Request = [PSCustomObject]@{Method=$Method;Uri=$EndpointUrl.Uri;Headers=$Headers}

        Write-Output $Request
    }
}

<#
    .SYNOPSIS
    Invoke AWS Request
    .DESCRIPTION
    Invoke AWS Request
#>
function Global:Invoke-AwsRequest {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
                Mandatory=$False,
                Position=0,
                HelpMessage="Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
                Mandatory=$False,
                Position=1,
                HelpMessage="HTTP Request Method")][ValidateSet("OPTIONS","GET","HEAD","PUT","DELETE","TRACE","CONNECT")][String]$Method="GET",
        [parameter(
                Mandatory=$False,
                Position=2,
                HelpMessage="Endpoint URI")][Uri]$Uri,
        [parameter(
                Mandatory=$False,
                Position=3,
                HelpMessage="Headers")][Hashtable]$Headers=@{},
        [parameter(
                Mandatory=$False,
                Position=4,
                HelpMessage="Content type")][String]$ContentType,
        [parameter(
                Mandatory=$False,
                Position=5,
                HelpMessage="Request payload")][String]$Body="",
        [parameter(
                Mandatory=$False,
                Position=6,
                HelpMessage="File to read data from")][System.IO.FileInfo]$InFile,
        [parameter(
                Mandatory=$False,
                Position=7,
                HelpMessage="File to output result to")][System.IO.DirectoryInfo]$OutFile
    )

    Begin {
        if ([environment]::OSVersion.Platform -match "Win") {
            # check if proxy is used
            $ProxyRegistry = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            $ProxySettings = Get-ItemProperty -Path $ProxyRegistry
            if ($ProxySettings.ProxyEnable) {
                Write-Warning "Proxy Server $($ProxySettings.ProxyServer) configured in Internet Explorer may be used to connect to the endpoint!"
            }
            if ($ProxySettings.AutoConfigURL) {
                Write-Warning "Proxy Server defined in automatic proxy configuration script $($ProxySettings.AutoConfigURL) configured in Internet Explorer may be used to connect to the endpoint!"
            }
        }
    }
 
    Process {
        # check if untrusted SSL certificates should be ignored
        if ($SkipCertificateCheck.IsPresent) {
            if ($PSVersionTable.PSVersion.Major -lt 6) {
                [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
            }
            else {
                if (!"Invoke-WebRequest:SkipCertificateCheck") {
                    $PSDefaultParameterValues.Add("Invoke-WebRequest:SkipCertificateCheck",$true)
                }
                else {
                    $PSDefaultParameterValues.'Invoke-WebRequest:SkipCertificateCheck'=$true
                }
            }
        }
        else {
            # currently there is no way to re-enable certificate check for the current session in PowerShell prior to version 6
            if ($PSVersionTable.PSVersion.Major -ge 6) {
                if ("Invoke-WebRequest:SkipCertificateCheck") {
                    $PSDefaultParameterValues.Remove("Invoke-WebRequest:SkipCertificateCheck")
                }
            }
        }

        # PowerShell 5 and early cannot skip certificate validation per request therefore we need to use a workaround
        if ($PSVersionTable.PSVersion.Major -lt 6 ) {
            if ($SkipCertificateCheck.isPresent) {
                $CurrentCertificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy
                [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
            }
            if ($Body) {
                if ($OutFile) {
                    Write-Verbose "Body:`n$Body"
                    Write-Verbose "Saving output in file $OutFile"
                    $Result = Invoke-WebRequest -Method $Method -Uri $Uri -Headers $Headers -Body ([System.Text.Encoding]::UTF8.GetBytes($Body)) -OutFile $OutFile
                }
                else {
                    Write-Verbose "Body:`n$Body"
                    $Result = Invoke-WebRequest -Method $Method -Uri $Uri -Headers $Headers -Body ([System.Text.Encoding]::UTF8.GetBytes($Body))
                }
            }
            else {
                if ($OutFile) {
                    Write-Verbose "Saving output in file $OutFile"
                    $Result = Invoke-WebRequest -Method $Method -Uri $Uri -Headers $Headers -OutFile $OutFile
                }
                elseif ($InFile) {
                    Write-Verbose "InFile:`n$InFile"
                    $Result = Invoke-WebRequest -Method $Method -Uri $Uri -Headers $Headers -InFile $InFile
                }
                else {
                    $Result = Invoke-WebRequest -Method $Method -Uri $Uri -Headers $Headers
                }
            }
            if ($SkipCertificateCheck.isPresent) {
                [System.Net.ServicePointManager]::CertificatePolicy = $CurrentCertificatePolicy
            }
        }
        else {
            if ($Body) {
                if ($OutFile) {
                    Write-Verbose "Body:`n$Body"
                    Write-Verbose "Saving output in file $OutFile"
                    $Result = Invoke-WebRequest -Method $Method -Uri $Uri -Headers $Headers -Body ([System.Text.Encoding]::UTF8.GetBytes($Body)) -OutFile $OutFile -SkipCertificateCheck:$SkipCertificateCheck -PreserveAuthorizationOnRedirect
                }
                else {
                    Write-Verbose "Body:`n$Body"
                    $Result = Invoke-WebRequest -Method $Method -Uri $Uri -Headers $Headers -Body ([System.Text.Encoding]::UTF8.GetBytes($Body)) -SkipCertificateCheck:$SkipCertificateCheck -PreserveAuthorizationOnRedirect
                }
            }
            else {
                if ($OutFile) {
                    Write-Verbose "Saving output in file $OutFile"
                    $Result = Invoke-WebRequest -Method $Method -Uri $Uri -Headers $Headers -OutFile $OutFile -SkipCertificateCheck:$SkipCertificateCheck -PreserveAuthorizationOnRedirect
                }
                elseif ($InFile) {
                    Write-Verbose "InFile:`n$InFile"
                    $Result = Invoke-WebRequest -Method $Method -Uri $Uri -Headers $Headers -InFile $InFile -SkipCertificateCheck:$SkipCertificateCheck -PreserveAuthorizationOnRedirect
                }
                else {
                    $Result = Invoke-WebRequest -Method $Method -Uri $Uri -Headers $Headers -SkipCertificateCheck:$SkipCertificateCheck -PreserveAuthorizationOnRedirect
                }
            }
        }

        Write-Output $Result
    }
}

Set-Alias -Name Set-AwsProfile -Value Add-AwsConfig
Set-Alias -Name New-AwsProfile -Value Add-AwsConfig
Set-Alias -Name Add-AwsProfile -Value Add-AwsConfig
Set-Alias -Name Update-AwsProfile -Value Add-AwsConfig
Set-Alias -Name Set-AwsCredential -Value Add-AwsConfig
Set-Alias -Name New-AwsCredential -Value Add-AwsConfig
Set-Alias -Name Add-AwsCredential -Value Add-AwsConfig
Set-Alias -Name Update-AwsCredential -Value Add-AwsConfig
Set-Alias -Name Set-AwsConfig -Value Add-AwsConfig
Set-Alias -Name New-AwsConfig -Value Add-AwsConfig
Set-Alias -Name Update-AwsConfig -Value Add-AwsConfig
<#
    .SYNOPSIS
    Add AWS Credentials
    .DESCRIPTION
    Add AWS Credentials
#>
function Global:Add-AwsConfig {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
                Mandatory=$False,
                Position=0,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][Alias("Profile")][String]$ProfileName="default",
        [parameter(
                Mandatory=$False,
                Position=1,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="AWS Profile location if different than .aws/credentials")][String]$ProfileLocation=$AWS_CREDENTIALS_FILE,
        [parameter(
                ParameterSetName="credential",
                Mandatory=$True,
                Position=2,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Credential")][PSCredential]$Credential,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$True,
                Position=3,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="S3 Access Key")][Alias("aws_access_key_id")][String]$AccessKey,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$True,
                Position=4,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="S3 Secret Access Key")][Alias("aws_secret_access_key")][String]$SecretKey,
        [parameter(
                Mandatory=$False,
                Position=5,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Default Region to use for all requests made with these credentials")][String]$Region="us-east-1",
        [parameter(
                Mandatory=$False,
                Position=6,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Custom endpoint URL if different than AWS URL")][Alias("endpoint_url")][System.UriBuilder]$EndpointUrl
    )
 
    Process {
        $ConfigLocation = $ProfileLocation -replace "/[^/]+$",'/config'

        if ($Credential) {
            $AccessKey = $Credential.UserName
            $SecretKey = $Credential.GetNetworkCredential().Password
        }

        if ($AccessKey -and $SecretKey) {
            try {
                $Credentials = ConvertFrom-AwsConfigFile -AwsConfigFile $ProfileLocation
            }
            catch {
                Write-Verbose "Retrieving credentials from $ProfileLocation failed"
            }

            if (($Credentials | Where-Object { $_.ProfileName -eq $ProfileName})) {
                $CredentialEntry = $Credentials | Where-Object { $_.ProfileName -eq $ProfileName}
            }
            else {
                $CredentialEntry = [PSCustomObject]@{ ProfileName = $ProfileName }
            }

            $CredentialEntry | Add-Member -MemberType NoteProperty -Name aws_access_key_id -Value $AccessKey -Force
            $CredentialEntry | Add-Member -MemberType NoteProperty -Name aws_secret_access_key -Value $SecretKey -Force

            Write-Debug $CredentialEntry

            $Credentials = @($Credentials | Where-Object { $_.ProfileName -ne $ProfileName}) + $CredentialEntry
            ConvertTo-AwsConfigFile -Config $Credentials -AwsConfigFile $ProfileLocation
        }

        if ($Region -or $EndpointUrl) {
            try {
                $Config = ConvertFrom-AwsConfigFile -AwsConfigFile $ConfigLocation
            }
            catch {
                Write-Verbose "Retrieving credentials from $ConfigLocation failed"
            }

            if (($Config | Where-Object { $_.ProfileName -eq $ProfileName})) {
                $ConfigEntry = $Config | Where-Object { $_.ProfileName -eq $ProfileName}
            }
            else {
                $ConfigEntry = [PSCustomObject]@{ ProfileName = $ProfileName }
            }

            if ($Region) {
                $ConfigEntry | Add-Member -MemberType NoteProperty -Name region -Value $Region -Force
            }
            if ($EndpointUrl) {
                $ConfigEntry | Add-Member -MemberType NoteProperty -Name endpoint_url -Value $EndpointUrl -Force
            }

            $Config = @($Config | Where-Object { $_.ProfileName -ne $ProfileName}) + $ConfigEntry
            ConvertTo-AwsConfigFile -Config $Config -AwsConfigFile $ConfigLocation
        }
    }
}

Set-Alias -Name Get-AwsProfiles -Value Get-AwsConfigs
Set-Alias -Name Get-AwsCredentials -Value Get-AwsConfigs
<#
    .SYNOPSIS
    Get the AWS config for all profiles and if there is a connection to a StorageGRID, it includes the AWS config of the connected tenant
    .DESCRIPTION
    Get the AWS config for all profiles and if there is a connection to a StorageGRID, it includes the AWS config of the connected tenant
#>
function Global:Get-AwsConfigs {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory=$False,
                Position=0,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="AWS Profile location if different than .aws/credentials")][String]$ProfileLocation=$AWS_CREDENTIALS_FILE
    )

    Process {
        $ConfigLocation = $ProfileLocation -replace "/[^/]+$",'/config'

        if (!(Test-Path $ProfileLocation)) {
            Throw "Profile location $ProfileLocation does not exist!"
        }

        $Credentials = @()
        $Config = @()
        try {
            $Credentials = ConvertFrom-AwsConfigFile -AwsConfigFile $ProfileLocation
        }
        catch {
            Write-Verbose "Retrieving credentials from $ProfileLocation failed"
        }
        try {
            $Config = ConvertFrom-AwsConfigFile -AwsConfigFile $ConfigLocation
        }
        catch {
            Write-Verbose "Retrieving credentials from $ConfigLocation failed"
        }

        foreach ($Credential in $Credentials) {
            $ConfigEntry = $Config | Where-Object { $_.ProfileName -eq $Credential.ProfileName } | Select-Object -First 1
            if ($ConfigEntry) {
                $ConfigEntry.aws_access_key_id = $Credential.aws_access_key_id
                $ConfigEntry.aws_secret_access_key = $Credential.aws_secret_access_key
            }
            else {
                $Config = @($Config) + ([PSCustomObject]@{ProfileName=$Credential.ProfileName;aws_access_key_id=$Credential.aws_access_key_id;aws_secret_access_key=$Credential.aws_secret_access_key;region="";endpoint_url=$null})
            }
        }

        Write-Output $Config
    }
}

Set-Alias -Name Get-AwsProfile -Value Get-AwsConfig
Set-Alias -Name Get-AwsCredential -Value Get-AwsConfig
<#
    .SYNOPSIS
    Get AWS config
    .DESCRIPTION
    Get AWS config
    If there is a connection to a StorageGRID, this is the AWS config of the connected tenant.
    If a profile is provided, it is the AWS config of the AWS profile.
#>
function Global:Get-AwsConfig {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory=$False,
                Position=0,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
                Mandatory=$False,
                Position=1,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName="",
        [parameter(
                Mandatory=$False,
                Position=2,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="AWS Profile location if different than .aws/credentials")][String]$ProfileLocation=$AWS_CREDENTIALS_FILE,
        [parameter(
                Mandatory=$False,
                Position=3,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="S3 Access Key")][String]$AccessKey="",
        [parameter(
                Mandatory=$False,
                Position=4,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="S3 Secret Access Key")][String]$SecretKey="",
        [parameter(
                Mandatory=$False,
                Position=5,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Account ID")][String]$AccountId="",
        [parameter(
                Mandatory=$False,
                Position=6,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Endpoint URL")][System.UriBuilder]$EndpointUrl=$null,
        [parameter(
                Mandatory=$False,
                Position=7,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Endpoint URL")][String]$Region
    )
    
    Begin {
        if (!$Server -and $CurrentSgwServer) {
            $Server = $CurrentSgwServer.PSObject.Copy()
        }
    }

    Process {
        $ConfigLocation = $ProfileLocation -replace "/[^/]+$",'/config'

        $Config = [PSCustomObject]@{ProfileName = $ProfileName; aws_access_key_id = $AccessKey; aws_secret_access_key = $SecretKey; region = $Region; endpoint_url = $EndpointUrl }

        if (!$ProfileName -and !$AccessKey -and !$Server) {
            $ProfileName = "default"
        }

        if ($ProfileName) {
            Write-Verbose "Profile $ProfileName specified, therefore returning AWS config of this profile"
            $Config = Get-AwsConfigs | Where-Object { $_.ProfileName -eq $ProfileName }
            if (!$Config) {
                Throw "Config for profile $ProfileName not found"
            }
        }
        elseif ($AccessKey) {
            Write-Verbose "Access Key $AccessKey and Secret Access Key specified, therefore returning AWS config for the keys"
        }
        else {
            # if an explicit endpoint URL is provided, use instead of the one from provided server
            if ($Server.AccountId) {
                $AccountId = $Server.AccountId
            }
            if (!$EndpointUrl) {
                $EndpointUrl = $Server.S3EndpointUrl
            }
            if (!$Server.DisableAutomaticAccessKeyGeneration -and $AccountId) {
                Write-Verbose "No profile and no access key specified, but connected to StorageGRID tenant with Account ID $AccountId. Therefore using autogenerated temporary AWS credentials"
                if ($Server.AccessKeyStore[$AccountId].expires -ge (Get-Date).ToUniversalTime().AddMinutes(1) -or ($Server.AccessKeyStore[$AccountId] -and !$Server.AccessKeyStore[$AccountId].expires)) {
                    $Credential = $Server.AccessKeyStore[$AccountId] | Sort-Object -Property expires | Select-Object -Last 1
                    Write-Verbose "Using existing Access Key $( $Credential.AccessKey )"
                }
                else {
                    $Credential = New-SgwS3AccessKey -Server $Server -Expires (Get-Date).AddSeconds($Server.TemporaryAccessKeyExpirationTime) -AccountId $AccountId
                    Write-Verbose "Created new temporary Access Key $( $Credential.AccessKey )"
                }
                $Config.aws_access_key_id = $Credential.AccessKey
                $Config.aws_secret_access_key = $Credential.SecretAccessKey
                $Config.endpoint_url = [System.UriBuilder]::new($EndpointUrl)
            }
        }

        if (!$Region -and $Config.region) {
            $Region = $Config.Region
        }
        elseif (!$Region -and !$Config.region) {
            $Config.region = "us-east-1"
        }

        if ($Config.aws_access_key_id) {
            Write-Output $Config
        }
    }
}

Set-Alias -Name Remove-AwsProfile -Value Remove-AwsConfig
Set-Alias -Name Remove-AwsCredential -Value Remove-AwsConfig
<#
    .SYNOPSIS
    Remove AWS Config
    .DESCRIPTION
    Remove AWS Config
#>
function Global:Remove-AwsConfig {
    [CmdletBinding()]

    PARAM (
        [parameter(
                Mandatory=$True,
                Position=0,
                HelpMessage="AWS Profile where config should be removed")][Alias("Profile")][String]$ProfileName,
        [parameter(
                Mandatory=$False,
                Position=1,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="AWS Profile location if different than .aws/credentials")][String]$ProfileLocation=$AWS_CREDENTIALS_FILE
    )

    Process {
        $ConfigLocation = $ProfileLocation -replace "/[^/]+$",'/config'

        $Credentials = ConvertFrom-AwsConfigFile -AwsConfigFile $ProfileLocation
        $Credentials = $Credentials | Where-Object { $_.ProfileName -ne $ProfileName }
        ConvertTo-AwsConfigFile -Config $Credentials -AwsConfigFile $ProfileLocation

        $Config = ConvertFrom-AwsConfigFile -AwsConfigFile $ConfigLocation
        $Config = $Credentials | Where-Object { $_.ProfileName -ne $ProfileName }
        ConvertTo-AwsConfigFile -Config $Config -AwsConfigFile $ConfigLocation
    }
}

Set-Alias -Name Add-AwsPolicyStatement -Value New-AwsPolicy
Set-Alias -Name New-IamPolicy -Value New-AwsPolicy
Set-Alias -Name Add-IamPolicyStatement -Value New-AwsPolicy
Set-Alias -Name New-S3BucketPolicy -Value New-AwsPolicy
Set-Alias -Name Add-S3BucketPolicyStatement -Value New-AwsPolicy
<#
    .SYNOPSIS
    Create new S3 Bucket Policy
    .DESCRIPTION
    Create new S3 Bucket Policy
#>
function Global:New-AwsPolicy {
    [CmdletBinding(DefaultParameterSetName = "PrincipalResourceAction")]

    PARAM (
        [parameter(
                Mandatory = $False,
                Position = 0,
                ValueFromPipeline = $True,
                ValueFromPipelineByPropertyName = $True,
                HelpMessage = "S3 Bucket Policy to add statements to")][Alias("BucketPolicy","IamPolicy","AwsPolicy","Policy")][String]$PolicyString,
        [parameter(
                Mandatory = $False,
                Position = 1,
                HelpMessage = "The Sid element is optional. The Sid is only intended as a description for the user. It is stored but not interpreted by the StorageGRID Webscale system.")][String]$Sid,
        [parameter(
                Mandatory = $False,
                Position = 2,
                HelpMessage = "Use the Effect element to establish whether the specified operations are allowed or denied. You must identify operations you allow (or deny) on buckets or objects using the supported Action element keywords.")][ValidateSet("Allow", "Deny")][String]$Effect = "Allow",
        [parameter(
                Mandatory = $False,
                Position = 3,
                ParameterSetName = "PrincipalResourceAction",
                HelpMessage = "The Resource element identifies buckets and objects. With it you can allow permissions to buckets and objects using the uniform resource name (URN) to identify the resource.")][PSCustomObject]
        [parameter(
                Mandatory = $False,
                Position = 3,
                ParameterSetName = "PrincipalResourceNotAction",
                HelpMessage = "The Resource element identifies buckets and objects. With it you can allow permissions to buckets and objects using the uniform resource name (URN) to identify the resource.")][PSCustomObject]
        [parameter(
                Mandatory = $False,
                Position = 3,
                ParameterSetName = "PrincipalNotResourceAction",
                HelpMessage = "The Resource element identifies buckets and objects. With it you can allow permissions to buckets and objects using the uniform resource name (URN) to identify the resource.")][PSCustomObject]
        [parameter(
                Mandatory = $False,
                Position = 3,
                ParameterSetName = "PrincipalNotResourceNotAction",
                HelpMessage = "The Resource element identifies buckets and objects. With it you can allow permissions to buckets and objects using the uniform resource name (URN) to identify the resource.")][PSCustomObject]$Principal = "*",
        [parameter(
                Mandatory = $False,
                Position = 3,
                ParameterSetName = "NotPrincipalResourceAction",
                HelpMessage = "The Resource element identifies buckets and objects. With it you can allow permissions to buckets and objects using the uniform resource name (URN) to identify the resource.")][PSCustomObject]
        [parameter(
                Mandatory = $False,
                Position = 3,
                ParameterSetName = "NotPrincipalResourceNotAction",
                HelpMessage = "The Resource element identifies buckets and objects. With it you can allow permissions to buckets and objects using the uniform resource name (URN) to identify the resource.")][PSCustomObject]
        [parameter(
                Mandatory = $False,
                Position = 3,
                ParameterSetName = "NotPrincipalNotResourceAction",
                HelpMessage = "The Resource element identifies buckets and objects. With it you can allow permissions to buckets and objects using the uniform resource name (URN) to identify the resource.")][PSCustomObject]
        [parameter(
                Mandatory = $False,
                Position = 3,
                ParameterSetName = "NotPrincipalNotResourceNotAction",
                HelpMessage = "The Resource element identifies buckets and objects. With it you can allow permissions to buckets and objects using the uniform resource name (URN) to identify the resource.")][PSCustomObject]$NotPrincipal,
        [parameter(
                Mandatory = $False,
                Position = 4,
                ParameterSetName = "PrincipalResourceAction",
                HelpMessage = "The Resource element identifies buckets and objects. With it you can allow permissions to buckets and objects using the uniform resource name (URN) to identify the resource.")][System.UriBuilder]
        [parameter(
                Mandatory = $False,
                Position = 4,
                ParameterSetName = "PrincipalResourceNotAction",
                HelpMessage = "The Resource element identifies buckets and objects. With it you can allow permissions to buckets and objects using the uniform resource name (URN) to identify the resource.")][System.UriBuilder]
        [parameter(
                Mandatory = $False,
                Position = 4,
                ParameterSetName = "NotPrincipalResourceAction",
                HelpMessage = "The Resource element identifies buckets and objects. With it you can allow permissions to buckets and objects using the uniform resource name (URN) to identify the resource.")][System.UriBuilder]
        [parameter(
                Mandatory = $False,
                Position = 4,
                ParameterSetName = "NotPrincipalResourceNotAction",
                HelpMessage = "The Resource element identifies buckets and objects. With it you can allow permissions to buckets and objects using the uniform resource name (URN) to identify the resource.")][System.UriBuilder]$Resource = "arn:aws:s3:::*",
        [parameter(
                Mandatory = $False,
                Position = 4,
                ParameterSetName = "PrincipalNotResourceAction",
                HelpMessage = "The NotResource element identifies buckets and objects. With it you can deny permissions to buckets and objects using the uniform resource name (URN) to identify the resource.")][System.UriBuilder]
        [parameter(
                Mandatory = $False,
                Position = 4,
                ParameterSetName = "PrincipalNotResourceNotAction",
                HelpMessage = "The NotResource element identifies buckets and objects. With it you can deny permissions to buckets and objects using the uniform resource name (URN) to identify the resource.")][System.UriBuilder]
        [parameter(
                Mandatory = $False,
                Position = 4,
                ParameterSetName = "NotPrincipalNotResourceAction",
                HelpMessage = "The NotResource element identifies buckets and objects. With it you can deny permissions to buckets and objects using the uniform resource name (URN) to identify the resource.")][System.UriBuilder]
        [parameter(
                Mandatory = $False,
                Position = 4,
                ParameterSetName = "NotPrincipalNotResourceNotAction",
                HelpMessage = "The NotResource element identifies buckets and objects. With it you can deny permissions to buckets and objects using the uniform resource name (URN) to identify the resource.")][System.UriBuilder]$NotResource,
        [parameter(
                Mandatory = $False,
                Position = 5,
                ParameterSetName = "PrincipalResourceAction",
                HelpMessage = "The Action element specifies a list of allowed actions and may allow all actions using a wildcard (e.g. s3:*).")][String[]]
        [parameter(
                Mandatory = $False,
                Position = 5,
                ParameterSetName = "PrincipalNotResourceAction",
                HelpMessage = "The Action element specifies a list of allowed actions and may allow all actions using a wildcard (e.g. s3:*).")][String[]]
        [parameter(
                Mandatory = $False,
                Position = 5,
                ParameterSetName = "NotPrincipalResourceAction",
                HelpMessage = "The Action element specifies a list of allowed actions and may allow all actions using a wildcard (e.g. s3:*).")][String[]]
        [parameter(
                Mandatory = $False,
                Position = 5,
                ParameterSetName = "NotPrincipalNotResourceAction",
                HelpMessage = "The Action element specifies a list of allowed actions and may allow all actions using a wildcard (e.g. s3:*).")][String[]]$Action = "s3:*",
        [parameter(
                Mandatory = $False,
                Position = 5,
                ParameterSetName = "PrincipalResourceNotAction",
                HelpMessage = "The NotAction element specifies a list of denied actions and may deny all actions using a wildcard (e.g. s3:*).")][String[]]
        [parameter(
                Mandatory = $False,
                Position = 5,
                ParameterSetName = "PrincipalNotResourceNotAction",
                HelpMessage = "The NotAction element specifies a list of denied actions and may deny all actions using a wildcard (e.g. s3:*).")][String[]]
        [parameter(
                Mandatory = $False,
                Position = 5,
                ParameterSetName = "NotPrincipalResourceNotAction",
                HelpMessage = "The NotAction element specifies a list of denied actions and may deny all actions using a wildcard (e.g. s3:*).")][String[]]
        [parameter(
                Mandatory = $False,
                Position = 5,
                ParameterSetName = "NotPrincipalNotResourceNotAction",
                HelpMessage = "The NotAction element specifies a list of denied actions and may deny all actions using a wildcard (e.g. s3:*).")][String[]]$NotAction,
        [parameter(
                Mandatory = $False,
                Position = 6,
                HelpMessage = "The Condition element is optional. Conditions allow you to build expressions to determine when a policy should be applied.")][String]$Condition
    )

    Process {
        # see https://docs.aws.amazon.com/AmazonS3/latest/dev/access-policy-language-overview.html for details on Policies

        if ($Resource -match "arn:aws" -or $NotResource  -match "arn:aws") {
            Write-Warning "Resource starts with arn:aws:"
            Write-Warning "If the policy is created for an S3 service different than AWS (e.g. StorageGRID),the Resource may need to be specified as:"
            if ($Resource) {
                Write-Warning ($Resource.ToString() -replace "arn:aws:","urn:sgws:")
            }
            else {
                Write-Warning ($NotResource.ToString() -replace "arn:aws:","urn:sgws:")
            }
        }

        if (!$PolicyString) {
            $Policy = [PSCustomObject]@{ Version = "2012-10-17"; Statement = @() }
        }
        else {
            $Policy = ConvertFrom-Json -InputObject $PolicyString
        }

        $Statement = [PSCustomObject]@{ Effect = $Effect }

        if ($Sid) {
            $Statement | Add-Member -MemberType NoteProperty -Name Sid -Value $Sid
        }
        if ($Principal) {
            $Statement | Add-Member -MemberType NoteProperty -Name Principal -Value $Principal
        }
        if ($NotPrincipal) {
            $Statement | Add-Member -MemberType NoteProperty -Name NotPrincipal -Value $NotPrincipal
        }
        if ($Resource) {
            $Statement | Add-Member -MemberType NoteProperty -Name Resource -Value $Resource.Uri.ToString()
        }
        if ($NotResource) {
            $Statement | Add-Member -MemberType NoteProperty -Name NotResource -Value $NotResource.Uri.ToString()
        }
        if ($Action) {
            $Statement | Add-Member -MemberType NoteProperty -Name Action -Value $Action
        }
        if ($NotAction) {
            $Statement | Add-Member -MemberType NoteProperty -Name NotAction -Value $NotAction
        }
        if ($Condition) {
            $Statement | Add-Member -MemberType NoteProperty -Name Condition -Value $Condition
        }

        $Policy.Statement += $Statement

        # convert to JSON
        $PolicyString = ConvertTo-Json -InputObject $Policy -Depth 10

        Write-Output $PolicyString
    }
}

### S3 Cmdlets ###

## Buckets ##

<#
    .SYNOPSIS
    Get S3 Buckets
    .DESCRIPTION
    Get S3 Buckets
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER SignerType
    AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER ProfileName
    AWS Profile to use which contains AWS sredentials and settings
    .PARAMETER ProfileLocation
    AWS Profile location if different than .aws/credentials
    .PARAMETER AccessKey
    S3 Access Key
    .PARAMETER SecretKey
    S3 Secret Access Key
    .PARAMETER AccountId
    StorageGRID account ID to execute this command against
    .PARAMETER UrlStyle
    URL Style (Default: Path)
    .PARAMETER UseDualstackEndpoint
    Use the dualstack endpoint of the specified region. S3 supports dualstack endpoints which return both IPv6 and IPv4 values.
    .PARAMETER Region
    Bucket Region
    .PARAMETER BucketName
    Bucket Name
#>
function Global:Get-S3Buckets {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
                Mandatory=$False,
                Position=0,
                HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
                Mandatory=$False,
                Position=1,
                HelpMessage="Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
                Mandatory=$False,
                Position=2,
                HelpMessage="Use presigned URL")][Switch]$Presign,
        [parameter(
                Mandatory=$False,
                Position=3,
                HelpMessage="Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
                Mandatory=$False,
                Position=4,
                HelpMessage="AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)")][String][ValidateSet("S3","AWS4")]$SignerType="AWS4",
        [parameter(
                Mandatory=$False,
                Position=5,
                HelpMessage="Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=6,
                HelpMessage="AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=7,
                HelpMessage="AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=6,
                HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=7,
                HelpMessage="S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
                ParameterSetName="account",
                Mandatory=$False,
                Position=6,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
                Mandatory=$False,
                Position=8,
                HelpMessage="Use the dualstack endpoint of the specified region. S3 supports dualstack endpoints which return both IPv6 and IPv4 values.")][Switch]$UseDualstackEndpoint,
        [parameter(
                Mandatory=$False,
                Position=9,
                HelpMessage="Bucket")][Alias("Name","Bucket")][String]$BucketName
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        $Method = "GET"
        $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId
    }
 
    Process {
        Write-Verbose "Retrieving all buckets"

        $Uri = "/"

        if ($Config) {
            $AwsRequest = Get-AwsRequest -AccessKey $Config.aws_access_key_id -SecretKey $Config.aws_secret_access_key -Method $Method -EndpointUrl $Config.endpoint_url -Uri $Uri -Presign:$Presign -SignerType $SignerType -UseDualstackEndpoint:$UseDualstackEndpoint
            if ($DryRun.IsPresent) {
                Write-Output $AwsRequest
            }
            else {
                $Result = Invoke-AwsRequest -SkipCertificateCheck:$SkipCertificateCheck -Method $Method -Uri $AwsRequest.Uri -Headers $AwsRequest.Headers -ErrorAction Stop

                $Content = [XML]$Result.Content

                if ($Content.ListAllMyBucketsResult) {
                    if ($BucketName) {
                        $XmlBuckets = $Content.ListAllMyBucketsResult.Buckets.ChildNodes | ? { $_.Name -eq [System.Globalization.IdnMapping]::new().GetAscii($BucketName) }
                    }
                    else {
                        $XmlBuckets = $Content.ListAllMyBucketsResult.Buckets.ChildNodes
                    }
                    foreach ($XmlBucket in $XmlBuckets) {
                        if (!$BucketName -or ($BucketName -eq $XmlBucket.Name)) {
                            $Location = Get-S3BucketLocation -SkipCertificateCheck:$SkipCertificateCheck -EndpointUrl $Config.endpoint_url -Bucket $XmlBucket.Name -AccessKey $Config.aws_access_key_id -SecretKey $Config.aws_secret_access_key -Presign:$Presign -SignerType $SignerType -UseDualstackEndpoint:$UseDualstackEndpoint
                            $UnicodeName = [System.Globalization.IdnMapping]::new().GetUnicode($XmlBucket.Name)
                            $BucketNameObject = [PSCustomObject]@{ BucketName = $UnicodeName; CreationDate = $XmlBucket.CreationDate; OwnerId = $Content.ListAllMyBucketsResult.Owner.ID; OwnerDisplayName = $Content.ListAllMyBucketsResult.Owner.DisplayName; Region = $Location }
                            Write-Output $BucketNameObject
                        }
                    }
                }
            }
        }
        elseif ($CurrentSgwServer.SupportedApiVersions -match "1" -and !$CurrentSgwServer.AccountId -and !$AccountId) {
            $Accounts = Get-SgwAccounts -Capabilities "s3"
            foreach ($Account in $Accounts) {
                Get-S3Buckets -Server $Server -SkipCertificateCheck:$SkipCertificateCheck -Presign:$Presign -DryRun:$DryRun -SignerType $SignerType -EndpointUrl $Config.endpoint_url -AccountId $Account.Id -UseDualstackEndpoint:$UseDualstackEndpoint
            }
        }
    }
}

<#
    .SYNOPSIS
    Test if S3 Bucket exists
    .DESCRIPTION
    Test if S3 Bucket exists
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER SignerType
    AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER ProfileName
    AWS Profile to use which contains AWS sredentials and settings
    .PARAMETER ProfileLocation
    AWS Profile location if different than .aws/credentials
    .PARAMETER AccessKey
    S3 Access Key
    .PARAMETER SecretKey
    S3 Secret Access Key
    .PARAMETER AccountId
    StorageGRID account ID to execute this command against
    .PARAMETER UrlStyle
    URL Style (Default: Path)
    .PARAMETER UseDualstackEndpoint
    Use the dualstack endpoint of the specified region. S3 supports dualstack endpoints which return both IPv6 and IPv4 values.
    .PARAMETER Region
    Bucket Region
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER CheckAllRegions
    Check all regions - by default only the specified region (or us-east-1 if no region is specified) will be checked.
#>
function Global:Test-S3Bucket {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
                Mandatory=$False,
                Position=0,
                HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
                Mandatory=$False,
                Position=1,
                HelpMessage="Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
                Mandatory=$False,
                Position=2,
                HelpMessage="Use presigned URL")][Switch]$Presign,
        [parameter(
                Mandatory=$False,
                Position=3,
                HelpMessage="Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
                Mandatory=$False,
                Position=4,
                HelpMessage="AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)")][String][ValidateSet("S3","AWS4")]$SignerType="AWS4",
        [parameter(
                Mandatory=$False,
                Position=5,
                HelpMessage="Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=6,
                HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][Alias("Profile")][String]$ProfileName,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=7,
                HelpMessage="AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=6,
                HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=7,
                HelpMessage="S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
                ParameterSetName="account",
                Mandatory=$False,
                Position=6,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
                Mandatory=$False,
                Position=8,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Region to be used")][String]$Region,
        [parameter(
                Mandatory=$False,
                Position=9,
                HelpMessage="Bucket URL Style (Default: path)")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
                Mandatory=$True,
                Position=10,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Bucket")][Alias("Name","Bucket")][String]$BucketName,
        [parameter(
                Mandatory=$False,
                Position=11,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Check all regions - by default only the specified region (or us-east-1 if no region is specified) will be checked.")][Switch]$CheckAllRegions
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId
        $Method = "HEAD"
    }

    Process {
        if (!$Region) {
            $Region = $Config.Region
        }

        if ($Config)  {
            $AwsRequest = Get-AwsRequest -AccessKey $Config.aws_access_key_id -SecretKey $Config.aws_secret_access_key -Method $Method -EndpointUrl $Config.endpoint_url -Presign:$Presign -SignerType $SignerType -Bucket $BucketName -UrlStyle $UrlStyle -Region $Region
            if ($DryRun.IsPresent) {
                Write-Output $AwsRequest
            }
            else {
                try {
                    $Result = Invoke-AwsRequest -SkipCertificateCheck:$SkipCertificateCheck -Method $Method -Uri $AwsRequest.Uri -Headers $AwsRequest.Headers
                    Write-Output $true
                }
                catch {
                    $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'
                    if ($CheckAllRegions.IsPresent -and [int]$_.Exception.Response.StatusCode -match "^3" -and $_.Exception.Response.Headers.TryGetValues("x-amz-bucket-region",[ref]$RedirectedRegion)) {
                        Write-Warning "Request was redirected as bucket does not belong to region $Region. Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                        Test-S3Bucket -SkipCertificateCheck:$SkipCertificateCheck -Presign:$Presign -DryRun:$DryRun -SignerType $SignerType -EndpointUrl $Config.endpoint_url -AccessKey $Config.aws_access_key_id -SecretKey $Config.aws_secret_access_key -Region $($RedirectedRegion[0]) -UrlStyle $UrlStyle -Bucket $BucketName
                    }
                    else {
                        Write-Output $false
                    }
                }
            }
        }
    }
}

<#
    .SYNOPSIS
    Create S3 Bucket
    .DESCRIPTION
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER SignerType
    AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER ProfileName
    AWS Profile to use which contains AWS sredentials and settings
    .PARAMETER ProfileLocation
    AWS Profile location if different than .aws/credentials
    .PARAMETER AccessKey
    S3 Access Key
    .PARAMETER SecretKey
    S3 Secret Access Key
    .PARAMETER AccountId
    StorageGRID account ID to execute this command against
    .PARAMETER UrlStyle
    URL Style (Default: Path)
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER CannedAclName
    Canned ACL
    .PARAMETER PublicReadOnly
    If set, applies an ACL making the bucket public with read-only permissions
    .PARAMETER PublicReadWrite
    If set, applies an ACL making the bucket public with read-write permissions
    .PARAMETER Region
    Bucket Region
    .PARAMETER UseDualstackEndpoint
    Use the dualstack endpoint of the specified region. S3 supports dualstack endpoints which return both IPv6 and IPv4 values.
    .PARAMETER Force
    Parameter is only used for compatibility with AWS Cmdlets and will be ignored
#>
function Global:New-S3Bucket {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
                Mandatory=$False,
                Position=0,
                HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
                Mandatory=$False,
                Position=1,
                HelpMessage="Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
                Mandatory=$False,
                Position=2,
                HelpMessage="Use presigned URL")][Switch]$Presign,
        [parameter(
                Mandatory=$False,
                Position=3,
                HelpMessage="Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
                Mandatory=$False,
                Position=4,
                HelpMessage="AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)")][String][ValidateSet("S3","AWS4")]$SignerType="AWS4",
        [parameter(
                Mandatory=$False,
                Position=5,
                HelpMessage="Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=6,
                HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][Alias("Profile")][String]$ProfileName,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=7,
                HelpMessage="AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=6,
                HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=7,
                HelpMessage="S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
                ParameterSetName="account",
                Mandatory=$False,
                Position=6,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
                Mandatory=$False,
                Position=8,
                HelpMessage="Bucket URL Style (Default: path)")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
                Mandatory=$True,
                Position=9,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Bucket Name")][Alias("Name","Bucket")][String]$BucketName,
        [parameter(
                Mandatory=$False,
                Position=10,
                HelpMessage="Canned ACL")][Alias("CannedAcl","Acl")][String][ValidateSet("private","public-read","public-read-write","aws-exec-read","authenticated-read","bucket-owner-read","bucket-owner-full-control")]$CannedAclName,
        [parameter(
                Mandatory=$False,
                Position=11,
                HelpMessage="If set, applies an ACL making the bucket public with read-only permissions")][Switch]$PublicReadOnly,
        [parameter(
                Mandatory=$False,
                Position=12,
                HelpMessage="If set, applies an ACL making the bucket public with read-write permissions")][Switch]$PublicReadWrite,
        [parameter(
                Mandatory=$False,
                Position=13,
                HelpMessage="Bucket Region")][Alias("Location","LocationConstraint")][String]$Region,
        [parameter(
                Mandatory=$False,
                Position=14,
                HelpMessage="Use the dualstack endpoint of the specified region. S3 supports dualstack endpoints which return both IPv6 and IPv4 values.")][Switch]$UseDualstackEndpoint,
        [parameter(
                Mandatory=$False,
                Position=15,
                HelpMessage="Parameter is only used for compatibility with AWS Cmdlets and will be ignored")][Switch]$Force

    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        $Method = "PUT"
    }
 
    Process {
        $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId

        if (!$Config) {
            Throw "No S3 credentials found"
        }

        if (!$Region) {
            $Region = $Config.Region
        }

        # TODO: Implement CannedAcl, PublicReadOnly and PublicReadWrite

        # AWS does not allow to set LocationConstraint for default region us-east-1
        if ($Region -and $Region -ne "us-east-1") {
            $RequestPayload = "<CreateBucketConfiguration xmlns=`"http://s3.amazonaws.com/doc/2006-03-01/`"><LocationConstraint>$Region</LocationConstraint></CreateBucketConfiguration>"
        }

        # convert Bucket to Punycode to support Unicode Bucket Names
        $BucketName = [System.Globalization.IdnMapping]::new().GetAscii($BucketName)

        $AwsRequest = Get-AwsRequest -AccessKey $Config.aws_access_key_id -SecretKey $Config.aws_secret_access_key -Method $Method -EndpointUrl $Config.endpoint_url -Presign:$Presign -SignerType $SignerType -Bucket $BucketName -UrlStyle $UrlStyle -RequestPayload $RequestPayload -Region $Region -UseDualstackEndpoint:$UseDualstackEndpoint

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Result = Invoke-AwsRequest -SkipCertificateCheck:$SkipCertificateCheck -Method $Method -Uri $AwsRequest.Uri -Headers $AwsRequest.Headers -Body $RequestPayload -ErrorAction Stop
        }
    }
}

<#
    .SYNOPSIS
    Remove S3 Bucket
    .DESCRIPTION
    Remove S3 Bucket
#>
function Global:Remove-S3Bucket {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
                Mandatory=$False,
                Position=0,
                HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
                Mandatory=$False,
                Position=1,
                HelpMessage="Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
                Mandatory=$False,
                Position=2,
                HelpMessage="Use presigned URL")][Switch]$Presign,
        [parameter(
                Mandatory=$False,
                Position=3,
                HelpMessage="Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
                Mandatory=$False,
                Position=4,
                HelpMessage="AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)")][String][ValidateSet("S3","AWS4")]$SignerType="AWS4",
        [parameter(
                Mandatory=$False,
                Position=5,
                HelpMessage="Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=6,
                HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][Alias("Profile")][String]$ProfileName,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=7,
                HelpMessage="AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=6,
                HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=7,
                HelpMessage="S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
                ParameterSetName="account",
                Mandatory=$False,
                Position=6,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
                Mandatory=$False,
                Position=8,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Region to be used")][String]$Region,
        [parameter(
                Mandatory=$False,
                Position=9,
                HelpMessage="Bucket URL Style (Default: path)")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
                Mandatory=$False,
                Position=10,
                HelpMessage="Use the dualstack endpoint of the specified region. S3 supports dualstack endpoints which return both IPv6 and IPv4 values.")][Switch]$UseDualstackEndpoint,
        [parameter(
                Mandatory=$True,
                Position=11,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Bucket Name")][Alias("Name","Bucket")][String]$BucketName,
        [parameter(
                Mandatory=$False,
                Position=12,
                HelpMessage="Force deletion even if bucket is not empty.")][Switch]$Force,
        [parameter(
                Mandatory=$False,
                Position=13,
                HelpMessage="If set, all remaining objects and/or object versions in the bucket are deleted proir to the bucket itself  being deleted.")][Switch]$DeleteBucketContent
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId
        $Method = "DELETE"
    }

    Process {
        if (!$Region) {
            $Region = $Config.Region
        }

        # Convert Bucket Name to IDN mapping to support Unicode Names
        $BucketName = [System.Globalization.IdnMapping]::new().GetAscii($BucketName)

        if ($Force -or $DeleteBucketContent) {
            Write-Verbose "Force parameter specified, removing all objects in the bucket before removing the bucket"
            Get-S3Objects -AccessKey $Config.aws_access_key_id -SecretKey $Config.aws_secret_access_key -EndpointUrl $Config.endpoint_url -Presign:$Presign -SignerType $SignerType -UrlStyle $UrlStyle -Bucket $BucketName -Region $Region -UseDualstackEndpoint:$UseDualstackEndpoint | Remove-S3Object -AccessKey $Config.aws_access_key_id -SecretKey $Config.aws_secret_access_key -EndpointUrl $Config.endpoint_url -Presign:$Presign -SignerType $SignerType -UrlStyle $UrlStyle -UseDualstackEndpoint:$UseDualstackEndpoint
        }

        $AwsRequest = Get-AwsRequest -AccessKey $Config.aws_access_key_id -SecretKey $Config.aws_secret_access_key -Method $Method -EndpointUrl $Config.endpoint_url -Presign:$Presign -SignerType $SignerType -Bucket $BucketName -UrlStyle $UrlStyle -Region $Region -UseDualstackEndpoint:$UseDualstackEndpoint

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Result = Invoke-AwsRequest -SkipCertificateCheck:$SkipCertificateCheck -Method $Method -Uri $AwsRequest.Uri -Headers $AwsRequest.Headers -ErrorAction Stop
        }
    }
}

<#
    .SYNOPSIS
    Get S3 Bucket ACL
    .DESCRIPTION
    Get S3 Bucket ACL
#>
function Global:Get-S3BucketPolicy {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
                Mandatory=$False,
                Position=0,
                HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
                Mandatory=$False,
                Position=1,
                HelpMessage="Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
                Mandatory=$False,
                Position=2,
                HelpMessage="Use presigned URL")][Switch]$Presign,
        [parameter(
                Mandatory=$False,
                Position=3,
                HelpMessage="Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
                Mandatory=$False,
                Position=4,
                HelpMessage="AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)")][String][ValidateSet("S3","AWS4")]$SignerType="AWS4",
        [parameter(
                Mandatory=$False,
                Position=5,
                HelpMessage="Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=6,
                HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][Alias("Profile")][String]$ProfileName,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=7,
                HelpMessage="AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=6,
                HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=7,
                HelpMessage="S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
                ParameterSetName="account",
                Mandatory=$False,
                Position=6,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
                Mandatory=$False,
                Position=8,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Region to be used")][String]$Region,
        [parameter(
                Mandatory=$False,
                Position=9,
                HelpMessage="Bucket URL Style (Default: path)")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
                Mandatory=$True,
                Position=10,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Bucket")][Alias("Name","Bucket")][String]$BucketName
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId
        $Method = "GET"
    }

    Process {
        if (!$Region) {
            $Region = $Config.Region
        }

        # Convert Bucket Name to IDN mapping to support Unicode Names
        $BucketName = [System.Globalization.IdnMapping]::new().GetAscii($BucketName)

        $Query = @{policy=""}

        $AwsRequest = Get-AwsRequest -AccessKey $Config.aws_access_key_id -SecretKey $Config.aws_secret_access_key -Method $Method -EndpointUrl $Config.endpoint_url -Presign:$Presign -SignerType $SignerType -Bucket $BucketName -UrlStyle $UrlStyle -Query $Query -Region $Region

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Result = Invoke-AwsRequest -SkipCertificateCheck:$SkipCertificateCheck -Method $Method -Uri $AwsRequest.Uri -Headers $AwsRequest.Headers -ErrorAction Stop

            Write-Output $Result.Content
        }
    }
}

Set-Alias -Name Add-S3BucketPolicy -Value Replace-S3BucketPolicy
Set-Alias -Name Write-S3BucketPolicy -Value Replace-S3BucketPolicy
<#
    .SYNOPSIS
    Replace S3 Bucket ACL
    .DESCRIPTION
    Replace S3 Bucket ACL
#>
function Global:Replace-S3BucketPolicy {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
                Mandatory=$False,
                Position=0,
                HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
                Mandatory=$False,
                Position=1,
                HelpMessage="Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
                Mandatory=$False,
                Position=2,
                HelpMessage="Use presigned URL")][Switch]$Presign,
        [parameter(
                Mandatory=$False,
                Position=3,
                HelpMessage="Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
                Mandatory=$False,
                Position=4,
                HelpMessage="AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)")][String][ValidateSet("S3","AWS4")]$SignerType="AWS4",
        [parameter(
                Mandatory=$False,
                Position=5,
                HelpMessage="Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=6,
                HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][Alias("Profile")][String]$ProfileName,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=7,
                HelpMessage="AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=6,
                HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=7,
                HelpMessage="S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
                ParameterSetName="account",
                Mandatory=$False,
                Position=6,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
                Mandatory=$False,
                Position=8,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Region to be used")][String]$Region,
        [parameter(
                Mandatory=$False,
                Position=9,
                HelpMessage="Bucket URL Style (Default: path)")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
                Mandatory=$True,
                Position=10,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Bucket Name")][Alias("Name","Bucket")][String]$BucketName,
        [parameter(
                Mandatory=$True,
                Position=11,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="The bucket policy as a JSON document")][String]$Policy
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId
        $Method = "PUT"
    }

    Process {
        if (!$Region) {
            $Region = $Config.Region
        }

        # Convert Bucket Name to IDN mapping to support Unicode Names
        $BucketName = [System.Globalization.IdnMapping]::new().GetAscii($BucketName)

        $Query = @{policy=""}

        # pretty print JSON to simplify debugging
        $Policy = ConvertFrom-Json -InputObject $Policy | ConvertTo-Json -Depth 10

        $AwsRequest = Get-AwsRequest -AccessKey $Config.aws_access_key_id -SecretKey $Config.aws_secret_access_key -Method $Method -EndpointUrl $Config.endpoint_url -Presign:$Presign -SignerType $SignerType -Bucket $BucketName -UrlStyle $UrlStyle -Query $Query -Region $Region -RequestPayload $Policy

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Result = Invoke-AwsRequest -SkipCertificateCheck:$SkipCertificateCheck -Method $Method -Uri $AwsRequest.Uri -Headers $AwsRequest.Headers -Body $Policy -ErrorAction Stop

            Write-Output $Result.Content
        }
    }
}

<#
    .SYNOPSIS
    Get S3 Bucket Versioning
    .DESCRIPTION
    Get S3 Bucket Versioning
#>
function Global:Get-S3BucketVersioning {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
                Mandatory=$False,
                Position=0,
                HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
                Mandatory=$False,
                Position=1,
                HelpMessage="Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
                Mandatory=$False,
                Position=2,
                HelpMessage="Use presigned URL")][Switch]$Presign,
        [parameter(
                Mandatory=$False,
                Position=3,
                HelpMessage="Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
                Mandatory=$False,
                Position=4,
                HelpMessage="AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)")][String][ValidateSet("S3","AWS4")]$SignerType="AWS4",
        [parameter(
                Mandatory=$False,
                Position=5,
                HelpMessage="Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=6,
                HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][Alias("Profile")][String]$ProfileName,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=7,
                HelpMessage="AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=6,
                HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=7,
                HelpMessage="S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
                ParameterSetName="account",
                Mandatory=$False,
                Position=6,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
                Mandatory=$False,
                Position=8,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Region to be used")][String]$Region,
        [parameter(
                Mandatory=$False,
                Position=9,
                HelpMessage="Bucket URL Style (Default: path)")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
                Mandatory=$True,
                Position=10,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Bucket")][Alias("Name","Bucket")][String]$BucketName
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId
        $Method = "GET"
    }

    Process {
        if (!$Region) {
            $Region = $Config.Region
        }

        # Convert Bucket Name to IDN mapping to support Unicode Names
        $BucketName = [System.Globalization.IdnMapping]::new().GetAscii($BucketName)

        $Query = @{versioning=""}

        $AwsRequest = Get-AwsRequest -AccessKey $Config.aws_access_key_id -SecretKey $Config.aws_secret_access_key -Method $Method -EndpointUrl $Config.endpoint_url -Presign:$Presign -SignerType $SignerType -Bucket $BucketName -UrlStyle $UrlStyle -Query $Query -Region $Region

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Result = Invoke-AwsRequest -SkipCertificateCheck:$SkipCertificateCheck -Method $Method -Uri $AwsRequest.Uri -Headers $AwsRequest.Headers -ErrorAction Stop

            # it seems AWS is sometimes not sending the Content-Type and then PowerShell does not parse the binary to string
            if (!$Result.Headers.'Content-Type') {
                $Content = [XML][System.Text.Encoding]::UTF8.GetString($Result.Content)
            }
            else {
                $Content = [XML]$Result.Content
            }

            Write-Output $Content.VersioningConfiguration.Status
        }
    }
}

<#
    .SYNOPSIS
    Enable S3 Bucket Versioning
    .DESCRIPTION
    Enable S3 Bucket Versioning
#>
function Global:Enable-S3BucketVersioning {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
                Mandatory=$False,
                Position=0,
                HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
                Mandatory=$False,
                Position=1,
                HelpMessage="Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
                Mandatory=$False,
                Position=2,
                HelpMessage="Use presigned URL")][Switch]$Presign,
        [parameter(
                Mandatory=$False,
                Position=3,
                HelpMessage="Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
                Mandatory=$False,
                Position=4,
                HelpMessage="AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)")][String][ValidateSet("S3","AWS4")]$SignerType="AWS4",
        [parameter(
                Mandatory=$False,
                Position=5,
                HelpMessage="Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=6,
                HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][Alias("Profile")][String]$ProfileName,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=7,
                HelpMessage="AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=6,
                HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=7,
                HelpMessage="S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
                ParameterSetName="account",
                Mandatory=$False,
                Position=6,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
                Mandatory=$False,
                Position=8,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Region to be used")][String]$Region,
        [parameter(
                Mandatory=$False,
                Position=9,
                HelpMessage="Bucket URL Style (Default: path)")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
                Mandatory=$True,
                Position=10,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Bucket")][Alias("Name","Bucket")][String]$BucketName
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId
        $Method = "PUT"
    }

    Process {
        # Convert Bucket Name to IDN mapping to support Unicode Names
        $BucketName = [System.Globalization.IdnMapping]::new().GetAscii($BucketName)

        $Query = @{versioning=""}

        $RequestPayload = "<VersioningConfiguration xmlns=`"http://s3.amazonaws.com/doc/2006-03-01/`"><Status>Enabled</Status></VersioningConfiguration>"

        $AwsRequest = Get-AwsRequest -AccessKey $Config.aws_access_key_id -SecretKey $Config.aws_secret_access_key -Method $Method -EndpointUrl $Config.endpoint_url -Presign:$Presign -SignerType $SignerType -Query $Query -Bucket $BucketName -UrlStyle $UrlStyle -RequestPayload $RequestPayload -Region $Region

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Result = Invoke-AwsRequest -SkipCertificateCheck:$SkipCertificateCheck -Method $Method -Uri $AwsRequest.Uri -Headers $AwsRequest.Headers -Body $RequestPayload -ErrorAction Stop

            # it seems AWS is sometimes not sending the Content-Type and then PowerShell does not parse the binary to string
            if (!$Result.Headers.'Content-Type') {
                $Content = [XML][System.Text.Encoding]::UTF8.GetString($Result.Content)
            }
            else {
                $Content = [XML]$Result.Content
            }

            Write-Output $Content.VersioningConfiguration.Status
        }
    }
}

<#
    .SYNOPSIS
    Suspend S3 Bucket Versioning
    .DESCRIPTION
    Suspend S3 Bucket Versioning
#>
function Global:Suspend-S3BucketVersioning {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
                Mandatory=$False,
                Position=0,
                HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
                Mandatory=$False,
                Position=1,
                HelpMessage="Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
                Mandatory=$False,
                Position=2,
                HelpMessage="Use presigned URL")][Switch]$Presign,
        [parameter(
                Mandatory=$False,
                Position=3,
                HelpMessage="Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
                Mandatory=$False,
                Position=4,
                HelpMessage="AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)")][String][ValidateSet("S3","AWS4")]$SignerType="AWS4",
        [parameter(
                Mandatory=$False,
                Position=5,
                HelpMessage="Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=6,
                HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][Alias("Profile")][String]$ProfileName,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=7,
                HelpMessage="AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=6,
                HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=7,
                HelpMessage="S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
                ParameterSetName="account",
                Mandatory=$False,
                Position=6,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
                Mandatory=$False,
                Position=8,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Region to be used")][String]$Region,
        [parameter(
                Mandatory=$False,
                Position=9,
                HelpMessage="Bucket URL Style (Default: path)")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
                Mandatory=$True,
                Position=10,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Bucket")][Alias("Name","Bucket")][String]$BucketName
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId
        $Method = "PUT"
    }

    Process {
        if (!$Region) {
            $Region = $Config.Region
        }

        # Convert Bucket Name to IDN mapping to support Unicode Names
        $BucketName = [System.Globalization.IdnMapping]::new().GetAscii($BucketName)

        $Query = @{versioning=""}

        $RequestPayload = "<VersioningConfiguration xmlns=`"http://s3.amazonaws.com/doc/2006-03-01/`"><Status>Suspended</Status></VersioningConfiguration>"

        $AwsRequest = Get-AwsRequest -AccessKey $Config.aws_access_key_id -SecretKey $Config.aws_secret_access_key -Method $Method -EndpointUrl $Config.endpoint_url -Presign:$Presign -SignerType $SignerType -Query $Query -Bucket $BucketName -UrlStyle $UrlStyle -RequestPayload $RequestPayload -Region $Region

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Result = Invoke-AwsRequest -SkipCertificateCheck:$SkipCertificateCheck -Method $Method -Uri $AwsRequest.Uri -Headers $AwsRequest.Headers -Body $RequestPayload -ErrorAction Stop

            # it seems AWS is sometimes not sending the Content-Type and then PowerShell does not parse the binary to string
            if (!$Result.Headers.'Content-Type') {
                $Content = [XML][System.Text.Encoding]::UTF8.GetString($Result.Content)
            }
            else {
                $Content = [XML]$Result.Content
            }

            Write-Output $Content.VersioningConfiguration.Status
        }
    }
}

Set-Alias -Name Get-S3BucketRegion -Value Get-S3BucketLocation
<#
    .SYNOPSIS
    Get S3 Bucket Location
    .DESCRIPTION
    Get S3 Bucket Location
#>
function Global:Get-S3BucketLocation {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
                Mandatory=$False,
                Position=0,
                HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
                Mandatory=$False,
                Position=1,
                HelpMessage="Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
                Mandatory=$False,
                Position=2,
                HelpMessage="Use presigned URL")][Switch]$Presign,
        [parameter(
                Mandatory=$False,
                Position=3,
                HelpMessage="Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
                Mandatory=$False,
                Position=4,
                HelpMessage="AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)")][String][ValidateSet("S3","AWS4")]$SignerType="AWS4",
        [parameter(
                Mandatory=$False,
                Position=5,
                HelpMessage="Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=6,
                HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][Alias("Profile")][String]$ProfileName,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=7,
                HelpMessage="AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=6,
                HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=7,
                HelpMessage="S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
                ParameterSetName="account",
                Mandatory=$False,
                Position=6,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
                Mandatory=$False,
                Position=8,
                HelpMessage="Bucket URL Style (Default: path)")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
                Mandatory=$False,
                Position=9,
                HelpMessage="Use the dualstack endpoint of the specified region. S3 supports dualstack endpoints which return both IPv6 and IPv4 values.")][Switch]$UseDualstackEndpoint,
        [parameter(
                Mandatory=$True,
                Position=10,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Bucket")][Alias("Name","Bucket")][String]$BucketName
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId
        $Method = "GET"
    }

    Process {
        Write-Verbose "Retrieving location for bucket $BucketName"

        # Convert Bucket Name to IDN mapping to support Unicode Names
        $BucketName = [System.Globalization.IdnMapping]::new().GetAscii($BucketName)

        $Uri = "/"

        $Query = @{location=""}

        $AwsRequest = Get-AwsRequest -AccessKey $Config.aws_access_key_id -SecretKey $Config.aws_secret_access_key -Method $Method -EndpointUrl $Config.endpoint_url -Uri $Uri -Query $Query -Bucket $BucketName -Presign:$Presign -SignerType $SignerType

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Result = Invoke-AwsRequest -SkipCertificateCheck:$SkipCertificateCheck -Method $Method -Uri $AwsRequest.Uri -Headers $AwsRequest.Headers -ErrorAction Stop

            # it seems AWS is sometimes not sending the Content-Type and then PowerShell does not parse the binary to string
            if (!$Result.Headers.'Content-Type') {
                $Content = [XML][System.Text.Encoding]::UTF8.GetString($Result.Content)
            }
            else {
                $Content = [XML]$Result.Content
            }

            $Location = $Content.LocationConstraint.InnerText

            if (!$Location) {
                # if no location is returned, bucket is in default region us-east-1
                Write-Output "us-east-1"
            }
            else {
                Write-Output $Content.LocationConstraint.InnerText
            }
        }
    }
}

## Objects ##

Set-Alias -Name Get-S3Object -Value Get-S3Objects
<#
    .SYNOPSIS
    Get S3 Objects in Bucket
    .DESCRIPTION
    Get S3 Objects in Bucket
#>
function Global:Get-S3Objects {
    [CmdletBinding(DefaultParameterSetName="account")]

    PARAM (
        [parameter(
                Mandatory=$False,
                Position=0,
                HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
                Mandatory=$False,
                Position=1,
                HelpMessage="Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
                Mandatory=$False,
                Position=2,
                HelpMessage="Use presigned URL")][Switch]$Presign,
        [parameter(
                Mandatory=$False,
                Position=3,
                HelpMessage="Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
                Mandatory=$False,
                Position=4,
                HelpMessage="AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)")][String][ValidateSet("S3","AWS4")]$SignerType="AWS4",
        [parameter(
                Mandatory=$False,
                Position=5,
                HelpMessage="Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=6,
                HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][Alias("Profile")][String]$ProfileName,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=7,
                HelpMessage="AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=6,
                HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=7,
                HelpMessage="S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
                ParameterSetName="account",
                Mandatory=$False,
                Position=6,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
                Mandatory=$False,
                Position=8,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Region to be used")][String]$Region,
        [parameter(
                Mandatory=$False,
                Position=9,
                HelpMessage="Bucket URL Style (Default: path)")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
                Mandatory=$False,
                Position=10,
                HelpMessage="Use the dualstack endpoint of the specified region. S3 supports dualstack endpoints which return both IPv6 and IPv4 values.")][Switch]$UseDualstackEndpoint,
        [parameter(
                Mandatory=$True,
                Position=11,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Bucket Name")][Alias("Name","Bucket")][String]$BucketName,
        [parameter(
                Mandatory=$False,
                Position=12,
                HelpMessage="Maximum Number of keys to return")][Int][ValidateRange(0,1000)]$MaxKeys=0,
        [parameter(
                Mandatory=$False,
                Position=13,
                HelpMessage="Bucket prefix for filtering")][Alias("Key")][String]$Prefix,
        [parameter(
                Mandatory=$False,
                Position=14,
                HelpMessage="Bucket prefix for filtering")][String]$Delimiter,
        [parameter(
                Mandatory=$False,
                Position=15,
                HelpMessage="Return Owner information (Only valid for list type 2).")][Switch]$FetchOwner=$False,
        [parameter(
                Mandatory=$False,
                Position=16,
                HelpMessage="Return key names after a specific object key in your key space. The S3 service lists objects in UTF-8 character encoding in lexicographical order (Only valid for list type 2).")][String]$StartAfter,
        [parameter(
                Mandatory=$False,
                Position=17,
                HelpMessage="Continuation token (Only valid for list type 1).")][String]$Marker,
        [parameter(
                Mandatory=$False,
                Position=18,
                HelpMessage="Continuation token (Only valid for list type 2).")][String]$ContinuationToken,
        [parameter(
                Mandatory=$False,
                Position=19,
                HelpMessage="Encoding type (Only allowed value is url).")][String][ValidateSet("url")]$EncodingType="url",
        [parameter(
                Mandatory=$False,
                Position=20,
                HelpMessage="Bucket list type.")][String][ValidateSet(1,2)]$ListType=1
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        $Method = "GET"
    }

    Process {
        $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId

        if (!$Config) {
            Throw "No S3 credentials found"
        }

        if (!$Region) {
            $Region = $Config.Region
        }

        $Query = @{}

        if ($Delimiter) { $Query["delimiter"] = $Delimiter }
        if ($EncodingType) { $Query["encoding-type"] = $EncodingType }
        if ($MaxKeys -ge 1) {
            $Query["max-keys"] = $MaxKeys
        }
        if ($Prefix) { $Query["prefix"] = $Prefix }

        # S3 supports two types for listing buckets, but only v2 is recommended, thus using list-type=2 query parameter
        if ($ListType -eq 1) {
            if ($Marker) { $Query["marker"] = $Marker }
        }
        else {
            $Query["list-type"] = 2
            if ($FetchOwner) { $Query["fetch-owner"] = $FetchOwner }
            if ($StartAfter) { $Query["start-after"] = $StartAfter }
            if ($ContinuationToken) { $Query["continuation-token"] = $ContinuationToken }
        }

        $BucketName = [System.Globalization.IdnMapping]::new().GetAscii($BucketName)

        $AwsRequest = Get-AwsRequest -AccessKey $Config.aws_access_key_id -SecretKey $Config.aws_secret_access_key -Method $Method -EndpointUrl $Config.endpoint_url -Presign:$Presign -SignerType $SignerType -Bucket $BucketName -UrlStyle $UrlStyle -Region $Region -Query $Query -UseDualstackEndpoint:$UseDualstackEndpoint

        if ($DryRun) {
            Write-Output $AwsRequest
        }
        else {
            try {
                $Result = Invoke-AwsRequest -SkipCertificateCheck:$SkipCertificateCheck -Method $Method -Uri $AwsRequest.Uri -Headers $AwsRequest.Headers -ErrorAction Stop

                $Content = [XML][System.Net.WebUtility]::UrlDecode($Result.Content)

                $Objects = $Content.ListBucketResult.Contents | ? { $_ }

                Write-Verbose "ListBucketResult Name: $($Content.ListBucketResult.Name)"

                $UnicodeBucket = [System.Globalization.IdnMapping]::new().GetUnicode($Content.ListBucketResult.Name)

                foreach ($Object in $Objects) {
                    $Object = [PSCustomObject]@{Bucket=$UnicodeBucket;Region=$Region;Key=$Object.Key;LastModified=(Get-Date $Object.LastModified);ETag=($Object.ETag -replace '"','');Size=[long]$Object.Size;OwnerId=$Object.Owner.ID;OwnerDisplayName=$Object.Owner.DisplayName;StorageClass=$Object.StorageClass}
                    Write-Output $Object
                }

                if ($Content.ListBucketResult.IsTruncated -eq "true" -and $MaxKeys -eq 0) {
                    Write-Verbose "1000 Objects were returned and max keys was not limited so continuing to get all objects"
                    Write-Debug "NextMarker: $($Content.ListBucketResult.NextMarker)"
                    Get-S3Objects -AccessKey $Config.aws_access_key_id -SecretKey $Config.aws_secret_access_key -EndpointUrl $Config.endpoint_url -Region $Region -SkipCertificateCheck:$SkipCertificateCheck -UrlStyle $UrlStyle -UseDualstackEndpoint:$UseDualstackEndpoint -Bucket $BucketName -MaxKeys $MaxKeys -Prefix $Prefix -FetchOwner:$FetchOwner -StartAfter $StartAfter -ContinuationToken $Content.ListBucketResult.NextContinuationToken -Marker $Content.ListBucketResult.NextMarker
                }
            }
            catch {
                $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'
                if ([int]$_.Exception.Response.StatusCode -match "^3" -and $_.Exception.Response.Headers.TryGetValues("x-amz-bucket-region",[ref]$RedirectedRegion)) {
                    Write-Warning "Request was redirected as bucket does not belong to region $Region. Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                    Get-S3Objects -SkipCertificateCheck:$SkipCertificateCheck -Presign:$Presign -DryRun:$DryRun -SignerType $SignerType -EndpointUrl $Config.endpoint_url -AccessKey $Config.aws_access_key_id -SecretKey $Config.aws_secret_access_key -Region $($RedirectedRegion[0]) -UrlStyle $UrlStyle -UseDualstackEndpoint:$UseDualstackEndpoint -Bucket $BucketName -MaxKeys $MaxKeys -Prefix $Prefix -Delimiter $Delimiter -FetchOwner:$FetchOwner -StartAfter $StartAfter -Marker $Marker -ContinuationToken $ContinuationToken -EncodingType $EncodingType
                }
                else {
                    Throw $_
                }
            }
        }
    }
}

Set-Alias -Name Get-S3Version -Value Get-S3ObjectVersions
Set-Alias -Name Get-S3Versions -Value Get-S3ObjectVersions
<#
    .SYNOPSIS
    Get S3 Object Versions
    .DESCRIPTION
    Get S3 Object Versions
#>
function Global:Get-S3ObjectVersions {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
                Mandatory=$False,
                Position=0,
                HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
                Mandatory=$False,
                Position=1,
                HelpMessage="Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
                Mandatory=$False,
                Position=2,
                HelpMessage="Use presigned URL")][Switch]$Presign,
        [parameter(
                Mandatory=$False,
                Position=3,
                HelpMessage="Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
                Mandatory=$False,
                Position=4,
                HelpMessage="AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)")][String][ValidateSet("S3","AWS4")]$SignerType="AWS4",
        [parameter(
                Mandatory=$False,
                Position=5,
                HelpMessage="Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=6,
                HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][Alias("Profile")][String]$ProfileName,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=7,
                HelpMessage="AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=6,
                HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=7,
                HelpMessage="S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
                ParameterSetName="account",
                Mandatory=$False,
                Position=6,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
                Mandatory=$False,
                Position=8,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Region to be used")][String]$Region,
        [parameter(
                Mandatory=$False,
                Position=9,
                HelpMessage="Bucket URL Style (Default: path)")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
                Mandatory=$True,
                Position=10,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Bucket Name")][Alias("Name","Bucket")][String]$BucketName,
        [parameter(
                Mandatory=$False,
                Position=10,
                HelpMessage="Maximum Number of keys to return")][Int][ValidateRange(0,1000)]$MaxKeys=0,
        [parameter(
                Mandatory=$False,
                Position=11,
                HelpMessage="Bucket prefix for filtering")][String]$Prefix,
        [parameter(
                Mandatory=$False,
                Position=12,
                HelpMessage="Bucket prefix for filtering")][String][ValidateLength(1,1)]$Delimiter,
        [parameter(
                Mandatory=$False,
                Position=13,
                HelpMessage="Continuation token for keys.")][String]$KeyMarker,
        [parameter(
                Mandatory=$False,
                Position=14,
                HelpMessage="Continuation token for versions.")][String]$VersionIdMarker,
        [parameter(
                Mandatory=$False,
                Position=15,
                HelpMessage="Encoding type (Only allowed value is url).")][String][ValidateSet("url")]$EncodingType
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId
        $Method = "GET"
    }

    Process {
        if (!$Region) {
            $Region = $Config.Region
        }

        $Query = @{versions=""}

        if ($Delimiter) { $Query["delimiter"] = $Delimiter }
        if ($EncodingType) { $Query["encoding-type"] = $EncodingType }
        if ($MaxKeys -ge 1) {
            $Query["max-keys"] = $MaxKeys
        }
        if ($Prefix) { $Query["prefix"] = $Prefix }
        if ($KeyMarker) { $Query["key-marker"] = $KeyMarker }
        if ($VersionIdMarker) { $Query["version-id-marker"] = $VersionIdMarker }

        $AwsRequest = Get-AwsRequest -AccessKey $Config.aws_access_key_id -SecretKey $Config.aws_secret_access_key -Method $Method -EndpointUrl $Config.endpoint_url -Presign:$Presign -SignerType $SignerType -Query $Query -Bucket $BucketName -UrlStyle $UrlStyle -Region $Region

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Result = Invoke-AwsRequest -SkipCertificateCheck:$SkipCertificateCheck -Method $Method -Uri $AwsRequest.Uri -Headers $AwsRequest.Headers -ErrorAction Stop

            $Content = [XML]$Result.Content

            $Versions = $Content.ListVersionsResult.Version | ? { $_ }
            $Versions | Add-Member -MemberType NoteProperty -Name Type -Value "Version"
            $DeleteMarkers = $Content.ListVersionsResult.DeleteMarker | ? { $_ }
            $DeleteMarkers | Add-Member -MemberType NoteProperty -Name Type -Value "DeleteMarker"
            $Versions += $DeleteMarkers

            foreach ($Version in $Versions) {
                $Version | Add-Member -MemberType NoteProperty -Name OwnerId -Value $Version.Owner.Id
                $Version | Add-Member -MemberType NoteProperty -Name OwnerDisplayName -Value $Version.Owner.DisplayName
                $Version | Add-Member -MemberType NoteProperty -Name Region -Value $Region
                $Version.PSObject.Members.Remove("Owner")
            }
            $Versions | Add-Member -MemberType NoteProperty -Name Bucket -Value $Content.ListVersionsResult.Name

            Write-Output $Versions

            if ($Content.ListVersionsResult.IsTruncated -eq "true" -and $MaxKeys -eq 0) {
                Write-Verbose "1000 Versions were returned and max keys was not limited so continuing to get all Versions"
                Get-S3BucketVersions -Server $Server -SkipCertificateCheck:$SkipCertificateCheck -Presign:$Presign -AccessKey $Config.aws_access_key_id -SecretKey $Config.aws_secret_access_key -EndpointUrl $Config.endpoint_url -Region $Region -UrlStyle $UrlStyle -Bucket $BucketName -MaxKeys $MaxKeys -Prefix $Prefix -KeyMarker $Content.ListVersionsResult.NextKeyMarker -VersionIdMarker $Content.ListVersionsResult.NextVersionIdMarker
            }
        }
    }
}

<#
    .SYNOPSIS
    Get S3 Presigned URL
    .DESCRIPTION
    Get S3 Presigned URL
#>
function Global:Get-S3PresignedUrl {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
                Mandatory=$False,
                Position=0,
                HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
                Mandatory=$False,
                Position=1,
                HelpMessage="Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
                Mandatory=$False,
                Position=2,
                HelpMessage="Use presigned URL")][Switch]$Presign,
        [parameter(
                Mandatory=$False,
                Position=3,
                HelpMessage="AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)")][String][ValidateSet("S3","AWS4")]$SignerType="AWS4",
        [parameter(
                Mandatory=$False,
                Position=4,
                HelpMessage="Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=5,
                HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][Alias("Profile")][String]$ProfileName,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=6,
                HelpMessage="AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=5,
                HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=6,
                HelpMessage="S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
                ParameterSetName="account",
                Mandatory=$False,
                Position=5,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
                Mandatory=$False,
                Position=7,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Region to be used")][String]$Region,
        [parameter(
                Mandatory=$False,
                Position=8,
                HelpMessage="Bucket URL Style (Default: path)")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
                Mandatory=$True,
                Position=9,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Bucket Name")][Alias("Name","Bucket")][String]$BucketName,
        [parameter(
                Mandatory=$True,
                Position=10,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Object key")][Alias("Object")][String]$Key,
        [parameter(
                Mandatory=$False,
                Position=11,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Object version ID")][String]$VersionId,
        [parameter(
                Mandatory=$False,
                Position=12,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Metadata")][Hashtable]$Metadata,
        [parameter(
                Mandatory=$False,
                Position=13,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Expiration Date of presigned URL (default 60 minutes from now)")][System.Datetime]$Expires=(Get-Date).AddHours(1),
        [parameter(
                Mandatory=$False,
                Position=14,
                HelpMessage="HTTP Request Method")][ValidateSet("OPTIONS","GET","HEAD","PUT","DELETE","TRACE","CONNECT")][String]$Method="GET"
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId
    }

    Process {
        if (!$Region) {
            $Region = $Config.Region
        }

        # Convert Bucket Name to IDN mapping to support Unicode Names
        $BucketName = [System.Globalization.IdnMapping]::new().GetAscii($BucketName)

        $Uri = "/$Key"
        $Presign = $true

        if ($VersionId) {
            $Query = @{versionId=$VersionId}
        }
        else {
            $Query = @{}
        }

        if ($Metadata) {
            foreach ($Key in $Metadata.Keys) {
                $Key = $Key -replace "^x-amz-meta-",""
                $Query["x-amz-meta-$Key"] = $Metadata[$Key]
            }
        }

        $AwsRequest = Get-AwsRequest -AccessKey $Config.aws_access_key_id -SecretKey $Config.aws_secret_access_key -Method $Method -EndpointUrl $Config.endpoint_url -Uri $Uri -Query $Query -Bucket $BucketName -Presign:$Presign -SignerType $SignerType -Region $Region -Expires $Expires

        Write-Output $AwsRequest.Uri.ToString()
    }
}

<#
    .SYNOPSIS
    Get S3 Object
    .DESCRIPTION
    Get S3 Object
#>
function Global:Get-S3ObjectMetadata {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
                Mandatory=$False,
                Position=0,
                HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
                Mandatory=$False,
                Position=1,
                HelpMessage="Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
                Mandatory=$False,
                Position=2,
                HelpMessage="Use presigned URL")][Switch]$Presign,
        [parameter(
                Mandatory=$False,
                Position=3,
                HelpMessage="Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
                Mandatory=$False,
                Position=4,
                HelpMessage="AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)")][String][ValidateSet("S3","AWS4")]$SignerType="AWS4",
        [parameter(
                Mandatory=$False,
                Position=5,
                HelpMessage="Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=6,
                HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][Alias("Profile")][String]$ProfileName,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=7,
                HelpMessage="AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=6,
                HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=7,
                HelpMessage="S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
                ParameterSetName="account",
                Mandatory=$False,
                Position=6,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
                Mandatory=$False,
                Position=8,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Region to be used")][String]$Region,
        [parameter(
                Mandatory=$False,
                Position=9,
                HelpMessage="Bucket URL Style (Default: path)")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
                Mandatory=$True,
                Position=10,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Bucket Name")][Alias("Name","Bucket")][String]$BucketName,
        [parameter(
                Mandatory=$True,
                Position=11,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Object key")][Alias("Object")][String]$Key,
        [parameter(
                Mandatory=$False,
                Position=12,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Object version ID")][String]$VersionId
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId

        $Method = "HEAD"
    }

    Process {
        if (!$Region) {
            $Region = $Config.Region
        }

        # Convert Bucket Name to IDN mapping to support Unicode Names
        $BucketName = [System.Globalization.IdnMapping]::new().GetAscii($BucketName)

        $Uri = "/$Key"

        if ($VersionId) {
            $Query = @{versionId=$VersionId}
        }
        else {
            $Query = @{}
        }

        $AwsRequest = Get-AwsRequest -AccessKey $Config.aws_access_key_id -SecretKey $Config.aws_secret_access_key -Method $Method -EndpointUrl $Config.endpoint_url -Uri $Uri -Query $Query -Bucket $BucketName -Presign:$Presign -SignerType $SignerType -Region $Region

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Result = Invoke-AwsRequest -SkipCertificateCheck:$SkipCertificateCheck -Method $Method -Uri $AwsRequest.Uri -Headers $AwsRequest.Headers -ErrorAction Stop

            $Headers = $Result.Headers
            $Metadata = @{}
            $CustomMetadata = @{}
            foreach ($MetadataKey in $Headers.Keys) {
                $Value = $Headers[$MetadataKey]
                if ($MetadataKey -match "x-amz-meta-") {
                    $MetadataKey = $MetadataKey -replace "x-amz-meta-",""
                    $CustomMetadata[$MetadataKey] = $Value
                }
                $Metadata[$MetadataKey] = $Value
            }

            # TODO: Implement missing Metadata

            $PartCount = ($Headers["ETag"] -split "-")[1]

            $Output = [PSCustomObject]@{Headers=$Headers;
                Metadata=$Metadata;
                CustomMetadata=$CustomMetadata;
                DeleteMarker=$null;
                AcceptRanges=$Headers.'Accept-Ranges' | Select -First 1;
                Expiration=$Headers["x-amz-expiration"] | Select -First 1;
                RestoreExpiration=$null;
                RestoreInProgress=$null;
                LastModified=$Headers.'Last-Modified' | Select -First 1;
                ETag=$Headers.ETag -replace '"','' | Select -First 1;
                MissingMeta=[int]$Headers["x-amz-missing-meta"] | Select -First 1;
                VersionId=$Headers["x-amz-version-id"] | Select -First 1;
                Expires=$null;
                WebsiteRedirectLocation=$null;
                ServerSideEncryptionMethod=$Headers["x-amz-server-side​-encryption"] | Select -First 1;
                ServerSideEncryptionCustomerMethod=$Headers["x-amz-server-side​-encryption​-customer-algorithm"] | Select -First 1;
                ServerSideEncryptionKeyManagementServiceKeyId=$Headers["x-amz-server-side-encryption-aws-kms-key-id"] | Select -First 1;
                ReplicationStatus=$Headers["x-amz-replication-status"] | Select -First 1;
                PartsCount=$PartCount;
                StorageClass=$Headers["x-amz-storage-class"] | Select -First 1;
            }

            Write-Output $Output
        }
    }
}

Set-Alias -Name Get-S3Object -Value Read-S3Object
<#
    .SYNOPSIS
    Read an S3 Object
    .DESCRIPTION
    Read an S3 Object
#>
function Global:Read-S3Object {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
                Mandatory=$False,
                Position=0,
                HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
                Mandatory=$False,
                Position=1,
                HelpMessage="Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
                Mandatory=$False,
                Position=2,
                HelpMessage="Use presigned URL")][Switch]$Presign,
        [parameter(
                Mandatory=$False,
                Position=3,
                HelpMessage="Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
                Mandatory=$False,
                Position=4,
                HelpMessage="AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)")][String][ValidateSet("S3","AWS4")]$SignerType="AWS4",
        [parameter(
                Mandatory=$False,
                Position=5,
                HelpMessage="Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=6,
                HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][Alias("Profile")][String]$ProfileName,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=7,
                HelpMessage="AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=6,
                HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=7,
                HelpMessage="S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
                ParameterSetName="account",
                Mandatory=$False,
                Position=6,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
                Mandatory=$False,
                Position=8,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Region to be used")][String]$Region,
        [parameter(
                Mandatory=$False,
                Position=9,
                HelpMessage="Bucket URL Style (Default: path)")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
                Mandatory=$True,
                Position=10,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Bucket Name")][Alias("Name","Bucket")][String]$BucketName,
        [parameter(
                Mandatory=$True,
                Position=11,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Object key")][Alias("Object")][String]$Key,
        [parameter(
                Mandatory=$False,
                Position=12,
                HelpMessage="Byte range to retrieve from object")][String]$Range,
        [parameter(
                Mandatory=$False,
                Position=13,
                HelpMessage="Path where object should be stored")][Alias("OutFile")][System.IO.DirectoryInfo]$Path
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId

        $Method = "GET"
    }

    Process {
        if (!$Region) {
            $Region = $Config.Region
        }

        # Convert Bucket Name to IDN mapping to support Unicode Names
        $BucketName = [System.Globalization.IdnMapping]::new().GetAscii($BucketName)

        $Uri = "/$Key"

        $Headers = @{}
        if ($Range) {            
            $Headers["Range"] = $Range
        }

        if ($Path) {
            if ($Path.Exists) {
                $Item = Get-Item $Path
                if ($Item -is [FileInfo]) {
                    $OutFile = $Item
                }
                else {
                    $OutFile = Join-Path -Path $Path -ChildPath $Key
                }
            }
            elseif ($Path.Parent.Exists) {
                $OutFile = $Path
            }
            else {
                Throw "Path $Path does not exist and parent directory $($Path.Parent) also does not exist"
            }
        }

        $AwsRequest = Get-AwsRequest -AccessKey $Config.aws_access_key_id -SecretKey $Config.aws_secret_access_key -Method $Method -EndpointUrl $Config.endpoint_url -Uri $Uri -Query $Query -Bucket $BucketName -Presign:$Presign -SignerType $SignerType -Region $Region

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Result = Invoke-AwsRequest -SkipCertificateCheck:$SkipCertificateCheck -Method $Method -Uri $AwsRequest.Uri -Headers $AwsRequest.Headers -OutFile $OutFile -ErrorAction Stop
            Write-Output $Result.Content
        }
    }
}

<#
    .SYNOPSIS
    Write S3 Object
    .DESCRIPTION
    Write S3 Object
#>
function Global:Write-S3Object {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
                Mandatory=$False,
                Position=0,
                HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
                Mandatory=$False,
                Position=1,
                HelpMessage="Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
                Mandatory=$False,
                Position=2,
                HelpMessage="Use presigned URL")][Switch]$Presign,
        [parameter(
                Mandatory=$False,
                Position=3,
                HelpMessage="Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
                Mandatory=$False,
                Position=4,
                HelpMessage="AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)")][String][ValidateSet("S3","AWS4")]$SignerType="AWS4",
        [parameter(
                Mandatory=$False,
                Position=5,
                HelpMessage="Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
                ParameterSetName="ProfileAndFile",
                Mandatory=$False,
                Position=6,
                HelpMessage="AWS Profile to use which contains AWS sredentials and settings")]
        [parameter(
                ParameterSetName="ProfileAndContent",
                Mandatory=$False,
                Position=6,
                HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][Alias("Profile")][String]$ProfileName,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=7,
                HelpMessage="AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
                ParameterSetName="KeyAndFile",
                Mandatory=$True,
                Position=6,
                HelpMessage="S3 Access Key")]
        [parameter(
                ParameterSetName="KeyAndContent",
                Mandatory=$True,
                Position=6,
                HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
                ParameterSetName="KeyAndFile",
                Mandatory=$True,
                Position=7,
                HelpMessage="S3 Secret Access Key")]
        [parameter(
                ParameterSetName="KeyAndContent",
                Mandatory=$True,
                Position=7,
                HelpMessage="S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
                ParameterSetName="AccountAndFile",
                Mandatory=$True,
                Position=6,
                HelpMessage="StorageGRID account ID to execute this command against")]
        [parameter(
                ParameterSetName="AccountAndContent",
                Mandatory=$True,
                Position=6,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
                Mandatory=$False,
                Position=8,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Region to be used")][String]$Region,
        [parameter(
                Mandatory=$False,
                Position=9,
                HelpMessage="Bucket URL Style (Default: path)")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
                Mandatory=$True,
                Position=10,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Bucket Name")][Alias("Name","Bucket")][String]$BucketName,
        [parameter(
                Mandatory=$False,
                Position=11,
                ParameterSetName="ProfileAndFile",
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Object key. If not provided, filename will be used")]
        [parameter(
                Mandatory=$False,
                Position=11,
                ParameterSetName="KeyAndFile",
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Object key. If not provided, filename will be used")]
        [parameter(
                Mandatory=$False,
                Position=11,
                ParameterSetName="AccountAndFile",
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Object key. If not provided, filename will be used")]
        [parameter(
                Mandatory=$True,
                Position=11,
                ParameterSetName="ProfileAndContent",
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Object key. If not provided, filename will be used")]
        [parameter(
                Mandatory=$True,
                Position=11,
                ParameterSetName="KeyAndContent",
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Object key. If not provided, filename will be used")]
        [parameter(
                Mandatory=$True,
                Position=11,
                ParameterSetName="AccountAndContent",
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Object key. If not provided, filename will be used")][Alias("Object")][String]$Key,
        [parameter(
                Mandatory=$True,
                Position=12,
                ParameterSetName="ProfileAndFile",
                HelpMessage="Path where object should be stored")]
        [parameter(
                Mandatory=$True,
                Position=12,
                ParameterSetName="KeyAndFile",
                HelpMessage="Path where object should be stored")]
        [parameter(
                Mandatory=$True,
                Position=12,
                ParameterSetName="AccountAndFile",
                HelpMessage="Path where object should be stored")][Alias("Path","File")][System.IO.FileInfo]$InFile,
        [parameter(
                Mandatory=$True,
                Position=13,
                ParameterSetName="ProfileAndContent",
                HelpMessage="Content of object")]
        [parameter(
                Mandatory=$True,
                Position=13,
                ParameterSetName="KeyAndContent",
                HelpMessage="Content of object")]
        [parameter(
                Mandatory=$True,
                Position=13,
                ParameterSetName="AccountAndContent",
                HelpMessage="Content of object")][Alias("InputObject")][String]$Content,
        [parameter(
                Mandatory=$False,
                Position=14,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Metadata")][Hashtable]$Metadata
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId

        $Method = "PUT"
    }
 
    Process {
        if (!$Region) {
            $Region = $Config.Region
        }

        # Convert Bucket Name to IDN mapping to support Unicode Names
        $BucketName = [System.Globalization.IdnMapping]::new().GetAscii($BucketName)

        if ($InFile -and !$InFile.Exists) {
            Throw "File $InFile does not exist"
        }

        # TODO: Check MIME type of file
        if (!$InFile) {
            $ContentType = "text/plain"
        }

        if (!$Key) {
            $Key = $InFile.Name
        }

        $Headers = @{}
        if ($Metadata) {
            foreach ($MetadataKey in $Metadata.Keys) {
                $MetadataKey = $MetadataKey -replace "^x-amz-meta-",""
                $MetadataKey = $MetadataKey.toLower()
                $Headers["x-amz-meta-$MetadataKey"] = $Metadata[$MetadataKey]
                # TODO: check that metadata is valid HTTP Header
            }
        }
        Write-Verbose "Metadata:`n$($Headers | ConvertTo-Json)"
        
        $Uri = "/$Key"

        $AwsRequest = Get-AwsRequest -AccessKey $Config.aws_access_key_id -SecretKey $Config.aws_secret_access_key -Method $Method -EndpointUrl $Config.endpoint_url -Uri $Uri -Query $Query -Bucket $BucketName -Presign:$Presign -SignerType $SignerType -Region $Region -InFile $InFile -RequestPayload $Content -ContentType $ContentType -Headers $Headers

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            try {
                $Result = Invoke-AwsRequest -SkipCertificateCheck:$SkipCertificateCheck -Method $Method -Uri $AwsRequest.Uri -Headers $AwsRequest.Headers -InFile $InFile -Body $Content -ContentType $ContentType
            }
            catch {
                $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'
                if ([int]$_.Exception.Response.StatusCode -match "^3" -and $_.Exception.Response.Headers.TryGetValues("x-amz-bucket-region",[ref]$RedirectedRegion)) {
                    Write-Warning "Request was redirected as bucket does not belong to region $Region. Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                    if ($InFile) {
                        Write-S3Object -SkipCertificateCheck:$SkipCertificateCheck -Presign:$Presign -DryRun:$DryRun -SignerType $SignerType -EndpointUrl $Config.endpoint_url -AccessKey $Config.aws_access_key_id -SecretKey $Config.aws_secret_access_key -Region $($RedirectedRegion[0]) -UrlStyle $UrlStyle -Bucket $BucketName -Key $Key -InFile $InFile -Metadata $Metadata
                    }
                    else {
                        Write-S3Object -SkipCertificateCheck:$SkipCertificateCheck -Presign:$Presign -DryRun:$DryRun -SignerType $SignerType -EndpointUrl $Config.endpoint_url -AccessKey $Config.aws_access_key_id -SecretKey $Config.aws_secret_access_key -Region $($RedirectedRegion[0]) -UrlStyle $UrlStyle -Bucket $BucketName -Key $Key -Content $Content -Metadata $Metadata
                    }
                }
                else {
                    Throw $_
                }
            }

            Write-Output $Result.Content
        }
    }
}

<#
    .SYNOPSIS
    Remove S3 Object
    .DESCRIPTION
    Remove S3 Object
#>
function Global:Remove-S3Object {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
                Mandatory=$False,
                Position=0,
                HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
                Mandatory=$False,
                Position=1,
                HelpMessage="Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
                Mandatory=$False,
                Position=2,
                HelpMessage="Use presigned URL")][Switch]$Presign,
        [parameter(
                Mandatory=$False,
                Position=3,
                HelpMessage="Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
                Mandatory=$False,
                Position=4,
                HelpMessage="AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)")][String][ValidateSet("S3","AWS4")]$SignerType="AWS4",
        [parameter(
                Mandatory=$False,
                Position=5,
                HelpMessage="Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=6,
                HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][Alias("Profile")][String]$ProfileName,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=7,
                HelpMessage="AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=6,
                HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=7,
                HelpMessage="S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
                ParameterSetName="account",
                Mandatory=$False,
                Position=6,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
                Mandatory=$False,
                Position=8,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Region to be used")][String]$Region,
        [parameter(
                Mandatory=$False,
                Position=9,
                HelpMessage="Bucket URL Style (Default: path)")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
                Mandatory=$False,
                Position=10,
                HelpMessage="Use the dualstack endpoint of the specified region. S3 supports dualstack endpoints which return both IPv6 and IPv4 values.")][Switch]$UseDualstackEndpoint,
        [parameter(
                Mandatory=$True,
                Position=11,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Bucket Name")][Alias("Name","Bucket")][String]$BucketName,
        [parameter(
                Mandatory=$True,
                Position=12,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Object key")][Alias("Object")][String]$Key,
        [parameter(
                Mandatory=$False,
                Position=13,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Object version ID")][String]$VersionId
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId

        $Method = "DELETE"
    }
 
    Process {
        if (!$Region) {
            $Region = $Config.Region
        }

        # Convert Bucket Name to IDN mapping to support Unicode Names
        $BucketName = [System.Globalization.IdnMapping]::new().GetAscii($BucketName)

        $Uri = "/$Key"

        if ($VersionId) {
            $Query = @{versionId=$VersionId}
        }
        else {
            $Query = @{}
        }

        $AwsRequest = Get-AwsRequest -AccessKey $Config.aws_access_key_id -SecretKey $Config.aws_secret_access_key -Method $Method -EndpointUrl $Config.endpoint_url -Uri $Uri -Query $Query -Bucket $BucketName -Presign:$Presign -SignerType $SignerType -Region $Region -UseDualstackEndpoint:$UseDualstackEndpoint

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Result = Invoke-AwsRequest -SkipCertificateCheck:$SkipCertificateCheck -Method $Method -Uri $AwsRequest.Uri -Headers $AwsRequest.Headers -ErrorAction Stop
        }
    }
}

<#
    .SYNOPSIS
    Copy S3 Object
    .DESCRIPTION
    Copy S3 Object
#>
function Global:Copy-S3Object {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
                Mandatory=$False,
                Position=0,
                HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
                Mandatory=$False,
                Position=1,
                HelpMessage="Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
                Mandatory=$False,
                Position=2,
                HelpMessage="Use presigned URL")][Switch]$Presign,
        [parameter(
                Mandatory=$False,
                Position=3,
                HelpMessage="Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
                Mandatory=$False,
                Position=4,
                HelpMessage="AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)")][String][ValidateSet("S3","AWS4")]$SignerType="AWS4",
        [parameter(
                Mandatory=$False,
                Position=5,
                HelpMessage="Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=6,
                HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][Alias("Profile")][String]$ProfileName,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=7,
                HelpMessage="AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=6,
                HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=7,
                HelpMessage="S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
                ParameterSetName="account",
                Mandatory=$False,
                Position=6,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
                Mandatory=$False,
                Position=8,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Region to be used")][String]$Region,
        [parameter(
                Mandatory=$False,
                Position=9,
                HelpMessage="Bucket URL Style (Default: path)")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
                Mandatory=$True,
                Position=10,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Bucket Name")][Alias("Name","Bucket")][String]$BucketName,
        [parameter(
                Mandatory=$True,
                Position=11,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Object key")][Alias("Object")][String]$Key,
        [parameter(
                Mandatory=$True,
                Position=12,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Bucket")][String]$SourceBucket,
        [parameter(
                Mandatory=$True,
                Position=13,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Object key")][String]$SourceKey,
        [parameter(
                Mandatory=$False,
                Position=14,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Object version ID")][String]$SourceVersionId,
        [parameter(
                Mandatory=$False,
                Position=15,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Object version ID")][ValidateSet("COPY","REPLACE")][String]$MetadataDirective="COPY",
        [parameter(
                Mandatory=$False,
                Position=16,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Metadata")][Hashtable]$Metadata,
        [parameter(
                Mandatory=$False,
                Position=17,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Copies the object if its entity tag (ETag) matches the specified Etag")][String]$Etag,
        [parameter(
                Mandatory=$False,
                Position=18,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Copies the object if its entity tag (ETag) is different than the specified NotETag")][String]$NotEtag,
        [parameter(
                Mandatory=$False,
                Position=19,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Copies the object if it hasn't been modified since the specified time")][DateTime]$UnmodifiedSince,
        [parameter(
                Mandatory=$False,
                Position=20,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Copies the object if it has been modified since the specified time")][DateTime]$ModifiedSince,
        [parameter(
                Mandatory=$False,
                Position=21,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="S3 Storage Class")][ValidateSet("STANDARD","STANDARD_IA","REDUCED_REDUNDANCY")][String]$StorageClass,
        [parameter(
                Mandatory=$False,
                Position=22,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Specifies whether the object tags are copied from the source object or replaced with tags provided in the request")][ValidateSet("COPY","REPLACE")][String]$TaggingDirective="COPY",
        [parameter(
                Mandatory=$False,
                Position=23,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Object tags")][HashTable]$Tags,
        [parameter(
                Mandatory=$False,
                Position=24,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Object tags")][ValidateSet("aws:kms","AES256")][String]$ServerSideEncryption
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId

        $Method = "PUT"
    }

    Process {
        if (!$Region) {
            $Region = $Config.Region
        }

        # Convert Bucket Name to IDN mapping to support Unicode Names
        $BucketName = [System.Globalization.IdnMapping]::new().GetAscii($BucketName)

        $Uri = "/$Key"

        $Headers = @{}
        $Headers["x-amz-copy-source"] = "/$BucketName/$Key"
        if ($VersionId) {
            $Headers["x-amz-copy-source"] += "?versionId=$VersionId"
        }
        $Headers["x-amz-metadata-directive"] = $MetadataDirective
        if ($Etag) {
            $Headers["x-amz-copy-source-if-match"] = $Etag
        }
        if ($NotEtag) {
            $Headers["x-amz-copy-source-if-none-match"] = $NotEtag
        }
        if ($UnmodifiedSince) {
            $Headers["x-amz-copy-source-if-unmodified-since"] = $UnmodifiedSince
        }
        if ($ModifiedSince) {
            $Headers["x-amz-copy-source-if-modified-since"] = $ModifiedSince
        }
        if ($StorageClass) {
            $Headers["x-amz-storage-class"] = $StorageClass
        }
        if ($TaggingDirective) {
            $Headers["x-amz-tagging-directive"] = $TaggingDirective
        }
        if ($ServerSideEncryption) {
            $Headers["x-amz-server-side​-encryption"] = $ServerSideEncryption
        }

        $AwsRequest = Get-AwsRequest -AccessKey $Config.aws_access_key_id -SecretKey $Config.aws_secret_access_key -Method $Method -EndpointUrl $Config.endpoint_url -Uri $Uri -Query $Query -Bucket $BucketName -Presign:$Presign -SignerType $SignerType -Headers $Headers -Region $Region

        if ($DryRun) {
            Write-Output $AwsRequest
        }
        else {
            $Result = Invoke-AwsRequest -SkipCertificateCheck:$SkipCertificateCheck -Method $Method -Uri $AwsRequest.Uri -Headers $AwsRequest.Headers -ErrorAction Stop
        }
    }
}

# StorageGRID specific #

<#
    .SYNOPSIS
    Get S3 Bucket Consistency Setting
    .DESCRIPTION
    Get S3 Bucket Consistency Setting
#>
function Global:Get-S3BucketConsistency {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
                Mandatory=$False,
                Position=0,
                HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
                Mandatory=$False,
                Position=1,
                HelpMessage="Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
                Mandatory=$False,
                Position=2,
                HelpMessage="Use presigned URL")][Switch]$Presign,
        [parameter(
                Mandatory=$False,
                Position=3,
                HelpMessage="Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
                Mandatory=$False,
                Position=4,
                HelpMessage="AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)")][String][ValidateSet("S3","AWS4")]$SignerType="AWS4",
        [parameter(
                Mandatory=$False,
                Position=5,
                HelpMessage="Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=6,
                HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][Alias("Profile")][String]$ProfileName,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=7,
                HelpMessage="AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=6,
                HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=7,
                HelpMessage="S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
                ParameterSetName="account",
                Mandatory=$False,
                Position=6,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
                Mandatory=$False,
                Position=8,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Region to be used")][String]$Region,
        [parameter(
                Mandatory=$False,
                Position=9,
                HelpMessage="Bucket URL Style (Default: path)")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
                Mandatory=$True,
                Position=10,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Bucket")][Alias("Name","Bucket")][String]$BucketName
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId

        $Method = "GET"
    }
 
    Process {
        if (!$Region) {
            $Region = $Config.Region
        }

        # Convert Bucket Name to IDN mapping to support Unicode Names
        $BucketName = [System.Globalization.IdnMapping]::new().GetAscii($BucketName)

        $Query = @{"x-ntap-sg-consistency"=""}

        $AwsRequest = Get-AwsRequest -AccessKey $Config.aws_access_key_id -SecretKey $Config.aws_secret_access_key -Method $Method -EndpointUrl $Config.endpoint_url -Uri $Uri -Query $Query -Bucket $BucketName -Presign:$Presign -SignerType $SignerType -Region $Region

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Result = Invoke-AwsRequest -SkipCertificateCheck:$SkipCertificateCheck -Method $Method -Uri $AwsRequest.Uri -Headers $AwsRequest.Headers -ErrorAction Stop

            $Content = [XML]$Result.Content

            $BucketNameConsistency = [PSCustomObject]@{Bucket=$BucketName;Consistency=$Content.Consistency.InnerText}

            Write-Output $BucketNameConsistency
        }
    }
}

<#
    .SYNOPSIS
    Modify S3 Bucket Consistency Setting
    .DESCRIPTION
    Modify S3 Bucket Consistency Setting
#>
function Global:Update-S3BucketConsistency {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
                Mandatory=$False,
                Position=0,
                HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
                Mandatory=$False,
                Position=1,
                HelpMessage="Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
                Mandatory=$False,
                Position=2,
                HelpMessage="Use presigned URL")][Switch]$Presign,
        [parameter(
                Mandatory=$False,
                Position=3,
                HelpMessage="Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
                Mandatory=$False,
                Position=4,
                HelpMessage="AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)")][String][ValidateSet("S3","AWS4")]$SignerType="AWS4",
        [parameter(
                Mandatory=$False,
                Position=5,
                HelpMessage="Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=6,
                HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][Alias("Profile")][String]$ProfileName,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=7,
                HelpMessage="AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=6,
                HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=7,
                HelpMessage="S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
                ParameterSetName="account",
                Mandatory=$False,
                Position=6,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
                Mandatory=$False,
                Position=8,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Region to be used")][String]$Region,
        [parameter(
                Mandatory=$False,
                Position=9,
                HelpMessage="Bucket URL Style (Default: path)")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
                Mandatory=$True,
                Position=10,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Bucket Name")][Alias("Name","Bucket")][String]$BucketName,
        [parameter(
                Mandatory=$True,
                Position=11,
                HelpMessage="Bucket")][ValidateSet("all","strong-global","strong-site","default","available","weak")][String]$Consistency
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId

        $Method = "PUT"
    }
 
    Process {
        if (!$Region) {
            $Region = $Config.Region
        }

        # Convert Bucket Name to IDN mapping to support Unicode Names
        $BucketName = [System.Globalization.IdnMapping]::new().GetAscii($BucketName)

        $Query = @{"x-ntap-sg-consistency"=$Consistency}

        $AwsRequest = Get-AwsRequest -AccessKey $Config.aws_access_key_id -SecretKey $Config.aws_secret_access_key -Method $Method -EndpointUrl $Config.endpoint_url -Uri $Uri -Query $Query -Bucket $BucketName -Presign:$Presign -SignerType $SignerType -Region $Region

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Result = Invoke-AwsRequest -SkipCertificateCheck:$SkipCertificateCheck -Method $Method -Uri $AwsRequest.Uri -Headers $AwsRequest.Headers -ErrorAction Stop
        }
    }
}

<#
    .SYNOPSIS
    Get S3 Bucket Storage Usage
    .DESCRIPTION
    Get S3 Bucket Storage Usage
#>
function Global:Get-S3StorageUsage {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
                Mandatory=$False,
                Position=0,
                HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
                Mandatory=$False,
                Position=1,
                HelpMessage="Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
                Mandatory=$False,
                Position=2,
                HelpMessage="Use presigned URL")][Switch]$Presign,
        [parameter(
                Mandatory=$False,
                Position=3,
                HelpMessage="Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
                Mandatory=$False,
                Position=4,
                HelpMessage="AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)")][String][ValidateSet("S3","AWS4")]$SignerType="AWS4",
        [parameter(
                Mandatory=$False,
                Position=5,
                HelpMessage="Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=6,
                HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][Alias("Profile")][String]$ProfileName,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=7,
                HelpMessage="AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=6,
                HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=7,
                HelpMessage="S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
                ParameterSetName="account",
                Mandatory=$False,
                Position=6,
                HelpMessage="StorageGRID account ID to execute this command against")][String]$AccountId
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId

        $Method = "GET"
    }

    Process {
        $Uri = "/"

        $Query = @{"x-ntap-sg-usage"=""}

        $AwsRequest = Get-AwsRequest -AccessKey $Config.aws_access_key_id -SecretKey $Config.aws_secret_access_key -Method $Method -EndpointUrl $Config.endpoint_url -Uri $Uri -Query $Query -Bucket $BucketName -Presign:$Presign -SignerType $SignerType

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Result = Invoke-AwsRequest -SkipCertificateCheck:$SkipCertificateCheck -Method $Method -Uri $AwsRequest.Uri -Headers $AwsRequest.Headers -ErrorAction Stop

            $Content = [XML]$Result.Content

            $UsageResult = [PSCustomObject]@{CalculationTime=(Get-Date -Date $Content.UsageResult.CalculationTime);ObjectCount=$Content.UsageResult.ObjectCount;DataBytes=$Content.UsageResult.DataBytes;buckets=$Content.UsageResult.Buckets.ChildNodes}

            Write-Output $UsageResult
        }
    }
}

<#
    .SYNOPSIS
    Get S3 Bucket Last Access Time
    .DESCRIPTION
    Get S3 Bucket Last Access Time
#>
function Global:Get-S3BucketLastAccessTime {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
                Mandatory=$False,
                Position=0,
                HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
                Mandatory=$False,
                Position=1,
                HelpMessage="Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
                Mandatory=$False,
                Position=2,
                HelpMessage="Use presigned URL")][Switch]$Presign,
        [parameter(
                Mandatory=$False,
                Position=3,
                HelpMessage="Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
                Mandatory=$False,
                Position=4,
                HelpMessage="AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)")][String][ValidateSet("S3","AWS4")]$SignerType="AWS4",
        [parameter(
                Mandatory=$False,
                Position=5,
                HelpMessage="Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=6,
                HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][Alias("Profile")][String]$ProfileName,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=7,
                HelpMessage="AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=6,
                HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=7,
                HelpMessage="S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
                ParameterSetName="account",
                Mandatory=$False,
                Position=6,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
                Mandatory=$False,
                Position=8,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Region to be used")][String]$Region,
        [parameter(
                Mandatory=$False,
                Position=9,
                HelpMessage="Bucket URL Style (Default: path)")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
                Mandatory=$True,
                Position=10,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Bucket")][Alias("Name","Bucket")][String]$BucketName
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId

        $Method = "GET"
    }
 
    Process {
        if (!$Region) {
            $Region = $Config.Region
        }

        # Convert Bucket Name to IDN mapping to support Unicode Names
        $BucketName = [System.Globalization.IdnMapping]::new().GetAscii($BucketName)

        $Query = @{"x-ntap-sg-lastaccesstime"=""}

        $AwsRequest = Get-AwsRequest -AccessKey $Config.aws_access_key_id -SecretKey $Config.aws_secret_access_key -Method $Method -EndpointUrl $Config.endpoint_url -Uri $Uri -Query $Query -Bucket $BucketName -Presign:$Presign -SignerType $SignerType -Region $Region

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Result = Invoke-AwsRequest -SkipCertificateCheck:$SkipCertificateCheck -Method $Method -Uri $AwsRequest.Uri -Headers $AwsRequest.Headers -ErrorAction Stop

            $Content = [XML]$Result.Content

            $BucketNameLastAccessTime = [PSCustomObject]@{Bucket=$BucketName;LastAccessTime=$Content.LastAccessTime.InnerText}

            Write-Output $BucketNameLastAccessTime
        }
    }
}

<#
    .SYNOPSIS
    Enable S3 Bucket Last Access Time
    .DESCRIPTION
    Enable S3 Bucket Last Access Time
#>
function Global:Enable-S3BucketLastAccessTime {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
                Mandatory=$False,
                Position=0,
                HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
                Mandatory=$False,
                Position=1,
                HelpMessage="Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
                Mandatory=$False,
                Position=2,
                HelpMessage="Use presigned URL")][Switch]$Presign,
        [parameter(
                Mandatory=$False,
                Position=3,
                HelpMessage="Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
                Mandatory=$False,
                Position=4,
                HelpMessage="AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)")][String][ValidateSet("S3","AWS4")]$SignerType="AWS4",
        [parameter(
                Mandatory=$False,
                Position=5,
                HelpMessage="Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=6,
                HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][Alias("Profile")][String]$ProfileName,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=7,
                HelpMessage="AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=6,
                HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=7,
                HelpMessage="S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
                ParameterSetName="account",
                Mandatory=$False,
                Position=6,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
                Mandatory=$False,
                Position=8,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Region to be used")][String]$Region,
        [parameter(
                Mandatory=$False,
                Position=9,
                HelpMessage="Bucket URL Style (Default: path)")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
                Mandatory=$True,
                Position=10,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Bucket")][Alias("Name","Bucket")][String]$BucketName
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId

        $Method = "PUT"
    }
 
    Process {
        if (!$Region) {
            $Region = $Config.Region
        }

        # Convert Bucket Name to IDN mapping to support Unicode Names
        $BucketName = [System.Globalization.IdnMapping]::new().GetAscii($BucketName)

        $Query = @{"x-ntap-sg-lastaccesstime"="enabled"}

        $AwsRequest = Get-AwsRequest -AccessKey $Config.aws_access_key_id -SecretKey $Config.aws_secret_access_key -Method $Method -EndpointUrl $Config.endpoint_url -Uri $Uri -Query $Query -Bucket $BucketName -Presign:$Presign -SignerType $SignerType -Region $Region

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Result = Invoke-AwsRequest -SkipCertificateCheck:$SkipCertificateCheck -Method $Method -Uri $AwsRequest.Uri -Headers $AwsRequest.Headers -ErrorAction Stop
        }
    }
}

<#
    .SYNOPSIS
    Disable S3 Bucket Last Access Time
    .DESCRIPTION
    Disable S3 Bucket Last Access Time
#>
function Global:Disable-S3BucketLastAccessTime {
    [CmdletBinding(DefaultParameterSetName="none")]

    PARAM (
        [parameter(
                Mandatory=$False,
                Position=0,
                HelpMessage="StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
                Mandatory=$False,
                Position=1,
                HelpMessage="Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
                Mandatory=$False,
                Position=2,
                HelpMessage="Use presigned URL")][Switch]$Presign,
        [parameter(
                Mandatory=$False,
                Position=3,
                HelpMessage="Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
                Mandatory=$False,
                Position=4,
                HelpMessage="AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)")][String][ValidateSet("S3","AWS4")]$SignerType="AWS4",
        [parameter(
                Mandatory=$False,
                Position=5,
                HelpMessage="Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=6,
                HelpMessage="AWS Profile to use which contains AWS sredentials and settings")][Alias("Profile")][String]$ProfileName,
        [parameter(
                ParameterSetName="profile",
                Mandatory=$False,
                Position=7,
                HelpMessage="AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=6,
                HelpMessage="S3 Access Key")][String]$AccessKey,
        [parameter(
                ParameterSetName="keys",
                Mandatory=$False,
                Position=7,
                HelpMessage="S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
                ParameterSetName="account",
                Mandatory=$False,
                Position=6,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
                Mandatory=$False,
                Position=8,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Region to be used")][String]$Region,
        [parameter(
                Mandatory=$False,
                Position=9,
                HelpMessage="Bucket URL Style (Default: path)")][String][ValidateSet("path","virtual-hosted")]$UrlStyle="path",
        [parameter(
                Mandatory=$True,
                Position=10,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Bucket")][Alias("Name","Bucket")][String]$BucketName
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId

        $Method = "PUT"
    }

    Process {
        if (!$Region) {
            $Region = $Config.Region
        }

        # Convert Bucket Name to IDN mapping to support Unicode Names
        $BucketName = [System.Globalization.IdnMapping]::new().GetAscii($BucketName)

        $Query = @{"x-ntap-sg-lastaccesstime"="disabled"}

        $AwsRequest = Get-AwsRequest -AccessKey $Config.aws_access_key_id -SecretKey $Config.aws_secret_access_key -Method $Method -EndpointUrl $Config.endpoint_url -Uri $Uri -Query $Query -Bucket $BucketName -Presign:$Presign -SignerType $SignerType -Region $Region

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Result = Invoke-AwsRequest -SkipCertificateCheck:$SkipCertificateCheck -Method $Method -Uri $AwsRequest.Uri -Headers $AwsRequest.Headers -ErrorAction Stop
        }
    }
}