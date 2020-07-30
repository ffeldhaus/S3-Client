$AWS_PROFILE_PATH = Join-Path -Path $HOME -ChildPath ".aws"
$AWS_CREDENTIALS_FILE = Join-Path -Path $AWS_PROFILE_PATH -ChildPath "credentials"
$DEFAULT_AWS_ENDPOINT = "https://s3.amazonaws.com"
$DEFAULT_TIMEOUT_SECONDS = 60
$MAX_RETRIES = 5
$LOG_LEVELS = @{"CRITICAL"=0;"ERROR"=1;"WARNING"=2;"INFORMATION"=3;"VERBOSE"=4;"DEBUG"=5;"DEFAULT"=-1}
$LOG_COLORS = @{"CRITICAL"=[System.ConsoleColor]::DarkRed;"ERROR"=[System.ConsoleColor]::Red;"WARNING"=[System.ConsoleColor]::Yellow;"INFORMATION"=[System.ConsoleColor]::Green;"VERBOSE"=[System.ConsoleColor]::Blue;"DEBUG"=[System.ConsoleColor]::DarkGray;"DEFAULT"=[System.ConsoleColor]::Gray}

$MIME_TYPES = @{ }
Import-Csv -Delimiter ',' -Path (Join-Path -Path $PSScriptRoot -ChildPath 'mimetypes.txt') -Header 'Extension', 'MimeType' | ForEach-Object { $MIME_TYPES[$_.Extension] = $_.MimeType }

# PowerShell 5 and earlier cannot skip certificate validation per request therefore we need to use a workaround
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
}

# adding HttpCopyClient and PushStreamContent class to provide async copy from GET response to PUT request
Add-Type -Path (Join-Path -Path $PSScriptRoot -ChildPath "HttpCopyClient.cs" ) -ReferencedAssemblies "System.Runtime.Extensions","System.Net.Primitives","System.Net.Http","System.Threading.Tasks","System.Diagnostics.Contracts"

### Helper Functions ###

function ConvertTo-SortedDictionary($HashTable) {
    #private
    $SortedDictionary = New-Object 'System.Collections.Generic.SortedDictionary[string, string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($Key in $HashTable.Keys) {
        $SortedDictionary[$Key] = $HashTable[$Key]
    }
    Write-Output $SortedDictionary
}

function Get-SignedString {
    #private
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $True,
            Position = 0,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Key in Bytes.")][Byte[]]$Key,
        [parameter(Mandatory = $False,
            Position = 1,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Unit of timestamp.")][String]$Message = "",
        [parameter(Mandatory = $False,
            Position = 2,
            HelpMessage = "Algorithm to use for signing.")][ValidateSet("SHA1", "SHA256")][String]$Algorithm = "SHA256"
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

function Sign($Key, $Message) {
    #private
    $hmacsha = New-Object System.Security.Cryptography.HMACSHA256
    $hmacsha.Key = $Key
    $hmacsha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Message))
}

function GetSignatureKey($Key, $Date, $Region, $Service) {
    #private
    $SignedDate = sign ([Text.Encoding]::UTF8.GetBytes(('AWS4' + $Key).ToCharArray())) $Date
    $SignedRegion = sign $SignedDate $Region
    $SignedService = sign $SignedRegion $Service
    sign $SignedService "aws4_request"
}

<#
    .SYNOPSIS
    Convert string to absolute file or directory path
    .DESCRIPTION
    Convert string to absolute file or directory path
    .PARAMETER Path
    Path as string
#>
function ConvertTo-AbsolutePath {
    #private
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory = $True,
            Position = 0,
            HelpMessage = "Path as string")][String]$Path,
        [parameter(
            Mandatory = $False,
            Position = 1,
            HelpMessage = "Base path for relative paths")][String]$BasePath = $PWD
    )

    Process {
        $SlashCount = $Path.Length - $Path.Replace('/','').Length
        $BackslashCount = $Path.Length - $Path.Replace('\','').Length
        if ($SlashCount -gt $BackslashCount) {
            # probably a Posix path
            $Path = $Path.Replace('/',[System.IO.Path]::DirectorySeparatorChar)
        }
        elseif ($BackslashCount -gt $SlashCount) {
            # probably a Windows path
            $Path = $Path.Replace('\',[System.IO.Path]::DirectorySeparatorChar)
        }

        # workaround as .NET before .NET Core does not support GetFullPath with basePath parameter
        if ($PSVersionTable.PSVersion.Major -lt 7) {
            $Path = [System.IO.Path]::GetFullPath($Path)
            $Path = $Path.Replace([System.Environment]::CurrentDirectory,$BasePath)
        }
        else {
            $Path = [System.IO.Path]::GetFullPath($Path,$BasePath)
        }

        Write-Output $Path
    }
}

<#
    .SYNOPSIS
    Convert data from AWS config file to config objects
    .DESCRIPTION
    Convert data from AWS config file to config objects
    .PARAMETER AwsConfigFile
    AWS Config File
#>
function ConvertFrom-AwsConfigFile {
    #private
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory = $True,
            Position = 0,
            HelpMessage = "AWS Config File")][String]$AwsConfigFile
    )

    Process {
        if (!(Test-Path $AwsConfigFile)) {
            throw "Config file $AwsConfigFile does not exist!"
        }

        Write-Log -Level Verbose -Config $Config -Message "Reading AWS Configuration from $AwsConfigFile"

        $Content = Get-Content -Path $AwsConfigFile -Raw
        # convert to JSON structure
        # replace all carriage returns
        $Content = $Content -replace "\r", ""
        # remove empty lines
        $Content = $Content -replace "(\n$)*", ""
        # remove profile string from profile section
        $Content = $Content -replace "profile ", ""

        # replace sections like s3 or iam where the line ends with a = with a JSON object including opening and closing curly brackets
        $Content = $Content -replace "([a-zA-Z0-9]+)\s*=\s*((?:\n  .+)+)", '"$1":{ $2 },'
        $Content = $Content -replace "([a-zA-Z0-9]+)\s*=\s*\n", "`"`$1`":{ },`n"
        $Content = $Content -replace "([a-zA-Z0-9]+)\s*=\s*\z", '"$1":{ },'

        # replace key value pairs with quoted key value pairs and replace = with :
        $Content = $Content -replace "\n\s*([^=^\s^`"]+)\s*=\s*([^\s^\n]*)", "`n`"`$1`":`"`$2`","

        # make sure that Profile is a Key Value inside the JSON Object
        $Content = $Content -replace "\[([^\]]+)\]([^\[]+)", "{`"ProfileName`":`"`$1`",`$2},`n"

        # remove additional , before a closing curly bracket
        $Content = $Content -replace "\s*,\s*\n?}", "}"

        # ensure that the complete output is an array consisting of multiple JSON objects
        $Content = $Content -replace "\A", "["
        $Content = $Content -replace "},?\s*\n?\s*\z", "}]"

        # ensure that backslashes are escaped
        $Content = $Content -replace "\\","\\"

        $Config = ConvertFrom-Json -InputObject $Content
        Write-Output $Config
    }
}

<#
    .SYNOPSIS
    Convert data from config objects to AWS config file
    .DESCRIPTION
    Convert data from config objects to AWS config file
    .PARAMETER Configs
    Configs to store in config file
    .PARAMETER AwsConfigFile
    AWS Config File
#>
function ConvertTo-AwsConfigFile {
    #private
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory = $True,
            Position = 0,
            HelpMessage = "Configs to store in config file")][PSCustomObject]$Configs,
        [parameter(
            Mandatory = $True,
            Position = 1,
            HelpMessage = "AWS Config File")][String]$AwsConfigFile
    )

    Process {
        Write-Log -Level Verbose -Config $Config -Message "Writing AWS Configuration to $AwsConfigFile"

        if (!(Test-Path $AwsConfigFile)) {
            New-Item -Path $AwsConfigFile -ItemType File -Force
        }

        $AwsConfigDirectory = ([System.IO.DirectoryInfo]$AwsConfigFile).Parent.FullName

        # make sure that parent folder is only accessible by current user
        try {
            if ([environment]::OSVersion.Platform -match "win") {
                $Acl = Get-Acl -Path $AwsConfigDirectory
                # remove inheritance
                $Acl.SetAccessRuleProtection($true, $false)
                $AcessRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                    $env:USERNAME, "FullControl",
                    ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
                    [System.Security.AccessControl.PropagationFlags]::None,
                    [System.Security.AccessControl.AccessControlType]::Allow)
                $Acl.AddAccessRule($AcessRule)
                Set-Acl -Path $AwsConfigDirectory -AclObject $Acl -ErrorAction Stop
            }
            else {
                Invoke-Expression "chmod 700 $AwsConfigDirectory"
                Invoke-Expression "chmod 600 $AwsConfigFile"
            }
        }
        catch {
            Write-Log -Level Verbose -Config $Config -Message "Couldn't restrict access to directory $AwsConfigDirectory"
        }

        if ($AwsConfigFile -match "credentials$") {
            foreach ($Config in $Configs) {
                $Output += "[$( $Config.ProfileName )]`n"
                $Output += "aws_access_key_id = $($Config.aws_access_key_id)`n"
                $Output += "aws_secret_access_key = $($Config.aws_secret_access_key)`n"
            }
        }
        else {
            foreach ($Config in $Configs) {
                if ($Config.ProfileName -eq "default") {
                    $Output += "[$( $Config.ProfileName )]`n"
                }
                else {
                    $Output += "[profile $( $Config.ProfileName )]`n"
                }
                $Properties = $Config.PSObject.Members | Where-Object { $_.MemberType -eq "NoteProperty" -and $_.Name -ne "ProfileName" -and $_.Value -isnot [PSCustomObject] }
                $Sections = $Config.PSObject.Members | Where-Object { $_.MemberType -eq "NoteProperty" -and $_.Name -ne "ProfileName" -and $_.Value -is [PSCustomObject] }
                foreach ($Property in $Properties) {
                    $Output += "$($Property.Name) = $($Property.Value)`n"
                }
                foreach ($Section in $Sections) {
                    $Properties = $Section.Value.PSObject.Members | Where-Object { $_.MemberType -eq "NoteProperty" }
                    if ($Properties) {
                        $Output += "$($Section.Name) =`n"
                    }
                    foreach ($Property in $Properties) {
                        $Output += "  $($Property.Name) = $($Property.Value)`n"
                    }
                }
            }
        }
        $LogOutput = $Output -replace "aws_secret_access_key = (.*)\n","aws_secret_access_key = ***`n"
        Write-Log -Level Debug -Config $Config -Message "Content to be written to $($AwsConfigFile):`n$LogOutput"

        if ([environment]::OSVersion.Platform -match "win") {
            # replace LF with CRLF
            $Output = $Output -replace "`n", "`r`n"
            $Output | Out-File -FilePath $AwsConfigFile
        }
        else {
            $Output | Out-File -FilePath $AwsConfigFile -NoNewline
        }
    }
}

<#
    .SYNOPSIS
    Convert DateTime object to unix timestamp either in seconds or milliseconds
    .DESCRIPTION
    Convert DateTime object to unix timestamp either in seconds or milliseconds
    .PARAMETER Date
    Date to be converted.
    .PARAMETER Unit
    Unit of timestamp, either milliseconds (default) or seconds.
#>
function ConvertTo-UnixTimestamp {
    #private
    [CmdletBinding()]

    #private

    PARAM (
        [parameter(Mandatory = $True,
            Position = 0,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Date to be converted.")][DateTime[]]$Date,
        [parameter(Mandatory = $False,
            Position = 1,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Unit of timestamp, either milliseconds (default) or seconds.")][ValidateSet("Seconds", "Milliseconds")][String]$Unit = "Milliseconds"
    )

    BEGIN {
        $epoch = Get-Date -Year 1970 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0
    }

    PROCESS {
        if ($Unit = "Seconds") {
            Write-Output ([math]::truncate($Date.ToUniversalTime().Subtract($epoch).TotalSeconds))
        }
        else {
            Write-Output ([math]::truncate($Date.ToUniversalTime().Subtract($epoch).TotalMilliSeconds))
        }
    }
}

<#
    .SYNOPSIS
    Convert bucket name with non DNS conform characters to Punycode
    .DESCRIPTION
    Convert bucket name with non DNS conform characters to Punycode
    .PARAMETER BucketName
    Bucket name to convert to punycode
    .PARAMETER SkipTest
    Skip test if non DNS conform bucket exist
    .PARAMETER Config
    AWS Config
 #>
function ConvertTo-Punycode {
    #private
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket name to convert to punycode")][Alias("Bucket")][String]$BucketName,
        [parameter(Mandatory = $False,
            Position = 1,
            HelpMessage = "Skip test if non DNS conform bucket exist")][Switch]$SkipTest,
        [parameter(Mandatory = $False,
            Position = 2,
            HelpMessage = "AWS Config")][PSCustomObject]$Config
    )

    PROCESS {
        if ($BucketName) {
            # Convert Bucket Name to IDN mapping to support Unicode Names
            $IdnMapping = New-Object -TypeName "System.Globalization.IdnMapping"
            $PunycodeBucketName = $IdnMapping.GetAscii($BucketName).ToLower()
        }
        else {
            $PunycodeBucketName = ""
        }
        # check if BucketName contains uppercase letters
        if ($PunycodeBucketName -match $BucketName -and $PunycodeBucketName -cnotmatch $BucketName) {
            if ($SkipTest.IsPresent -or !$Config) {
                Write-Log -Level Warning -Config $Config -Message "BucketName $BucketName includes uppercase letters which MUST NOT be used. Converting BucketName to lowercase $PunycodeBucketName. AWS S3 and StorageGRID since version 11.1 do not support Buckets with uppercase letters!"
                Write-Output $PunycodeBucketName
            }
            else {
                $Config = $Config.PSObject.Copy()
                $Config.AddressingStyle = "path"
                $BucketNameExists = Test-S3Bucket -Config $Config -Bucket $BucketName -Force
                if ($BucketNameExists) {
                    Write-Log -Level Warning -Config $Config -Message "BucketName $BucketName includes uppercase letters which SHOULD NOT be used!"
                    Write-Output $BucketName
                }
                else {
                    Write-Output $PunycodeBucketName
                }
            }
        }
        else {
            Write-Output $PunycodeBucketName
        }
    }
}

<#
    .SYNOPSIS
    Convert Punycode encoded bucket name to unicode bucket name
    .DESCRIPTION
    Convert Punycode encoded bucket name to unicode bucket name
    .PARAMETER BucketName
    Bucket name to convert from punycode
 #>
function ConvertFrom-Punycode {
    #private
    [CmdletBinding()]

    PARAM (
        [parameter(Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket name to convert to punycode")][Alias("Bucket")][String]$BucketName
    )

    PROCESS {
        if ($BucketName) {
            # Convert Bucket Name to IDN mapping to support Unicode Names
            $IdnMapping = New-Object -TypeName "System.Globalization.IdnMapping"
            $UnicodeBucketName = $IdnMapping.GetUnicode($BucketName)
            Write-Output $UnicodeBucketName
        }
        else {
            Write-Output ""
        }
    }
}

<#
    .SYNOPSIS
    Write log
    .DESCRIPTION
    Write log
    .PARAMETER Level
    Log level
    .PARAMETER Config
    AWS Config
    .PARAMETER Message
    Log message
    .PARAMETER ErrorRecord
    Error record
 #>
 function Write-Log {
    #private
    [CmdletBinding(DefaultParameterSetName="Message")]

    PARAM (
        [parameter(Mandatory = $True,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Log Level")][String][ValidateSet("CRITICAL","ERROR","WARNING","INFORMATION","VERBOSE","DEBUG","DEFAULT")]$Level,
        [parameter(Mandatory = $False,
            Position = 1,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS Config")][PSCustomObject]$Config,
        [parameter(Mandatory = $True,
            ParameterSetName = "Message",
            Position = 2,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Log message")][PSCustomObject]$Message,
        [parameter(Mandatory = $True,
            ParameterSetName = "ErrorRecord",
            Position = 3,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Error record")][System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    PROCESS {
        $PSCallStack = Get-PSCallStack
        $Invocation = $PSCallStack[1]
        $InvocationFunctionName = $Invocation.FunctionName -replace "Global:","" -replace "<[^>]*>",""
        $InvocationScriptName = $Invocation.ScriptName
        $InvocationScriptLineNumber = $Invocation.ScriptLineNumber
        $DateTime = Get-Date -Format o

        if ($Config.LogLevel -and $Config.LogLevel -ne "DEFAULT") {
            $MaxLogLevel = $Config.LogLevel
        }
        else {
            $MaxLogLevel = "INFORMATION"
        }

        if ($Message) {
            $Message = "$DateTime $($Level.ToUpper().PadRight(7," ")) $InvocationFunctionName $($InvocationScriptName):$InvocationScriptLineNumber $Message"
        }
        if ($ErrorRecord) {
            $Message = "$DateTime $($Level.ToUpper().PadRight(7," ")) $($ErrorRecord.InvocationInfo.MyCommand) $($ErrorRecord.InvocationInfo.ScriptName):$($($ErrorRecord.InvocationInfo.ScriptLineNumber)) $($ErrorRecord.Exception.Message)"
        }

        if ($Config.LogPath -and $LOG_LEVELS[$Level] -le $LOG_LEVELS[$MaxLogLevel]) {
            $LogPath = ConvertTo-AbsolutePath -Path $Config.LogPath
            if (Test-Path -Path $LogPath -PathType Container) {
                $FileName = "$(Get-Date -Format FileDate)-$($Config.ProfileName).log"
                $LogFile = Join-Path -Path $LogPath -ChildPath $FileName
                $Message | Out-File -Append -FilePath $LogFile
            }
            elseif (Test-Path -Path $LogPath.Parent -PathType Container) {
                $Message | Out-File -Append -FilePath $LogPath
            }
            else {
                Write-Warning "Cannot write to log path $LogPath as the directory does not exists"
            }
        }

        switch ($Level) {
            "ERROR" { Write-Error $Message }
            "WARNING" { Write-Warning $Message }
            "INFORMATION" { Write-Host $Message }
            "VERBOSE" { Write-Verbose $Message }
            "DEBUG" { Write-Debug $Message }
        }
    }
}

<#
    .SYNOPSIS
    Read log file
    .DESCRIPTION
    Read log file
    .PARAMETER Config
    AWS Config
    .PARAMETER Path
    Path to log file
 #>
 function Read-LogFile {
    #private
    [CmdletBinding(DefaultParameterSetName="Config")]

    PARAM (
        [parameter(
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS Profile to use which contains AWS sredentials and settings")][Alias("Profile")][String]$ProfileName = "default",
        [parameter(Mandatory = $False,
            ParameterSetName="Config",
            Position = 1,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS Config")][PSCustomObject]$Config,
        [parameter(Mandatory = $True,
            ParameterSetName="Path",
            Position = 2,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Path to log file")][String]$Path
    )

    BEGIN {
        if (!$Config) {
            $Config = Get-AwsConfig -ProfileName $ProfileName -LogPath $Path
        }
        if (!$Config.LogPath) {
            throw "Logging not enabled for profile $($Config.ProfileName)"
        }
    }

    PROCESS {
        if (Test-Path -Path $Config.LogPath -PathType Container) {
            $FileName = "$(Get-Date -Format FileDate)-$($Config.ProfileName).log"
            $LogFile = [System.IO.FileInfo](Join-Path -Path $Config.LogPath -ChildPath $FileName)
        }
        elseif (Test-Path -Path $Config.LogPath -PathType Leaf) {
            $LogFile = [System.IO.FileInfo]$Config.LogPath.FullName
        }

        if ($LogFile.Exists) {
            $ConsoleColors = [System.ConsoleColor].GetEnumValues()
            $LogColor = [ConsoleColor]"Gray"
            Get-Content -Path $LogFile | foreach {
                $Level = $_.split(' ') | Select-Object -First 1 -Skip 1
                if ($Level -and $ConsoleColors.Contains($LOG_COLORS[$Level])) {
                    $LogColor = $LOG_COLORS[$Level]
                }
                Write-Host -ForegroundColor $LogColor -Message $_
            }
        }
        else {
            Write-Log -Level Warning -Message "Log file $LogFile does not exist"
        }
    }
}

### AWS Cmdlets ###

<#
    .SYNOPSIS
    Retrieve SHA256 Hash for Payload
    .DESCRIPTION
    Retrieve SHA256 Hash for Payload
    .PARAMETER StringToHash
    String to hash
    .PARAMETER FileToHash
    File to hash
    .PARAMETER StreamToHash
    Stream to hash
#>
function Global:Get-AwsHash {
    #private
    [CmdletBinding(DefaultParameterSetName = "string")]

    PARAM (
        [parameter(
            Mandatory = $False,
            Position = 0,
            ParameterSetName = "string",
            HelpMessage = "String to hash")][String]$StringToHash = "",
        [parameter(
            Mandatory = $True,
            Position = 1,
            ParameterSetName = "file",
            HelpMessage = "File to hash")][System.IO.FileInfo]$FileToHash,
        [parameter(
            Mandatory = $True,
            Position = 2,
            ParameterSetName = "stream",
            HelpMessage = "Stream to hash")][System.IO.Stream]$StreamToHash
    )

    Process {
        $Hasher = [System.Security.Cryptography.SHA256]::Create()

        if ($FileToHash) {
            $Hash = Get-FileHash -Algorithm SHA256 -Path $FileToHash | Select-Object -ExpandProperty Hash
        }
        elseif ($StreamToHash) {
            $Hash = ([BitConverter]::ToString($Hasher.ComputeHash($StreamToHash)) -replace '-','').ToLower()
            $null = $StreamToHash.Seek(0, [System.IO.SeekOrigin]::Begin)
        }
        else {
            $Hash = ([BitConverter]::ToString($Hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($StringToHash))) -replace '-', '').ToLower()
        }

        Write-Output $Hash
    }
}

<#
    .SYNOPSIS
    Create AWS Authentication Signature Version 2 for Request
    .DESCRIPTION
    Create AWS Authentication Signature Version 2 for Request
    .PARAMETER AccessKey
    S3 Access Key
    .PARAMETER SecretKey
    S3 Secret Access Key
    .PARAMETER EndpointUrl
    Endpoint hostname and optional port
    .PARAMETER Method
    HTTP Request Method
    .PARAMETER Uri
    URI
    .PARAMETER ContentMD5
    Content MD5
    .PARAMETER ContentType
    Content Type
    .PARAMETER DateTime
    Date
    .PARAMETER Headers
    HTTP Headers
    .PARAMETER BucketName
    Bucket name
    .PARAMETER QueryString
    Query String (unencoded)
#>
function Global:New-AwsSignatureV2 {
    #private
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory = $True,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            Mandatory = $True,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            Mandatory = $True,
            Position = 2,
            HelpMessage = "Endpoint hostname and optional port")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "HTTP Request Method")][ValidateSet("OPTIONS", "GET", "HEAD", "PUT", "POST", "DELETE", "TRACE", "CONNECT")][String]$Method = "GET",
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "URI")][String]$Uri = "/",
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Content MD5")][String]$ContentMD5 = "",
        [parameter(
            Mandatory = $False,
            Position = 7,
            HelpMessage = "Content Type")][String]$ContentType = "",
        [parameter(
            Mandatory = $False,
            Position = 8,
            HelpMessage = "Date")][String]$DateTime,
        [parameter(
            Mandatory = $False,
            Position = 9,
            HelpMessage = "HTTP Headers")][Hashtable]$Headers = @{ },
        [parameter(
            Mandatory=$False,
            Position=10,
            HelpMessage="Bucket name")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 11,
            HelpMessage = "Query String (unencoded)")][String]$QueryString
    )

    Process {
        Write-Log -Level Verbose -Config $Config -Message "Create AWS Authentication Signature Version 2 for AWS Request"

        # this Cmdlet follows the steps outlined in https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html

        # date initialization in required format
        if (!$DateTime) {
            $DateTime = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")
        }

        Write-Log -Level Debug -Config $Config -Message "Task 1: Constructing the CanonicalizedResource Element"

        $CanonicalizedResource = ""
        Write-Log -Level Debug -Config $Config -Message "Task 1 Step 1: Start with an empty string:`n$CanonicalizedResource"

        if ($BucketName -and $EndpointUrl.Host -match "^$BucketName") {
            $CanonicalizedResource += "/$BucketName"
            Write-Log -Level Debug -Config $Config -Message "Task 1 Step 2: Add the bucket name for virtual host style:`n$CanonicalizedResource"
        }
        else {
            Write-Log -Level Debug -Config $Config -Message "Task 1 Step 2: bucket name already part of Url for path style therefore skipping this step"
        }

        $CanonicalURI = [System.UriBuilder]::new($Uri).Path
        $CanonicalizedResource += $CanonicalURI
        Write-Log -Level Debug -Config $Config -Message "Task 1 Step 3: Append the path part of the un-decoded HTTP Request-URI, up-to but not including the query string:`n$CanonicalizedResource"

        if ($QueryString) {
            $CanonicalizedResource += "?$QueryString"
        }
        Write-Log -Level Debug -Config $Config -Message "Task 1 Step 4: Append the query string unencoded for signing:`n$CanonicalizedResource"

        Write-Log -Level Debug -Config $Config -Message "Task 2: Constructing the CanonicalizedAmzHeaders Element"

        Write-Log -Level Debug -Config $Config -Message "Task 2 Step 1: Filter for all headers starting with x-amz and are not x-amz-date"
        $AmzHeaders = $Headers.Clone()
        # remove all headers which do not start with x-amz
        $Headers.Keys | ForEach-Object { if ($_ -notmatch "x-amz" -or $_ -eq "x-amz-date") { $AmzHeaders.Remove($_) } }

        Write-Log -Level Debug -Config $Config -Message "Task 2 Step 2: Sort headers lexicographically"
        $SortedAmzHeaders = ConvertTo-SortedDictionary $AmzHeaders

        $CanonicalizedAmzHeaders = ($SortedAmzHeaders.GetEnumerator() | ForEach-Object { "$($_.Key.ToLower()):$($_.Value)" }) -join "`n"
        if ($CanonicalizedAmzHeaders) {
            $CanonicalizedAmzHeaders = $CanonicalizedAmzHeaders + "`n"
        }
        Write-Log -Level Debug -Config $Config -Message "Task 2 Step 3: CanonicalizedAmzHeaders headers:`n$CanonicalizedAmzHeaders"

        Write-Log -Level Debug -Config $Config -Message "Task 3: String to sign"

        $StringToSign = "$Method`n$ContentMD5`n$ContentType`n$DateTime`n$CanonicalizedAmzHeaders$CanonicalizedResource"
        Write-Log -Level Debug -Config $Config -Message "Task 3 Step 1: StringToSign:`n$StringToSign"

        Write-Log -Level Debug -Config $Config -Message "Task 4: Signature"

        $SignedString = Get-SignedString -Key ([Text.Encoding]::UTF8.GetBytes($SecretKey)) -Message $StringToSign -Algorithm SHA1
        $Signature = [Convert]::ToBase64String($SignedString)
        Write-Log -Level Debug -Config $Config -Message "Task 4 Step 1: Signature:`n$Signature"

        Write-Output $Signature
    }
}

<#
    .SYNOPSIS
    Create AWS Authentication Signature Version 4 for Request
    .DESCRIPTION
    Create AWS Authentication Signature Version 4 for Request
    .PARAMETER AccessKey
    S3 Access Key
    .PARAMETER SecretKey
    S3 Secret Access Key
    .PARAMETER EndpointUrl
    Endpoint hostname and optional port
    .PARAMETER Method
    HTTP Request Method
    .PARAMETER Uri
    URI
    .PARAMETER CanonicalQueryString
    Canonical query string
    .PARAMETER DateTime
    Date Time (yyyyMMddTHHmmssZ)
    .PARAMETER DateString
    Date String (yyyyMMdd)
    .PARAMETER RequestPayloadHash
    Request payload hash
    .PARAMETER Region
    Region
    .PARAMETER Service
    Service
    .PARAMETER Headers
    HTTP Headers
    .PARAMETER ContentType
    Content Type
#>
function Global:New-AwsSignatureV4 {
    #private
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory = $True,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            Mandatory = $True,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            Mandatory = $True,
            Position = 2,
            HelpMessage = "Endpoint hostname and optional port")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "HTTP Request Method")][ValidateSet("OPTIONS", "GET", "HEAD", "PUT", "POST", "DELETE", "TRACE", "CONNECT")][String]$Method = "GET",
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "URI")][String]$Uri = "/",
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Canonical Query String")][String]$CanonicalQueryString,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Date Time (yyyyMMddTHHmmssZ)")][String]$DateTime,
        [parameter(
            Mandatory = $False,
            Position = 7,
            HelpMessage = "Date String (yyyyMMdd)")][String]$DateString,
        [parameter(
            Mandatory = $False,
            Position = 8,
            HelpMessage = "Request payload hash")][String]$RequestPayloadHash,
        [parameter(
            Mandatory = $False,
            Position = 9,
            HelpMessage = "Region")][String]$Region = "us-east-1",
        [parameter(
            Mandatory = $False,
            Position = 10,
            HelpMessage = "Region")][String]$Service = "s3",
        [parameter(
            Mandatory = $False,
            Position = 11,
            HelpMessage = "HTTP Headers")][Hashtable]$Headers = @{ },
        [parameter(
            Mandatory = $False,
            Position = 12,
            HelpMessage = "Content type")][String]$ContentType
    )

    Process {
        Write-Log -Level Verbose -Config $Config -Message "Create AWS Authentication Signature Version 4 for AWS Request"

        # this Cmdlet follows the steps outlined in http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html

        # date initialization in required format
        if (!$DateTime) {
            $DateTime = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")
        }
        if (!$DateString) {
            $DateString = [DateTime]::UtcNow.ToString('yyyyMMdd')
        }

        Write-Log -Level Debug -Config $Config -Message "Task 1: Create a Canonical Request for Signature Version 4"
        # http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

        Write-Log -Level Debug -Config $Config -Message "1. HTTP Request Method:`n$Method"

        # get the properly encoded relative URI
        $CanonicalURI = ([System.UriBuilder]"$EndpointUrl$($Uri -replace '^/','')").Uri.PathAndQuery
        Write-Log -Level Debug -Config $Config -Message "2. Canonical URI:`n$CanonicalURI"

        Write-Log -Level Debug -Config $Config -Message "3. Canonical query string:`n$CanonicalQueryString"

        $SortedHeaders = ConvertTo-SortedDictionary $Headers
        $CanonicalHeaders = (($SortedHeaders.GetEnumerator() | ForEach-Object { "$($_.Key.ToLower()):$($_.Value)" }) -join "`n") + "`n"
        Write-Log -Level Debug -Config $Config -Message "4. Canonical headers:`n$CanonicalHeaders"

        $SignedHeaders = $SortedHeaders.Keys.ToLower() -join ";"
        Write-Log -Level Debug -Config $Config -Message "5. Signed headers:`n$SignedHeaders"

        Write-Log -Level Debug -Config $Config -Message "6. Hashed Payload`n$RequestPayloadHash"

        $CanonicalRequest = "$Method`n$CanonicalURI`n$CanonicalQueryString`n$CanonicalHeaders`n$SignedHeaders`n$RequestPayloadHash"
        Write-Log -Level Debug -Config $Config -Message "7. CanonicalRequest:`n$CanonicalRequest"

        $hasher = [System.Security.Cryptography.SHA256]::Create()
        $CanonicalRequestHash = ([BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($CanonicalRequest))) -replace '-', '').ToLower()
        Write-Log -Level Debug -Config $Config -Message "8. Canonical request hash:`n$CanonicalRequestHash"

        Write-Log -Level Debug -Config $Config -Message "Task 2: Create a String to Sign for Signature Version 4"
        # http://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html

        $AlgorithmDesignation = "AWS4-HMAC-SHA256"
        Write-Log -Level Debug -Config $Config -Message "1. Algorithm designation:`n$AlgorithmDesignation"

        Write-Log -Level Debug -Config $Config -Message "2. request date value, specified with ISO8601 basic format in the format YYYYMMDD'T'HHMMSS'Z:`n$DateTime"

        $CredentialScope = "$DateString/$Region/$Service/aws4_request"
        Write-Log -Level Debug -Config $Config -Message "3. Credential scope:`n$CredentialScope"

        Write-Log -Level Debug -Config $Config -Message "4. Canonical request hash:`n$CanonicalRequestHash"

        $StringToSign = "$AlgorithmDesignation`n$DateTime`n$CredentialScope`n$CanonicalRequestHash"
        Write-Log -Level Debug -Config $Config -Message "StringToSign:`n$StringToSign"

        Write-Log -Level Debug -Config $Config -Message "Task 3: Calculate the Signature for AWS Signature Version 4"
        # http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html

        $SigningKey = GetSignatureKey $SecretKey $DateString $Region $Service
        Write-Log -Level Debug -Config $Config -Message "1. Signing Key:`n$([System.BitConverter]::ToString($SigningKey))"

        $Signature = ([BitConverter]::ToString((sign $SigningKey $StringToSign)) -replace '-', '').ToLower()
        Write-Log -Level Debug -Config $Config -Message "2. Signature:`n$Signature"

        Write-Output $Signature
    }
}

<#
    .SYNOPSIS
    Get AWS Request
    .DESCRIPTION
    Get AWS Request
    .PARAMETER Config
    AWS Config
    .PARAMETER Method
    HTTP Request Method
    .PARAMETER Uri
    URI (e.g. / or /key)
    .PARAMETER Query
    Query
    .PARAMETER Service
    Service (e.g. S3)
    .PARAMETER Headers
    HTTP Headers
    .PARAMETER BucketName
    Bucket name
    .PARAMETER Date
    Date
    .PARAMETER RequestPayload
    Request payload
    .PARAMETER InFile
    File to read data from
    .PARAMETER InStream
    IO Stream to read data from
    .PARAMETER Presign
    Presign URL
    .PARAMETER Expires
    Presign URL Expiration Date
#>
function Global:Get-AwsRequest {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 1,
            HelpMessage = "HTTP Request Method")][ValidateSet("OPTIONS", "GET", "HEAD", "PUT", "POST", "DELETE", "TRACE", "CONNECT")][String]$Method = "GET",
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "URI (e.g. / or /key)")][String]$Uri = "/",
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Query")][Hashtable]$Query = @{ },
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Service (e.g. S3)")][String]$Service = "s3",
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "HTTP Headers")][Hashtable]$Headers = @{ },
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Bucket name")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 7,
            HelpMessage = "Date")][DateTime]$Date = [DateTime]::Now,
        [parameter(
            Mandatory = $False,
            Position = 8,
            HelpMessage = "Request payload")][String]$RequestPayload = "",
        [parameter(
            Mandatory = $False,
            Position = 9,
            HelpMessage = "File to read data from")][System.IO.FileInfo]$InFile,
        [parameter(
            Mandatory = $False,
            Position = 10,
            HelpMessage = "IO Stream to read data from")][System.IO.Stream]$InStream,
        [parameter(
            Mandatory = $False,
            Position = 11,
            HelpMessage = "Presign URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 12,
            HelpMessage = "Presign URL Expiration Date")][DateTime]$Expires = (Get-Date).AddHours(1)
    )

    Begin {
        Write-Log -Level Verbose -Config $Config -Message "Get AWS Request"

        # convert relative paths to absolute paths for InFile
        if ($InFile) {
            $InFile = ConvertTo-AbsolutePath -Path $InFile
        }

        # if no config object is suplied, use default config
        if (!$Config) {
            $Config = Get-AwsConfig
            if (!$Config) {
                throw "No config supplied and no default config available"
            }
        }

        # as we are modifying the endpoint URL, make sure to work on a new object and not modify the original object
        $Config = $Config.PSObject.Copy()
        $Config.EndpointUrl = [System.UriBuilder]$Config.EndpointUrl.ToString()
        if (!$Config.EndpointUrl -or $Config.EndpointUrl -match "amazonaws.com") {
            if ($Config.Region -eq "us-east-1" -or !$Config.Region) {
                if ($Config.UseDualstackEndpoint) {
                    $Config.EndpointUrl.Host = "s3.dualstack.amazonaws.com"
                }
                else {
                    $Config.EndpointUrl.Host = "s3.amazonaws.com"
                }
            }
            else {
                if ($Config.UseDualstackEndpoint) {
                    $Config.EndpointUrl.Host = "s3.dualstack.$($Config.Region).amazonaws.com"
                }
                else {
                    $Config.EndpointUrl.Host = "s3.$($Config.Region).amazonaws.com"
                }
            }
        }
        Write-Log -Level Debug -Config $Config -Message "Modified endpoint URL based on options: $($Config.EndpointUrl)"

        Write-Log -Level Debug -Config $Config -Message "Ensure that plus sign (+), exclamation mark (!), asterisk (*) and brackets (()) are encoded in URI, otherwise AWS signing will not work"
        $Uri = $Uri -replace '\+', '%2B' -replace '!', '%21' -replace '\*', '%2A' -replace '\(', '%28' -replace '\)', '%29'
        Write-Log -Level Debug -Config $Config -Message "Encoded URI: $Uri"

        if (($Config.AddressingStyle -match "virtual" -and $BucketName) -or ($Config.AddressingStyle -eq "auto" -and $Config.EndpointUrl -match "amazonaws.com" -and $BucketName)) {
            $Config.EndpointUrl.Host = $BucketName + '.' + $Config.EndpointUrl.Host
            Write-Log -Level Debug -Config $Config -Message "Using virtual-hosted style URL $($Config.EndpointUrl)"
        }
        elseif ($BucketName) {
            Write-Log -Level Debug -Config $Config -Message "Using path style URL $($Config.EndpointUrl)"
            $Uri = "/$BucketName" + $Uri
        }
    }

    Process {
        # convert date to expected format
        $DateTime = $Date.ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
        $DateString = $Date.ToUniversalTime().ToString('yyyyMMdd')

        # AWS expects a request payload hash for signer type AWS4 when changing an object (e.g. HTTP methods PUT, POST, DELETE) and also for unsecure connections via http instead of https
        if ($Method -match 'PUT|POST|DELETE' -and $Config.SignerType -eq "AWS4" -and ($Config.PayloadSigning -eq "true" -or ($Config.PayloadSigning -eq "auto" -and $Config.EndpointUrl -match "http://"))) {
            if ($InFile.Exists) {
                $RequestPayloadHash = Get-AwsHash -FileToHash $InFile
            }
            elseif ($InStream) {
                $RequestPayloadHash = Get-AwsHash -StreamToHash $InStream
            }
            else {
                $RequestPayloadHash = Get-AwsHash -StringToHash $RequestPayload
            }
        }
        else {
            $RequestPayloadHash = 'UNSIGNED-PAYLOAD'
        }
        Write-Log -Level Debug -Config $Config -Message "RequestPayloadHash: $RequestPayloadHash"

        # AWS expects the ContentMD5 header when changing an object (e.g. HTTP methods PUT, POST, DELETE) via an insecure connection
        # the payload MD5 sum is also used in creating a unique ID when recording the response
        if ($Method -match 'PUT|POST|DELETE' -and ($InFile -or $InStream -or $RequestPayload) -and ($Config.PayloadSigning -eq "true" -or ($Config.PayloadSigning -eq "auto" -and $Config.EndpointUrl -match "http://")) -or $Config.RecordMode) {
            $MD5CryptoServiceProvider = [System.Security.Cryptography.MD5CryptoServiceProvider]::new()
            if ($InFile.Exists) {
                $InStream = [System.IO.FileStream]::new($InFile, [System.IO.FileMode]::Open)
                $Md5 = $MD5CryptoServiceProvider.ComputeHash($InStream)
                $null = $Stream.Close
            }
            elseif ($InStream) {
                $Md5 = $MD5CryptoServiceProvider.ComputeHash($InStream)
                $InStream.Seek(0, [System.IO.SeekOrigin]::Begin)
            }
            else {
                $Md5 = $Md5 = $MD5CryptoServiceProvider.ComputeHash([System.Text.UTF8Encoding]::new().GetBytes($RequestPayload))
            }
            $ContentMd5 = [Convert]::ToBase64String($Md5)
        }
        else {
            $ContentMd5 = $null
        }

        if (!$Headers["host"]) { $Headers["host"] = $Config.EndpointUrl.Uri.Authority }

        # for requests which are not presigned, AWS requires few headers
        if (!$Presign.IsPresent) {
            if ($Config.SignerType -eq "AWS4") {
                if (!$Headers["x-amz-date"]) { $Headers["x-amz-date"] = $DateTime }
                if (!$Headers["x-amz-content-sha256"]) { $Headers["x-amz-content-sha256"] = $RequestPayloadHash }
            }
            else {
                if (!$Headers["date"]) { $Headers["date"] = $Date.ToUniversalTime().ToString("r") }
            }
            if (!$Headers["content-type"] -and $ContentType) { $Headers["content-type"] = $ContentType }
            if (!$Headers["content-md5"] -and $ContentMd5 -and !$Config.RecordMode ) { $Headers["content-md5"] = $ContentMd5 }
        }

        $SortedHeaders = ConvertTo-SortedDictionary $Headers
        $SignedHeaders = $SortedHeaders.Keys.ToLower() -join ";"

        # if a request should be presigned, then the query parameter needs to be constructed in a specific way depending on signer type AWS4 or S3
        if ($Presign.IsPresent) {
            if ($Config.SignerType -eq "AWS4") {
                $RequestPayloadHash = "UNSIGNED-PAYLOAD"
                $ExpiresInSeconds = [Math]::Ceiling(($Expires - $Date).TotalSeconds)
                $CredentialScope = "$DateString/$($Config.Region)/$Service/aws4_request"
                $Query["Action"] = $Method
                $Query["X-Amz-Algorithm"] = "AWS4-HMAC-SHA256"
                $Query["X-Amz-Credential"] = "$($Config.AccessKey)/$($CredentialScope)"
                $Query["X-Amz-Date"] = $DateTime
                $Query["X-Amz-Expires"] = $ExpiresInSeconds
                $Query["X-Amz-SignedHeaders"] = $SignedHeaders
            }
            else {
                $ExpiresUnixTime = $Expires | ConvertTo-UnixTimestamp -Unit Seconds
                $Query["Expires"] = $ExpiresUnixTime
                $Query["AWSAccessKeyId"] = $Config.AccessKey
                $DateTime = $ExpiresUnixTime
            }
        }

        $QueryString = ""
        $CanonicalQueryString = ""
        if ($Query.Keys.Count -ge 1) {
            # using Sorted Dictionary as query need to be sorted by encoded keys
            $SortedQuery = New-Object 'System.Collections.Generic.SortedDictionary[string, string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)

            foreach ($Key in $Query.Keys) {
                # Key and value need to be URL encoded separately
                $SortedQuery[$Key] = $Query[$Key]
            }
            # AWS V2 only requires specific queries to be included in signing process
            # and AWS V4 requires these queries to come after all other queries
            $SpecialQueryStrings = "partNumber|uploadId|versioning|location|acl|torrent|lifecycle|versionid|response-content-type|response-content-language|response-expires|response-cache-control|response-content-disposition|response-content-encoding"
            foreach ($Key in ($SortedQuery.Keys | Where-Object { $_ -notmatch $SpecialQueryStrings })) {
                # AWS expects that spaces be encoded as %20 instead of as + and .NET has a different view on this, therefore we need to do it manually
                $Value = [System.Net.WebUtility]::UrlEncode($SortedQuery[$Key]) -replace '\+', '%20' -replace '!', '%21' -replace '\*', '%2A' -replace '\(', '%28' -replace '\)', '%29'
                $CanonicalQueryString += "$([System.Net.WebUtility]::UrlEncode($Key))=$($Value)&"
            }
            foreach ($Key in ($SortedQuery.Keys | Where-Object { $_ -match $SpecialQueryStrings })) {
                if ($SortedQuery[$Key]) {
                    $QueryString += "$Key=$($SortedQuery[$Key])&"
                }
                else {
                    $QueryString += "$Key&"
                }
                # AWS expects that spaces be encoded as %20 instead of as + and .NET has a different view on this, therefore we need to do it manually
                $Value = [System.Net.WebUtility]::UrlEncode($SortedQuery[$Key]) -replace '\+', '%20' -replace '!', '%21' -replace '\*', '%2A' -replace '\(', '%28' -replace '\)', '%29'
                $CanonicalQueryString += "$([System.Net.WebUtility]::UrlEncode($Key))=$($Value)&"
            }
            $QueryString = $QueryString -replace "&`$", ""
            $CanonicalQueryString = $CanonicalQueryString -replace "&`$", ""
        }
        Write-Log -Level Debug -Config $Config -Message "Query String with selected Query components for S3 Signer: $QueryString"
        Write-Log -Level Debug -Config $Config -Message "Canonical Query String with all Query components for AWS Signer: $CanonicalQueryString"

        if ($Config.SignerType -eq "AWS4") {
            Write-Log -Level Debug -Config $Config -Message "Using AWS Signature Version 4"
            $Signature = New-AwsSignatureV4 -AccessKey $Config.AccessKey -SecretKey $Config.SecretKey -EndpointUrl $Config.EndpointUrl -Region $Config.Region -Uri $Uri -CanonicalQueryString $CanonicalQueryString -Method $Method -RequestPayloadHash $RequestPayloadHash -DateTime $DateTime -DateString $DateString -Headers $Headers
            Write-Log -Level Debug -Config $Config -Message "Task 4: Add the Signing Information to the Request"
            # http://docs.aws.amazon.com/general/latest/gr/sigv4-add-signature-to-request.html
            if (!$Presign.IsPresent) {
                $Headers["Authorization"] = "AWS4-HMAC-SHA256 Credential=$($Config.AccessKey)/$DateString/$($Config.Region)/$Service/aws4_request,SignedHeaders=$SignedHeaders,Signature=$Signature"
            }
        }
        else {
            Write-Log -Level Debug -Config $Config -Message "Using AWS Signature Version 2"
            $Signature = New-AwsSignatureV2 -AccessKey $Config.AccessKey -SecretKey $Config.SecretKey -EndpointUrl $Config.EndpointUrl -Uri $Uri -Method $Method -ContentMD5 $Headers["content-md5"] -ContentType $ContentType -DateTime $Date.ToUniversalTime().ToString("r") -Bucket $BucketName -QueryString $QueryString -Headers $Headers
            if (!$Presign.IsPresent) {
                $Headers["Authorization"] = "AWS $($Config.AccessKey):$($Signature)"
            }
        }

        # if the request is presigned, then the signature has to be added to the end of the query string
        if ($Presign.IsPresent) {
            $UrlEncodedSignature = [System.Net.WebUtility]::UrlEncode($Signature)
            if ($Config.SignerType -eq "AWS4") {
                $CanonicalQueryString += "&X-Amz-Signature=$UrlEncodedSignature"
            }
            else {
                $CanonicalQueryString += "&Signature=$UrlEncodedSignature"
            }
        }

        $Config.EndpointUrl.Path = $Uri
        $Config.EndpointUrl.Query = $CanonicalQueryString

        Write-Log -Level Debug -Config $Config -Message "Request URI:`n$($Config.EndpointUrl.Uri)"
        Write-Log -Level Debug -Config $Config -Message "Request Headers:`n$($Headers | ConvertTo-Json)"

        if ($Size) {
            $ContentLength = $Size
        }
        if ($InStream) {
            $ContentLength = $InStream.Length
        }
        else {
            $ContentLength = $RequestPayload.Length
        }

        $HttpRequestMessage = [System.Net.Http.HttpRequestMessage]::new($Method, $Config.EndpointUrl.Uri)

        if ($HttpContent) {
            $HttpRequestMessage.Content = $HttpContent
        }
        elseif ($InStream) {
            $StreamContent = [System.Net.Http.StreamContent]::new($InStream)
            $StreamContent.Headers.ContentLength = $ContentLength
            $HttpRequestMessage.Content = $StreamContent
        }
        elseif ($RequestPayload -or $Headers["content-md5"] -or $Headers["content-type"]) {
            Write-Log -Level Debug -Config $Config -Message "RequestPayload:`n$RequestPayload"
            $StringContent = [System.Net.Http.StringContent]::new($RequestPayload)
            $HttpRequestMessage.Content = $StringContent
        }

        Write-Log -Level Debug -Config $Config -Message "Adding content headers to HttpContent object"
        if ($Headers["content-md5"]) {
            $HttpRequestMessage.Content.Headers.ContentMD5 = [Convert]::FromBase64String($Headers["content-md5"])
            $Headers.Remove("content-md5")
        }
        elseif ($Headers["Content-MD5"] -ne $null) {
            Throw "content-md5 header specified but empty"
        }

        if ($Headers["content-type"]) {
            $HttpRequestMessage.Content.Headers.ContentType = $Headers["content-type"]
            $Headers.Remove("content-type")
        }
        elseif ($Headers["content-type"] -ne $null) {
            Throw "content-type header specified but empty"
        }

        Write-Log -Level Debug -Config $Config -Message "Adding all other headers to the HttpRequestMessage object"
        foreach ($HeaderKey in $Headers.Keys) {
            Write-Log -Level Debug -Config $Config -Message "$($HeaderKey):$($Headers[$HeaderKey])"
            # AWS Authorization Header is not RFC compliant, therefore we need to skip header validation
            if ($HeaderKey -eq "Authorization") {
                $null = $HttpRequestMessage.Headers.TryAddWithoutValidation($HeaderKey, $Headers[$HeaderKey])
            }
            else {
                $null = $HttpRequestMessage.Headers.Add($HeaderKey, $Headers[$HeaderKey])
            }
        }

        $HttpRequestMessage | Add-Member -MemberType AliasProperty -Name Uri -Value RequestUri

        # make config object available via HttpRequestMessage to use pipeline the output of Get-AwsRequest to Invoke-AwsRequest without explicitly specifying the config parameter
        $HttpRequestMessage | Add-Member -MemberType NoteProperty -Name Config -Value $Config

        # create a unique ID based on the request to store and retrieve recordings
        $RecordIdString = "$Method`n$($HttpRequestMessage.RequestUri)`n"
        if ($HttpRequestMessage.Headers) {
            $RecordIdString += ($HttpRequestMessage.Headers | Where-Object { $_.Key -notmatch 'Authorization|^x-amz-date|^date' } | Sort-Object | Foreach {"$($_.Key.ToLower()): $($_.Value.ToLower())" }) -join "`n"
        }
        if ($HttpRequestMessage.Content.Headers) {
            $RecordIdString += "`n"
            $RecordIdString += ($HttpRequestMessage.Content.Headers | Sort-Object | Foreach {"$($_.Key.ToLower()): $($_.Value.ToLower())" }) -join "`n"
        }
        if ($ContentMd5) {
            $RecordIdString += "`n"
            $RecordIdString += $ContentMd5
        }
        $RecordId = Get-AwsHash -StringToHash $RecordIdString
        Write-Log -Level Verbose -Config $Config -Message "RecordIdString:`n$RecordIdString"
        Write-Log -Level Verbose -Config $Config -Message "RecordId:`n$RecordId"

        $HttpRequestMessage | Add-Member -MemberType NoteProperty -Name RecordIdString -Value $RecordIdString
        $HttpRequestMessage | Add-Member -MemberType NoteProperty -Name RecordId -Value $RecordId

        Write-Output $HttpRequestMessage
    }
}

<#
    .SYNOPSIS
    Invoke AWS Request
    .DESCRIPTION
    Invoke AWS Request
    .PARAMETER Config
    AWS Config
    .PARAMETER Method
    HTTP Request Method
    .PARAMETER RequestUri
    Request URI
    .PARAMETER Headers
    HTTP Headers
    .PARAMETER Content
    HTTP Content
    .PARAMETER CancellationToken
    Thread cancellation token
    .PARAMETER RecordId
    Record ID uniquely identifying request
#>
function Global:Invoke-AwsRequest {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName,
            HelpMessage = "AWS Config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 1,
            ValueFromPipelineByPropertyName,
            HelpMessage = "HTTP Request Method")][ValidateSet("OPTIONS", "GET", "HEAD", "PUT", "POST", "DELETE", "TRACE", "CONNECT")][System.Net.Http.HttpMethod]$Method = "GET",
        [parameter(
            Mandatory = $False,
            Position = 2,
            ValueFromPipelineByPropertyName,
            HelpMessage = "Request URI")][Alias("Uri")][System.UriBuilder]$RequestUri,
        [parameter(
            Mandatory = $False,
            Position = 3,
            ValueFromPipelineByPropertyName,
            HelpMessage = "HTTP Headers")][System.Collections.IEnumerable]$Headers,
        [parameter(
            Mandatory = $False,
            Position = 4,
            ValueFromPipelineByPropertyName,
            HelpMessage = "HTTP Content")][System.Net.Http.HttpContent]$Content,
        [parameter(
            Mandatory = $False,
            Position = 5,
            ValueFromPipelineByPropertyName,
            HelpMessage = "Thread cancellation token")][System.Threading.CancellationToken]$CancellationToken,
        [parameter(
            Mandatory = $False,
            Position = 6,
            ValueFromPipelineByPropertyName,
            HelpMessage = "Record ID uniquely identifying request")][String]$RecordId
    )

    Write-Log -Level Verbose -Config $Config -Message "Invoking Request:`n$Method $RequestUri"

    if ($Config.RecordMode -eq "replay") {
        if ($S3ClientRecordState) {
            $RecordFileName = "$($RecordId)-$($S3ClientRecordState)"
        }
        else {
            $RecordFileName = $RecordId
        }
        $RecordPath = ConvertTo-AbsolutePath -Path $Config.RecordPath
        $RecordFile = [System.IO.FileInfo](Join-Path -Path $RecordPath -ChildPath $RecordFileName)
        Write-Log -Level Verbose -Config $Config -Message "Replaying response from file $RecordFile"
        $RecordFileExists = Test-Path -Path $RecordFile -PathType Leaf
        if ($RecordFileExists) {
            $TaskMetadata = Get-Content -Path $RecordFile | ConvertFrom-Json
            $HttpResponseMessage = [System.Net.Http.HttpResponseMessage]::new($TaskMetadata.ResultMetadata.StatusCode)
            foreach ($Header in $TaskMetadata.ResultMetadata.Headers) {
                $null = $HttpResponseMessage.Headers.TryAddWithoutValidation($Header.Key,$Header.Value)
            }
            if ($TaskMetadata.ResultMetadata.ContentFile) {
                $ContentFile = ConvertTo-AbsolutePath -Path $TaskMetadata.ResultMetadata.ContentFile
                $ContentStream = [System.IO.FileStream]::new($ContentFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
                $HttpContent = [System.Net.Http.StreamContent]::new($ContentStream)
                foreach ($Header in $TaskMetadata.ResultMetadata.ContentHeaders) {
                    $null = $HttpContent.Headers.TryAddWithoutValidation($Header.Key,$Header.Value)
                }
                $HttpResponseMessage.Content = $HttpContent
            }
            $Task = [System.Threading.Tasks.Task]::FromResult($HttpResponseMessage)
        }
        else {
            Throw "File $RecordFileName does not exist."
        }
    }
    else {
        $HttpRequestMessage = [System.Net.Http.HttpRequestMessage]::new($Method, $RequestUri)
        $HttpRequestMessage.Content = $Content

        Write-Log -Level Debug -Config $Config -Message "Adding headers"
        foreach ($Header in $Headers.GetEnumerator()) {
            # AWS Authorization Header is not RFC compliant, therefore we need to skip header validation
            if ($Header.Key -eq "Authorization") {
                $null = $HttpRequestMessage.Headers.TryAddWithoutValidation($Header.Key, $Header.Value)
            }
            else {
                $null = $HttpRequestMessage.Headers.Add($Header.Key, $Header.Value)
            }
        }

        if ([environment]::OSVersion.Platform -match "Win") {
            # check if proxy is used and display a warning as the proxy may block access to the endpoint or manipulate headers
            $ProxyRegistry = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            $ProxySettings = Get-ItemProperty -Path $ProxyRegistry
            if ($ProxySettings.ProxyEnable) {
                Write-Log -Level Warning -Config $Config -Message "Proxy Server $($ProxySettings.ProxyServer) configured in Internet Explorer may be used to connect to the endpoint!"
            }
            if ($ProxySettings.AutoConfigURL) {
                Write-Log -Level Warning -Config $Config -Message "Proxy Server defined in automatic proxy configuration script $($ProxySettings.AutoConfigURL) configured in Internet Explorer may be used to connect to the endpoint!"
            }
        }

        # check if untrusted SSL certificates should be ignored
        $HttpClientHandler = [System.Net.Http.HttpClientHandler]::new()
        if ($Config.SkipCertificateCheck) {
            if ($PSVersionTable.PSVersion.Major -lt 6) {
                # PowerShell 5 and earlier cannot skip certificate validation per request therefore we need to use a workaround
                $CurrentCertificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy
                [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
            }
            else {
                $HttpClientHandler.ServerCertificateCustomValidationCallback = [System.Net.Http.HttpClientHandler]::DangerousAcceptAnyServerCertificateValidator
            }
        }
        $HttpClient = [System.Net.Http.HttpClient]::new($HttpClientHandler)

        $UserAgent = "PowerShell-S3-Client/$($MyInvocation.MyCommand.Version)"
        Write-Log -Level Debug -Config $Config -Message "Adding User Agent header: $UserAgent"
        $HttpClient.DefaultRequestHeaders.UserAgent.Add($UserAgent)

        $HttpClient.Timeout = [Timespan]::FromSeconds([Math]::Max($Content.Headers.ContentLength / 10KB, $DEFAULT_TIMEOUT_SECONDS))
        Write-Log -Level Verbose -Config $Config -Message "Timeout set proportional to size of data to be downloaded (assuming at least 10 KByte/s): $($HttpClient.Timeout)s"

        Write-Log -Level Debug -Config $Config -Message "Send request asynchronously"
        try {
            if ($CancellationToken) {
                $Task = $HttpClient.SendAsync($HttpRequestMessage, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead, $CancellationToken)
            }
            else {
                $Task = $HttpClient.SendAsync($HttpRequestMessage, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead)
            }
        }
        catch {
            throw $_
        }
        finally {
            if ($Config.SkipCertificateCheck -and $PSVersionTable.PSVersion.Major -lt 6) {
                [System.Net.ServicePointManager]::CertificatePolicy = $CurrentCertificatePolicy
            }
        }

        if ($Config.RecordMode -eq "record") {
            $RecordPath = ConvertTo-AbsolutePath -Path $Config.RecordPath
            $RecordPathExists = Test-Path -Path $RecordPath -PathType Container
            if ($RecordPathExists) {
                if ($S3ClientRecordState) {
                    $RecordFileName = "$($RecordId)-$($S3ClientRecordState)"
                }
                else {
                    $RecordFileName = $RecordId
                }
                $RecordFile = [System.IO.FileInfo](Join-Path -Path $RecordPath -ChildPath $RecordFileName)
                Write-Log -Level Verbose -Config $Config -Message "Recording response to file $RecordFile"

                # serialize the task data and store it in the record file
                $TaskMetadata = @{
                    Status = $Task.Status
                }

                if ($Task.Exception) {
                    $TaskMetadata.Exception = $Task.Exception
                }

                if ($Task.Result) {
                    $HttpResponseMessage = $Task.Result
                    # serialize the response message
                    $HttpResponseMessageMetadata = @{
                        Version = $HttpResponseMessage.Version.ToString()
                        StatusCode = $HttpResponseMessage.StatusCode
                        Headers = $HttpResponseMessage.Headers
                    }

                    # copy the raw content of the http response needs to a file
                    $ContentFile = Join-Path -Path $Config.RecordPath -ChildPath ($RecordFile.BaseName + "-content.raw")
                    $ContentStream = [System.IO.FileStream]::new($ContentFile, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite)
                    # ensure that existing content is completely replaced
                    $ContentStream.SetLength(0)
                    $null = $HttpResponseMessage.Content.CopyToAsync($ContentStream).Result
                    # reset the file content stream to allow the content to be processed again by the Cmdlet running Invoke-AwsRequest
                    $ContentStream.Position = 0
                    # the length of the response is only available after reading it
                    if ($ContentStream.Length -gt 0) {
                        # add content headers to the file content stream
                        $HttpContent = [System.Net.Http.StreamContent]::new($ContentStream)
                        foreach ($Header in $Task.Result.Content.Headers) {
                            $null = $HttpContent.Headers.TryAddWithoutValidation($Header.Key,$Header.Value)
                        }
                        # replace the response content with the file content
                        $HttpResponseMessage.Content = $HttpContent
                        # add a reference to the content file
                        $HttpResponseMessageMetadata.ContentFile = $ContentFile
                        $HttpResponseMessageMetadata.ContentHeaders = $HttpResponseMessage.Content.Headers
                    }
                    else {
                        # ensure that content file is removed when it is empty
                        Remove-Item $ContentFile
                    }

                    $TaskMetadata.ResultMetadata = $HttpResponseMessageMetadata
                }

                $TaskMetadata | ConvertTo-Json -Depth 4 | Out-File -FilePath $RecordFile
            }
            else {
                Write-Log -Level Warning -Config $Config -Message "Cannot record response as record path $RecordPath is not an existing directory."
            }
        }
    }
    Write-Output $Task
}

<#
    .SYNOPSIS
    Test AWS Response
    .DESCRIPTION
    Test AWS Response
    .PARAMETER Task
    Task with HttpResponseMessage to be tested
    .PARAMETER Config
    AWS config
#>
function Global:Test-AwsResponse {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory = $True,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Task with HttpResponseMessage to be tested")][System.Threading.Tasks.Task[System.Net.Http.HttpResponseMessage]]$Task,
        [parameter(
            Mandatory = $False,
            Position = 1,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config
    )

    Write-Log -Level Verbose -Config $Config -Message "Testing AWS Response"

    $RedirectedRegion = New-Object -TypeName 'System.Collections.Generic.List[string]'

    $Result = [PSCustomObject]@{Status="";Message=""}

    if ($Task.Result.IsSuccessStatusCode) {
        $Result.Status = "SUCCESS"
        Write-Log -Level Verbose -Config $Config -Message "Response has success status code"
    }
    elseif ($Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
        $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
        $RetryCount++
        $Result.Message = "Task failed due to internal server error, starting retry number $RetryCount of $MAX_RETRIES retries after exponential backoff of $SleepSeconds seconds"
        Write-Log -Level Verbose -Config $Config -Message $Result.Message
        Start-Sleep -Seconds $SleepSeconds
        $Result.Status = "RETRY"
    }
    elseif ($Task.IsCanceled -and $Config.RetryCount -lt $Config.MaxRetries) {
        $SleepSeconds = [System.Math]::Pow(3, $Config.RetryCount)
        $Config.RetryCount++
        $Result.Message = "Task canceled, starting retry number $($Config.RetryCount) of $($Config.MaxRetries) retries after exponential backoff of $SleepSeconds seconds"
        Write-Log -Level Verbose -Config $Config -Message $Result.Message
        Start-Sleep -Seconds $SleepSeconds
        $Result.Status = "RETRY"
    }
    elseif ($Task.IsCanceled -and $Config.RetryCount -ge $Config.MaxRetries) {
        $Result.Message = "Task canceled (usually due to a connection timeout) and maximum number of $(Config.MaxRetries) retries are reached."
        Write-Log -Level Verbose -Config $Config -Message $Result.Message
        $Result.Status = "FAILED"
    }
    elseif ($Task.Exception.Message -match "Device not configured") {
        $Result.Message = "Task failed due to issues with the network connection." + $Task.Exception.Message
        Write-Log -Level Verbose -Config $Config -Message $Result.Message
        $Result.Status = "FAILED"
    }
    elseif ($Task.IsFaulted) {
        $Result.Message = $Task.Exception.Message
        Write-Log -Level Verbose -Config $Config -Message $Result.Message
        $Result.Status = "FAILED"
    }
    elseif ($Task.Result.Headers -and $Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
        $Result.Message = "Request was redirected as bucket does not belong to specified region. Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
        Write-Log -Level Verbose -Config $Config -Message $Result.Message
        $Result.Status = "REDIRECTED"
        $Config.Region = $RedirectedRegion[0]
    }
    elseif ($Task.Result) {
        $Result.Message = "Request completed with HTTP status code $($Task.Result.StatusCode)."
        if ($Task.Result.Content) {
            $Result.Message += " HTTP Response Content:`n$($Task.Result.Content.ReadAsStringAsync().Result)"
        }
        Write-Log -Level Verbose -Config $Config -Message $Result.Message
        $Result.Status = $Task.Result.StatusCode
    }
    else {
        $Result.Message = "Task did not succeed and has status $($Task.Status)"
        Write-Log -Level Verbose -Config $Config -Message $Result.Message
        $Result.Status = "OTHER"
    }
    Write-Output $Result
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
    Add AWS Config and Credentials
    .DESCRIPTION
    Add AWS Config and Credentials
    .PARAMETER ProfileName
    AWS Profile to use which contains AWS sredentials and settings
    .PARAMETER ProfileLocation
    AWS Profile location if different than .aws/credentials
    .PARAMETER Credential
    Credential
    .PARAMETER AccessKey
    S3 Access Key
    .PARAMETER SecretKey
    S3 Secret Access Key
    .PARAMETER Region
    Default region to use for all requests made with these credentials
    .PARAMETER EndpointUrl
    Custom endpoint URL if different than AWS URL
    .PARAMETER MaxConcurrentRequests
    The maximum number of concurrent requests (Default: processor count * 2)
    .PARAMETER MaxQueueSize
    The maximum number of tasks in the task queue (Default: 1000)
    .PARAMETER MultipartThreshold
    The size threshold where multipart uploads are used of individual files (Default: 8MB)
    .PARAMETER MultipartChunksize
    When using multipart transfers, this is the chunk size that is used for multipart transfers of individual files
    .PARAMETER MaxBandwidth
    The maximum bandwidth that will be consumed for uploading and downloading data to and from Amazon S3
    .PARAMETER UseAccelerateEndpoint
    Use the Amazon S3 Accelerate endpoint for all s3 and s3api commands. S3 Accelerate must first be enabled on the bucket before attempting to use the accelerate endpoint. This is mutually exclusive with the use_dualstack_endpoint option.
    .PARAMETER UseDualstackEndpoint
    Use the Amazon S3 dual IPv4 / IPv6 endpoint for all s3 commands. This is mutually exclusive with the use_accelerate_endpoint option.
    .PARAMETER AddressingStyle
    Specifies which addressing style to use. This controls if the bucket name is in the hostname or part of the URL. Value values are: path, virtual, and auto. The default value is auto.
    .PARAMETER PayloadSigning
    Refers to whether or not to SHA256 sign sigv4 payloads. By default, this is disabled for streaming uploads (UploadPart and PutObject) when using https.
    .PARAMETER SkipCertificateCheck
    Enable or disable skipping of certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER SignerType
    AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)
    .PARAMETER LogPath
    Log path
    .PARAMETER LogLevel
    Log level
    .PARAMETER RecordPath
    Path to directory to store response records in
    .PARAMETER RecordMode
    Record mode
#>
function Global:Add-AwsConfig {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS Profile to use which contains AWS sredentials and settings")][Alias("Profile")][String]$ProfileName = "default",
        [parameter(
            Mandatory = $False,
            Position = 1,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation = $AWS_CREDENTIALS_FILE,
        [parameter(
            Mandatory = $False,
            Position = 2,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Credential")][PSCredential]$Credential,
        [parameter(
            Mandatory = $False,
            Position = 3,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "S3 Access Key")][Alias("aws_access_key_id")][String]$AccessKey,
        [parameter(
            Mandatory = $False,
            Position = 4,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "S3 Secret Access Key")][Alias("aws_secret_access_key")][String]$SecretKey,
        [parameter(
            Mandatory = $False,
            Position = 5,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Default region to use for all requests made with these credentials")][String]$Region,
        [parameter(
            Mandatory = $False,
            Position = 6,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Custom endpoint URL if different than AWS URL")][Alias("endpoint_url")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "The maximum number of concurrent requests (Default: processor count * 2)")][Alias("max_concurrent_requests")][UInt16]$MaxConcurrentRequests,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "The maximum number of tasks in the task queue (Default: 1000)")][Alias("max_queue_size")][UInt16]$MaxQueueSize,
        [parameter(
            Mandatory = $False,
            Position = 9,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "The size threshold where multipart uploads are used of individual files (Default: 8MB)")][Alias("multipart_threshold")][String]$MultipartThreshold,
        [parameter(
            Mandatory = $False,
            Position = 10,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "When using multipart transfers, this is the chunk size that is used for multipart transfers of individual files")][Alias("multipart_chunksize")][String]$MultipartChunksize,
        [parameter(
            Mandatory = $False,
            Position = 11,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "The maximum bandwidth that will be consumed for uploading and downloading data to and from Amazon S3")][Alias("max_bandwidth")][String]$MaxBandwidth,
        [parameter(
            Mandatory = $False,
            Position = 12,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Use the Amazon S3 Accelerate endpoint for all s3 and s3api commands. S3 Accelerate must first be enabled on the bucket before attempting to use the accelerate endpoint. This is mutually exclusive with the use_dualstack_endpoint option.")][Alias("use_accelerate_endpoint")][Boolean]$UseAccelerateEndpoint,
        [parameter(
            Mandatory = $False,
            Position = 13,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Use the Amazon S3 dual IPv4 / IPv6 endpoint for all s3 commands. This is mutually exclusive with the use_accelerate_endpoint option.")][Alias("use_dualstack_endpoint")][Boolean]$UseDualstackEndpoint,
        [parameter(
            Mandatory = $False,
            Position = 14,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Specifies which addressing style to use. This controls if the bucket name is in the hostname or part of the URL. Value values are: path, virtual, and auto. The default value is auto.")][Alias("UrlStyle", "addressing_style")][ValidateSet("auto", "path", "virtual")][String]$AddressingStyle,
        [parameter(
            Mandatory = $False,
            Position = 15,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Refers to whether or not to SHA256 sign sigv4 payloads. By default, this is disabled for streaming uploads (UploadPart and PutObject) when using https.")][Alias("payload_signing_enabled")][ValidateSet("auto", "true", "false")][String]$PayloadSigning,
        [parameter(
            Mandatory = $False,
            Position = 16,
            HelpMessage = "Enable or disable skipping of certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Boolean]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 17,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)")][String][ValidateSet("S3", "AWS4")]$SignerType,
        [parameter(
            Mandatory = $False,
            Position = 18,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Maximum retry count")][Int]$MaxRetries,
        [parameter(
            Mandatory = $False,
            Position = 19,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Log path")][System.IO.DirectoryInfo]$LogPath,
        [parameter(
            Mandatory = $False,
            Position = 20,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Log level")][String][ValidateSet("CRITICAL","ERROR","WARNING","INFORMATION","VERBOSE","DEBUG","DEFAULT")]$LogLevel,
        [parameter(
            Mandatory = $False,
            Position = 21,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Path to directory to store response records in")][System.IO.DirectoryInfo]$RecordPath,
        [parameter(
            Mandatory = $False,
            Position = 22,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Record mode")][String][ValidateSet("record","replay")]$RecordMode
    )

    Write-Log -Level Verbose -Config $Config -Message "Add AWS Config"

    $ConfigLocation = $ProfileLocation -replace "credentials$", 'config'

    if ($Credential) {
        $AccessKey = $Credential.UserName
        $SecretKey = $Credential.GetNetworkCredential().Password
    }

    $Credentials = @()
    $Configs = @()

    if ($AccessKey -and $SecretKey) {
        try {
            $Credentials = ConvertFrom-AwsConfigFile -AwsConfigFile $ProfileLocation
        }
        catch {
            Write-Log -Level Verbose -Config $Config -Message "Retrieving credentials from $ProfileLocation failed"
        }

        if (($Credentials | Where-Object { $_.ProfileName -eq $ProfileName })) {
            $CredentialEntry = $Credentials | Where-Object { $_.ProfileName -eq $ProfileName }
        }
        else {
            $CredentialEntry = [PSCustomObject]@{ ProfileName = $ProfileName }
        }

        $CredentialEntry | Add-Member -MemberType NoteProperty -Name aws_access_key_id -Value $AccessKey -Force
        $CredentialEntry | Add-Member -MemberType NoteProperty -Name aws_secret_access_key -Value $SecretKey -Force

        $Credentials = (@($Credentials | Where-Object { $_.ProfileName -ne $ProfileName }) + $CredentialEntry) | Where-Object { $_.ProfileName }
        ConvertTo-AwsConfigFile -Config $Credentials -AwsConfigFile $ProfileLocation
    }

    try {
        $Configs = ConvertFrom-AwsConfigFile -AwsConfigFile $ConfigLocation
    }
    catch {
        Write-Log -Level Warning -Config $Config -Message "Retrieving config from $ConfigLocation failed"
    }

    $Config = $Configs | Where-Object { $_.ProfileName -eq $ProfileName }
    if ($Config) {
        Write-Log -Level Verbose -Config $Config -Message "Updating AWS Config for profile $ProfileName"
        if (!$Config.S3) {
            $Config | Add-Member -MemberType NoteProperty -Name "S3" -Value ([PSCustomObject]@{ })
        }
    }
    else {
        Write-Log -Level Verbose -Config $Config -Message "Adding AWS Config for profile $ProfileName"
        $Config = [PSCustomObject]@{ ProfileName = $ProfileName; s3 = [PSCustomObject]@{ } }
    }

    if ($Region -and $Region -ne "us-east-1") {
        $Config | Add-Member -MemberType NoteProperty -Name region -Value $Region -Force
    }
    elseif ($Config.Region -and $Region -eq "us-east-1") {
        $Config.PSObject.Properties.Remove("Region")
    }

    if ($EndpointUrl) {
        $EndpointUrlString = $EndpointUrl -replace "(http://.*:80)", '$1' -replace "(https://.*):443", '$1' -replace "/$", ""
        $Config.S3 | Add-Member -MemberType NoteProperty -Name endpoint_url -Value $EndpointUrlString -Force
    }

    if ($MaxConcurrentRequests -and $MaxConcurrentRequests -ne ([Environment]::ProcessorCount * 2)) {
        $Config.S3 | Add-Member -MemberType NoteProperty -Name max_concurrent_requests -Value $MaxConcurrentRequests -Force
    }
    elseif ($Config.S3.max_concurrent_requests -and $MaxConcurrentRequests -eq ([Environment]::ProcessorCount * 2)) {
        $Config.S3.PSObject.Properties.Remove("max_concurrent_requests")
    }

    if ($MaxQueueSize -and $MaxQueueSize -ne 1000) {
        $Config.S3 | Add-Member -MemberType NoteProperty -Name max_queue_size -Value $MaxQueueSize -Force
    }
    elseif ($Config.S3.max_queue_size -and $MaxQueueSize -eq 1000) {
        $Config.S3.PSObject.Properties.Remove("max_queue_size")
    }

    if ($MultipartThreshold -and $MultipartThreshold -ne "8MB") {
        $Config.S3 | Add-Member -MemberType NoteProperty -Name multipart_threshold -Value $MultipartThreshold -Force
    }
    elseif ($Config.S3.multipart_threshold -and $MultipartThreshold -eq "8MB") {
        $Config.S3.PSObject.Properties.Remove("multipart_threshold")
    }

    if ($MultipartChunksize -and $MultipartChunksize -ne "0") {
        $Config.S3 | Add-Member -MemberType NoteProperty -Name multipart_chunksize -Value $MultipartChunksize -Force
    }
    elseif ($Config.S3.multipart_chunksize -and $MultipartChunksize -eq "0") {
        $Config.S3.PSObject.Properties.Remove("multipart_chunksize")
    }

    if ($MaxBandwidth -and $MaxBandwidth -ne "0") {
        $Config.S3 | Add-Member -MemberType NoteProperty -Name max_bandwidth -Value $MaxBandwidth -Force
    }
    elseif ($Config.S3.max_bandwidth -and $MaxBandwidth -eq "0") {
        $Config.S3.PSObject.Properties.Remove("max_bandwidth")
    }

    if ($UseAccelerateEndpoint -and $UseDualstackEndpoint) {
        Throw "The parameters use_accelerate_endpoint and use_dualstack_endpoint are mutually exclusive!"
    }

    if ($UseAccelerateEndpoint) {
        $Config.S3 | Add-Member -MemberType NoteProperty -Name use_accelerate_endpoint -Value $UseAccelerateEndpoint -Force
    }
    elseif ($Config.S3.use_accelerate_endpoint -and !$UseAccelerateEndpoint) {
        $Config.S3.PSObject.Properties.Remove("use_accelerate_endpoint")
    }

    if ($UseDualstackEndpoint) {
        $Config.S3 | Add-Member -MemberType NoteProperty -Name use_dualstack_endpoint -Value $UseDualstackEndpoint -Force
    }
    elseif ($Config.use_dualstack_endpoint -and !$UseDualstackEndpoint) {
        $Config.S3.PSObject.Properties.Remove("use_dualstack_endpoint")
    }

    if ($AddressingStyle -and $AddressingStyle -ne "auto") {
        $Config.S3 | Add-Member -MemberType NoteProperty -Name addressing_style -Value $AddressingStyle -Force
    }
    elseif ($Config.S3.addressing_style -and $AddressingStyle -match "auto|false") {
        $Config.S3.PSObject.Properties.Remove("addressing_style")
    }

    if ($PayloadSigning -and $PayloadSigning -ne "auto") {
        $Config.S3 | Add-Member -MemberType NoteProperty -Name payload_signing_enabled -Value $PayloadSigning -Force
    }
    elseif ($Config.S3.payload_signing_enabled -and $PayloadSigning -match "auto|false") {
        $Config.S3.PSObject.Properties.Remove("payload_signing_enabled")
    }

    if ($SkipCertificateCheck) {
        $Config.S3 | Add-Member -MemberType NoteProperty -Name skip_certificate_check -Value $SkipCertificateCheck -Force
    }
    elseif ($Config.skip_certificate_check -and !$SkipCertificateCheck) {
        $Config.S3.PSObject.Properties.Remove("skip_certificate_check")
    }

    if ($SignerType) {
        $Config.S3 | Add-Member -MemberType NoteProperty -Name signer_type -Value $SignerType -Force
    }
    elseif ($Config.S3.signer_type -and $SignerType -match "AWS4") {
        $Config.S3.PSObject.Properties.Remove("signer_type")
    }

    if ($MaxRetries -and $MaxRetries -ne $MAX_RETRIES) {
        $Config.S3 | Add-Member -MemberType NoteProperty -Name max_retries -Value $MaxRetries -Force
    }
    elseif ($Config.S3.max_retries -and $MaxRetries -eq $MAX_RETRIES) {
        $Config.S3.PSObject.Properties.Remove("max_retries")
    }

    if ($LogPath) {
        $Config | Add-Member -MemberType NoteProperty -Name log_path -Value $LogPath -Force
    }
    if ($LogLevel -and $LogLevel -ne "DEFAULT") {
        $Config | Add-Member -MemberType NoteProperty -Name log_level -Value $LogLevel -Force
    }
    elseif ($Config.log_level -and $LogLevel -eq "DEFAULT") {
        $Config.PSObject.Properties.Remove("log_level")
    }

    if ($RecordPath) {
        $Config | Add-Member -MemberType NoteProperty -Name record_path -Value $RecordPath -Force
    }

    if ($RecordMode -and $Config.record_path) {
        $Config | Add-Member -MemberType NoteProperty -Name record_mode -Value $RecordMode -Force
    }

    $Configs = (@($Configs | Where-Object { $_.ProfileName -ne $ProfileName }) + $Config) | Where-Object { $_.ProfileName }
    ConvertTo-AwsConfigFile -Config $Configs -AwsConfigFile $ConfigLocation
}

Set-Alias -Name Get-AwsProfiles -Value Get-AwsConfigs
Set-Alias -Name Get-AwsCredentials -Value Get-AwsConfigs
<#
    .SYNOPSIS
    Get the AWS config for all profiles and if there is a connection to a StorageGRID, it includes the AWS config of the connected tenant
    .DESCRIPTION
    Get the AWS config for all profiles and if there is a connection to a StorageGRID, it includes the AWS config of the connected tenant
    .PARAMETER ProfileLocation
    AWS Profile location if different than .aws/credentials
#>
function Global:Get-AwsConfigs {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation = $AWS_CREDENTIALS_FILE
    )

    Write-Log -Level Verbose -Config $Config -Message "Get the AWS config for all profiles"

    if (!$ProfileLocation) {
        $ProfileLocation = $AWS_CREDENTIALS_FILE
    }
    $ConfigLocation = $ProfileLocation -replace "credentials$", 'config'

    if (!(Test-Path $ProfileLocation)) {
        Write-Log -Level Warning -Config $Config -Message "Profile location $ProfileLocation does not exist!"
        break
    }

    $Credentials = @()
    $Config = @()
    try {
        $Credentials = ConvertFrom-AwsConfigFile -AwsConfigFile $ProfileLocation
    }
    catch {
        Write-Log -Level Warning -Config $Config -Message "Retrieving credentials from $ProfileLocation failed"
    }
    try {
        $Configs = ConvertFrom-AwsConfigFile -AwsConfigFile $ConfigLocation
    }
    catch {
        Write-Log -Level Warning -Config $Config -Message "Retrieving credentials from $ConfigLocation failed"
    }

    foreach ($Credential in $Credentials) {
        $Config = $Configs | Where-Object { $_.ProfileName -eq $Credential.ProfileName } | Select-Object -First 1
        if (!$Config) {
            $Config = [PSCustomObject]@{ProfileName = $Credential.ProfileName }
            $Configs = @($Configs) + $Config
        }
        if ($Credential.aws_access_key_id) {
            $Config | Add-Member -MemberType NoteProperty -Name aws_access_key_id -Value $Credential.aws_access_key_id -Force
        }
        if ($Credential.aws_secret_access_key) {
            $Config | Add-Member -MemberType NoteProperty -Name aws_secret_access_key -Value $Credential.aws_secret_access_key -Force
        }
    }

    foreach ($Config in $Configs) {
        $Output = [PSCustomObject]@{ProfileName = $Config.ProfileName; AccessKey = $Config.aws_access_key_id; SecretKey = $Config.aws_secret_access_key }
        if ($Config.S3.Region) {
            $Output | Add-Member -MemberType NoteProperty -Name Region -Value $Config.S3.Region
        }
        elseif ($Config.Region) {
            $Output | Add-Member -MemberType NoteProperty -Name Region -Value $Config.Region
        }
        else {
            $Output | Add-Member -MemberType NoteProperty -Name Region -Value "us-east-1"
        }
        if ($Config.S3.endpoint_url) {
            $Output | Add-Member -MemberType NoteProperty -Name EndpointUrl -Value $Config.S3.endpoint_url
        }
        elseif ($Config.endpoint_url) {
            $Output | Add-Member -MemberType NoteProperty -Name EndpointUrl -Value $Config.endpoint_url
        }
        else {
            $Output | Add-Member -MemberType NoteProperty -Name EndpointUrl -Value $DEFAULT_AWS_ENDPOINT
        }
        if ($Config.S3.max_concurrent_requests) {
            $Output | Add-Member -MemberType NoteProperty -Name MaxConcurrentRequests -Value $Config.S3.max_concurrent_requests
        }
        elseif ($Config.max_concurrent_requests) {
            $Output | Add-Member -MemberType NoteProperty -Name MaxConcurrentRequests -Value $Config.max_concurrent_requests
        }
        else {
            $Output | Add-Member -MemberType NoteProperty -Name MaxConcurrentRequests -Value ([Environment]::ProcessorCount * 2)
        }
        if ($Config.S3.max_queue_size) {
            $Output | Add-Member -MemberType NoteProperty -Name MaxQueueSize -Value $Config.S3.max_queue_size
        }
        elseif ($Config.max_queue_size) {
            $Output | Add-Member -MemberType NoteProperty -Name MaxQueueSize -Value $Config.max_queue_size
        }
        else {
            $Output | Add-Member -MemberType NoteProperty -Name MaxQueueSize -Value 1000
        }
        if ($Config.S3.multipart_threshold) {
            $Output | Add-Member -MemberType NoteProperty -Name MultipartThreshold -Value $Config.S3.multipart_threshold
        }
        elseif ($Config.multipart_threshold) {
            $Output | Add-Member -MemberType NoteProperty -Name MultipartThreshold -Value $Config.multipart_threshold
        }
        else {
            $Output | Add-Member -MemberType NoteProperty -Name MultipartThreshold -Value "8MB"
        }
        if ($Config.S3.multipart_chunksize) {
            $Output | Add-Member -MemberType NoteProperty -Name MultipartChunksize -Value $Config.S3.multipart_chunksize
        }
        elseif ($Config.multipart_chunksize) {
            $Output | Add-Member -MemberType NoteProperty -Name MultipartChunksize -Value $Config.multipart_chunksize
        }
        else {
            $Output | Add-Member -MemberType NoteProperty -Name MultipartChunksize -Value $null
        }
        if ($Config.S3.max_bandwidth) {
            $Output | Add-Member -MemberType NoteProperty -Name MaxBandwidth -Value $Config.S3.max_bandwidth
        }
        else {
            $Output | Add-Member -MemberType NoteProperty -Name MaxBandwidth -Value $Config.max_bandwidth
        }
        if ($Config.S3.use_accelerate_endpoint) {
            $Output | Add-Member -MemberType NoteProperty -Name UseAccelerateEndpoint -Value ([System.Convert]::ToBoolean($Config.S3.use_accelerate_endpoint))
        }
        elseif ($Config.use_accelerate_endpoint) {
            $Output | Add-Member -MemberType NoteProperty -Name UseAccelerateEndpoint -Value ([System.Convert]::ToBoolean($Config.use_accelerate_endpoint))
        }
        else {
            $Output | Add-Member -MemberType NoteProperty -Name UseAccelerateEndpoint -Value $false
        }
        if ($Config.S3.use_dualstack_endpoint) {
            $Output | Add-Member -MemberType NoteProperty -Name UseDualstackEndpoint -Value ([System.Convert]::ToBoolean($Config.S3.use_dualstack_endpoint))
        }
        elseif ($Config.use_dualstack_endpoint) {
            $Output | Add-Member -MemberType NoteProperty -Name UseDualstackEndpoint -Value ([System.Convert]::ToBoolean($Config.use_dualstack_endpoint))
        }
        else {
            $Output | Add-Member -MemberType NoteProperty -Name UseDualstackEndpoint -Value $false
        }
        if ($Config.S3.addressing_style) {
            $Output | Add-Member -MemberType NoteProperty -Name AddressingStyle -Value $Config.S3.addressing_style
        }
        elseif ($Config.addressing_style) {
            $Output | Add-Member -MemberType NoteProperty -Name AddressingStyle -Value $Config.addressing_style
        }
        else {
            $Output | Add-Member -MemberType NoteProperty -Name AddressingStyle -Value "auto"
        }
        if ($Config.S3.payload_signing_enabled) {
            $Output | Add-Member -MemberType NoteProperty -Name PayloadSigning -Value $Config.S3.payload_signing_enabled
        }
        elseif ($Config.payload_signing_enabled) {
            $Output | Add-Member -MemberType NoteProperty -Name PayloadSigning -Value $Config.payload_signing_enabled
        }
        else {
            $Output | Add-Member -MemberType NoteProperty -Name PayloadSigning -Value "auto"
        }

        if ($Config.S3.skip_certificate_check) {
            $Output | Add-Member -MemberType NoteProperty -Name SkipCertificateCheck -Value ([System.Convert]::ToBoolean($Config.S3.skip_certificate_check))
        }
        elseif ($Config.skip_certificate_check) {
            $Output | Add-Member -MemberType NoteProperty -Name SkipCertificateCheck -Value ([System.Convert]::ToBoolean($Config.skip_certificate_check))
        }
        else {
            $Output | Add-Member -MemberType NoteProperty -Name SkipCertificateCheck -Value $False
        }
        if ($Config.S3.signer_type) {
            $Output | Add-Member -MemberType NoteProperty -Name SignerType -Value $Config.S3.signer_type
        }
        elseif ($Config.signer_type) {
            $Output | Add-Member -MemberType NoteProperty -Name SignerType -Value $Config.signer_type
        }
        else {
            $Output | Add-Member -MemberType NoteProperty -Name SignerType -Value "AWS4"
        }
        $Output | Add-Member -MemberType NoteProperty -Name RetryCount -Value 0
        if ($Config.S3.max_retries) {
            $Output | Add-Member -MemberType NoteProperty -Name MaxRetries -Value $Config.S3.max_retries
        }
        else {
            $Output | Add-Member -MemberType NoteProperty -Name MaxRetries -Value $MAX_RETRIES
        }
        if ($Config.log_path) {
            $Output | Add-Member -MemberType NoteProperty -Name LogPath -Value ([System.IO.DirectoryInfo]$Config.log_path)
        }
        if ($Config.log_level) {
            $Output | Add-Member -MemberType NoteProperty -Name LogLevel -Value $Config.log_level
        }
        else {
            $Output | Add-Member -MemberType NoteProperty -Name LogLevel -Value "DEFAULT"
        }
        if ($Config.record_path) {
            $Output | Add-Member -MemberType NoteProperty -Name RecordPath -Value ([System.IO.DirectoryInfo]$Config.record_path)
            if ($Config.record_mode) {
                $Output | Add-Member -MemberType NoteProperty -Name RecordMode -Value $Config.record_mode
            }
        }
        Write-Output $Output
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
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used
    .PARAMETER ProfileName
    AWS Profile to use which contains AWS sredentials and settings
    .PARAMETER ProfileLocation
    AWS Profile location if different than .aws/credentials
    .PARAMETER AccessKey
    S3 Access Key
    .PARAMETER SecretKey
    S3 Secret Access Key
    .PARAMETER AccountId
    StorageGRID Account ID
    .PARAMETER Region
    Default Region to use for all requests made with these credentials
    .PARAMETER EndpointUrl
    Custom endpoint URL if different than AWS URL
    .PARAMETER MaxConcurrentRequests
    The maximum number of concurrent requests (Default: processor count * 2)
    .PARAMETER MaxQueueSize
    The maximum number of tasks in the task queue (Default: 1000)
    .PARAMETER MultipartThreshold
    The size threshold where multipart uploads are used of individual files (Default: 8MB)
    .PARAMETER MultipartChunksize
    When using multipart transfers, this is the chunk size that is used for multipart transfers of individual files
    .PARAMETER MaxBandwidth
    The maximum bandwidth that will be consumed for uploading and downloading data to and from Amazon S3
    .PARAMETER UseAccelerateEndpoint
    Use the Amazon S3 Accelerate endpoint for all s3 and s3api commands. S3 Accelerate must first be enabled on the bucket before attempting to use the accelerate endpoint. This is mutually exclusive with the use_dualstack_endpoint option.
    .PARAMETER UseDualstackEndpoint
    Use the Amazon S3 dual IPv4 / IPv6 endpoint for all s3 commands. This is mutually exclusive with the use_accelerate_endpoint option.
    .PARAMETER AddressingStyle
    Specifies which addressing style to use. This controls if the bucket name is in the hostname or part of the URL. Value values are: path, virtual, and auto. The default value is auto.
    .PARAMETER PayloadSigning
    Refers to whether or not to SHA256 sign sigv4 payloads. By default, this is disabled for streaming uploads (UploadPart and PutObject) when using https.
    .PARAMETER SkipCertificateCheck
    Enable or disable skipping of certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER SignerType
    AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)
    .PARAMETER LogPath
    Log path
    .PARAMETER LogLevel
    Log level
    .PARAMETER RecordPath
    Path to directory to store response records in
    .PARAMETER RecordMode
    Record mode
#>
function Global:Get-AwsConfig {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            Mandatory = $False,
            Position = 1,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName,
        [parameter(
            Mandatory = $False,
            Position = 2,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation = $AWS_CREDENTIALS_FILE,
        [parameter(
            Mandatory = $False,
            Position = 3,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            Mandatory = $False,
            Position = 4,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "S3 Secret Access Key")][String]$SecretKey,
        [parameter(
            Mandatory = $False,
            Position = 5,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID Account ID")][String]$AccountId,
        [parameter(
            Mandatory = $False,
            Position = 6,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Default Region to use for all requests made with these credentials")][String]$Region,
        [parameter(
            Mandatory = $False,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "The maximum number of concurrent requests (Default: processor count * 2)")][Alias("max_concurrent_requests")][UInt16]$MaxConcurrentRequests,
        [parameter(
            Mandatory = $False,
            Position = 9,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "The maximum number of tasks in the task queue (Default: 1000)")][Alias("max_queue_size")][UInt16]$MaxQueueSize,
        [parameter(
            Mandatory = $False,
            Position = 10,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "The size threshold where multipart uploads are used of individual files (Default: 8MB)")][Alias("multipart_threshold")][String]$MultipartThreshold,
        [parameter(
            Mandatory = $False,
            Position = 11,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "When using multipart transfers, this is the chunk size that is used for multipart transfers of individual files")][Alias("multipart_chunksize")][String]$MultipartChunksize,
        [parameter(
            Mandatory = $False,
            Position = 12,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "The maximum bandwidth that will be consumed for uploading and downloading data to and from Amazon S3")][Alias("max_bandwidth")][String]$MaxBandwidth,
        [parameter(
            Mandatory = $False,
            Position = 13,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Use the Amazon S3 Accelerate endpoint for all s3 and s3api commands. S3 Accelerate must first be enabled on the bucket before attempting to use the accelerate endpoint. This is mutually exclusive with the use_dualstack_endpoint option.")][Alias("use_accelerate_endpoint")][String]$UseAccelerateEndpoint,
        [parameter(
            Mandatory = $False,
            Position = 14,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Use the Amazon S3 dual IPv4 / IPv6 endpoint for all s3 commands. This is mutually exclusive with the use_accelerate_endpoint option.")][Alias("use_dualstack_endpoint")][String]$UseDualstackEndpoint,
        [parameter(
            Mandatory = $False,
            Position = 15,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Specifies which addressing style to use. This controls if the bucket name is in the hostname or part of the URL. Value values are: path, virtual, and auto. The default value is auto.")][Alias("addressing_style")][ValidateSet("auto", "path", "virtual")][String]$AddressingStyle,
        [parameter(
            Mandatory = $False,
            Position = 16,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Refers to whether or not to SHA256 sign sigv4 payloads. By default, this is disabled for streaming uploads (UploadPart and PutObject) when using https.")][Alias("payload_signing_enabled")][String]$PayloadSigning,
        [parameter(
            Mandatory = $False,
            Position = 17,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Enable or disable skipping of certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][String]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 18,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)")][String][ValidateSet("S3", "AWS4")]$SignerType,
        [parameter(
            Mandatory = $False,
            Position = 19,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Current retry count")][Int]$RetryCount,
        [parameter(
            Mandatory = $False,
            Position = 20,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Maximum retry count")][Int]$MaxRetries,
        [parameter(
            Mandatory = $False,
            Position = 21,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Log path")][String]$LogPath,
        [parameter(
            Mandatory = $False,
            Position = 22,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Log level")][String][ValidateSet("CRITICAL","ERROR","WARNING","INFORMATION","VERBOSE","DEBUG","DEFAULT")]$LogLevel,
        [parameter(
            Mandatory = $False,
            Position = 23,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Path to directory to store response records in")][System.IO.DirectoryInfo]$RecordPath,
        [parameter(
            Mandatory = $False,
            Position = 24,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Record mode")][String][ValidateSet("record","replay")]$RecordMode
    )

    Write-Log -Level Verbose -Config $Config -Message "Get AWS config"

    if (!$Server -and $CurrentSgwServer) {
        $Server = $CurrentSgwServer.PSObject.Copy()
    }

    $Config = [PSCustomObject]@{ProfileName = $ProfileName;
        AccessKey                           = $AccessKey;
        SecretKey                           = $SecretKey;
        Region                              = $Region;
        EndpointUrl                         = $EndpointUrl;
        MaxConcurrentRequests               = $MaxConcurrentRequests;
        MaxQueueSize                        = $MaxQueueSize;
        MultipartThreshold                  = $MultipartThreshold;
        MultipartChunksize                  = $MultipartChunksize;
        MaxBandwidth                        = $MaxBandwidth;
        UseAccelerateEndpoint               = $UseAccelerateEndpoint;
        UseDualstackEndpoint                = $UseDualstackEndpoint;
        AddressingStyle                     = $AddressingStyle;
        PayloadSigning                      = $PayloadSigning;
        SkipCertificateCheck                = [System.Convert]::ToBoolean($SkipCertificateCheck -eq $true);
        SignerType                          = $SignerType
        RetryCount                          = $RetryCount
        MaxRetries                          = $MaxRetries
        LogPath                             = $LogPath
        LogLevel                            = $LogLevel
    }

    if (!$ProfileName -and !$AccessKey -and !($Server -and ($AccountId -or $Server.AccountId))) {
        $ProfileName = "default"
    }

    if ($ProfileName) {
        Write-Log -Level Verbose -Config $Config -Message "Profile $ProfileName specified, therefore returning AWS config of this profile"
        $Config = Get-AwsConfigs -ProfileLocation $ProfileLocation | Where-Object { $_.ProfileName -eq $ProfileName }
        if (!$Config) {
            Write-Log -Level Warning -Config $Config -Message "Config for profile $ProfileName not found"
            return
        }
    }
    elseif ($AccessKey) {
        Write-Log -Level Verbose -Config $Config -Message "Access Key $AccessKey and Secret Access Key specified, therefore returning AWS config for the keys"
        $PayloadSigning = "auto"
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
            Write-Log -Level Verbose -Config $Config -Message "No profile and no access key specified, but connected to StorageGRID tenant with Account ID $AccountId. Therefore using autogenerated temporary AWS credentials"
            if ($Server.AccessKeyStore[$AccountId].Expires -ge (Get-Date).AddMinutes(1) -or ($Server.AccessKeyStore[$AccountId] -and !$Server.AccessKeyStore[$AccountId].Expires)) {
                $Credential = $Server.AccessKeyStore[$AccountId] | Sort-Object -Property expires | Select-Object -Last 1
                Write-Log -Level Verbose -Config $Config -Message "Using existing Access Key $( $Credential.AccessKey )"
            }
            else {
                $Credential = New-SgwS3AccessKey -Server $Server -Expires (Get-Date).AddSeconds($Server.TemporaryAccessKeyExpirationTime) -AccountId $AccountId
                Write-Log -Level Verbose -Config $Config -Message "Created new temporary Access Key $( $Credential.AccessKey )"
            }
            $Config.AccessKey = $Credential.AccessKey
            $Config.SecretKey = $Credential.SecretAccessKey
            $Config.EndpointUrl = [System.UriBuilder]$EndpointUrl.ToString()
            $Config.SkipCertificateCheck = $Server.SkipCertificateCheck
        }
    }

    if ($Region) {
        $Config.Region = $Region
    }
    elseif (!$Config.Region) {
        $Config.Region = "us-east-1"
    }

    if ($EndpointUrl) {
        $Config.EndpointUrl = $EndpointUrl
    }

    if ($MaxConcurrentRequests) {
        $Config.MaxConcurrentRequests = $MaxConcurrentRequests
    }
    elseif (!$Config.MaxConcurrentRequests) {
        $Config.MaxConcurrentRequests = ([Environment]::ProcessorCount * 2)
    }

    if ($MaxQueueSize) {
        $Config.MaxQueueSize = $MaxQueueSize
    }
    elseif (!$Config.MaxQueueSize) {
        $Config.MaxQueueSize = 1000
    }

    if ($MultipartThreshold) {
        $Config.MultipartThreshold = $MultipartThreshold
    }
    elseif (!$Config.MultipartThreshold) {
        $Config.MultipartThreshold = "8MB"
    }

    if ($MultipartChunksize) {
        $Config.MultipartChunksize = $MultipartChunksize
    }

    if ($MaxBandwidth) {
        $Config.MaxBandwidth = $MaxBandwidth
    }

    if ($UseAccelerateEndpoint) {
        $Config.UseAccelerateEndpoint = ([System.Convert]::ToBoolean($UseAccelerateEndpoint))
    }
    elseif ($null -eq $Config.UseAccelerateEndpoint) {
        $Config.UseAccelerateEndpoint = $false
    }

    if ($UseDualstackEndpoint) {
        $Config.UseDualstackEndpoint = ([System.Convert]::ToBoolean($UseDualstackEndpoint))
    }
    elseif ($null -eq $Config.UseDualstackEndpoint) {
        $Config.UseDualstackEndpoint = $false
    }

    if ($AddressingStyle) {
        $Config.AddressingStyle = $AddressingStyle
    }
    elseif (!$Config.AddressingStyle) {
        $Config.AddressingStyle = "auto"
    }

    if ($PayloadSigning) {
        $Config.PayloadSigning = $PayloadSigning
    }
    elseif (!$Config.PayloadSigning) {
        $Config.PayloadSigning = "auto"
    }

    if (!$Config.SkipCertificateCheck -and $SkipCertificateCheck) {
        $Config.SkipCertificateCheck = ([System.Convert]::ToBoolean($SkipCertificateCheck))
    }
    elseif ($SkipCertificateCheck -eq $null) {
        $Config.SkipCertificateCheck = $false
    }

    if ($SignerType) {
        $Config.SignerType = $SignerType
    }
    elseif (!$Config.SignerType) {
        $Config.SignerType = "AWS4"
    }

    if ($RetryCount) {
        $Config | Add-Member -MemberType NoteProperty -Name RetryCount -Value $RetryCount -Force
    }

    if ($MaxRetries) {
        $Config.MaxRetries = $MaxRetries
    }
    elseif (!$Config.MaxRetries) {
        $Config.MaxRetries = $MAX_RETRIES
    }

    if ($LogPath) {
        $Config.LogPath = [System.IO.DirectoryInfo]$LogPath
    }

    if ($LogLevel) {
        $Config.LogLevel = $LogLevel
    }

    if ($RecordPath) {
        $Config | Add-Member -MemberType NoteProperty -Name RecordPath -Value ([System.IO.DirectoryInfo]$RecordPath)
        if ($RecordMode) {
            $Config | Add-Member -MemberType NoteProperty -Name RecordMode -Value $RecordMode
        }
    }

    if ($Config.AccessKey -and $Config.SecretKey) {
        Write-Output $Config
    }
}

Set-Alias -Name Remove-AwsProfile -Value Remove-AwsConfig
Set-Alias -Name Remove-AwsCredential -Value Remove-AwsConfig
<#
    .SYNOPSIS
    Remove AWS Config
    .DESCRIPTION
    Remove AWS Config
    .PARAMETER ProfileName
    AWS Profile to use which contains AWS sredentials and settings
    .PARAMETER ProfileLocation
    AWS Profile location if different than .aws/credentials
#>
function Global:Remove-AwsConfig {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory = $True,
            Position = 0,
            HelpMessage = "AWS Profile where config should be removed")][Alias("Profile")][String]$ProfileName,
        [parameter(
            Mandatory = $False,
            Position = 1,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation = $AWS_CREDENTIALS_FILE
    )

    Write-Log -Level Verbose -Config $Config -Message "Remove AWS config"

    $ConfigLocation = $ProfileLocation -replace "credentials$", 'config'

    $Credentials = ConvertFrom-AwsConfigFile -AwsConfigFile $ProfileLocation
    $Credentials = $Credentials | Where-Object { $_.ProfileName -ne $ProfileName }
    ConvertTo-AwsConfigFile -Config $Credentials -AwsConfigFile $ProfileLocation

    $Configs = ConvertFrom-AwsConfigFile -AwsConfigFile $ConfigLocation
    $Configs = $Configs | Where-Object { $_.ProfileName -ne $ProfileName }
    ConvertTo-AwsConfigFile -Config $Configs -AwsConfigFile $ConfigLocation
}

Set-Alias -Name Add-AwsPolicyStatement -Value New-AwsPolicy
Set-Alias -Name New-IamPolicy -Value New-AwsPolicy
Set-Alias -Name Add-IamPolicyStatement -Value New-AwsPolicy
Set-Alias -Name New-S3BucketPolicy -Value New-AwsPolicy
Set-Alias -Name Add-S3BucketPolicyStatement -Value New-AwsPolicy
<#
    .SYNOPSIS
    Create new AWS Policy
    .DESCRIPTION
    Create new AWS Policy
    .PARAMETER PolicyString
    S3 Bucket Policy to add statements to
    .PARAMETER Sid
    The Sid element is optional. The Sid is only intended as a description for the user. It is stored but not interpreted by the StorageGRID Webscale system.
    .PARAMETER Effect
    Use the Effect element to establish whether the specified operations are allowed or denied. You must identify operations you allow (or deny) on buckets or objects using the supported Action element keywords.
    .PARAMETER Principal
    Use the Principal element in a policy to specify the principal that is allowed or denied access to a resource
    .PARAMETER NotPrincipal
    Use the NotPrincipal element in a policy to specify all but the specified principal that is allowed or denied access to a resource
    .PARAMETER Resource
    The Resource element identifies buckets and objects. With it you can allow or deny permissions to buckets and objects using the uniform resource name (URN) to identify the resource.
    .PARAMETER NotResource
    The NotResource element identifies all but the specified buckets and objects. With it you can allow or deny permissions to all but the specified buckets and objects using the uniform resource name (URN) to identify the resource.
    .PARAMETER Action
    The Action element specifies a list of actions or all actions using a wildcard (e.g. s3:*).
    .PARAMETER NotAction
    The NotAction element identifies all but the specified list of actions or all actions using a wildcard (e.g. s3:*).
    .PARAMETER Condition
    The Condition element is optional. Conditions allow you to build expressions to determine when a policy should be applied.
    .PARAMETER FullAccess
    Grant full access.
    .PARAMETER ReadOnlyAccess
    Grant read only access.
    .PARAMETER DenyWriteDeleteAndPolicyChanges
    Explicitly deny write operations.
    .PARAMETER WriteOnceReadManyAccess
    Explicitly deny write operations.
#>
function Global:New-AwsPolicy {
    [CmdletBinding(DefaultParameterSetName = "PrincipalResourceAction")]

    PARAM (
        [parameter(
            Mandatory = $False,
            Position = 0,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "S3 Bucket Policy to add statements to")][Alias("BucketPolicy", "IamPolicy", "AwsPolicy", "Policy")][String]$PolicyString,
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
            HelpMessage = "Use the Principal element in a policy to specify the principal that is allowed or denied access to a resource")][PSCustomObject[]]
        [parameter(
            Mandatory = $False,
            Position = 3,
            ParameterSetName = "PrincipalResourceNotAction",
            HelpMessage = "Use the Principal element in a policy to specify the principal that is allowed or denied access to a resource")][PSCustomObject[]]
        [parameter(
            Mandatory = $False,
            Position = 3,
            ParameterSetName = "PrincipalNotResourceAction",
            HelpMessage = "Use the Principal element in a policy to specify the principal that is allowed or denied access to a resource")][PSCustomObject[]]
        [parameter(
            Mandatory = $False,
            Position = 3,
            ParameterSetName = "PrincipalNotResourceNotAction",
            HelpMessage = "Use the Principal element in a policy to specify the principal that is allowed or denied access to a resource")][PSCustomObject[]]$Principal,
        [parameter(
            Mandatory = $False,
            Position = 3,
            ParameterSetName = "NotPrincipalResourceAction",
            HelpMessage = "Use the NotPrincipal element in a policy to specify all but the specified principal that is allowed or denied access to a resource")][PSCustomObject[]]
        [parameter(
            Mandatory = $False,
            Position = 3,
            ParameterSetName = "NotPrincipalResourceNotAction",
            HelpMessage = "Use the NotPrincipal element in a policy to specify all but the specified principal that is allowed or denied access to a resource")][PSCustomObject[]]
        [parameter(
            Mandatory = $False,
            Position = 3,
            ParameterSetName = "NotPrincipalNotResourceAction",
            HelpMessage = "Use the NotPrincipal element in a policy to specify all but the specified principal that is allowed or denied access to a resource")][PSCustomObject[]]
        [parameter(
            Mandatory = $False,
            Position = 3,
            ParameterSetName = "NotPrincipalNotResourceNotAction",
            HelpMessage = "Use the NotPrincipal element in a policy to specify all but the specified principal that is allowed or denied access to a resource")][PSCustomObject[]]$NotPrincipal,
        [parameter(
            Mandatory = $False,
            Position = 4,
            ParameterSetName = "PrincipalResourceAction",
            HelpMessage = "The Resource element identifies buckets and objects. With it you can allow or deny permissions to buckets and objects using the uniform resource name (URN) to identify the resource.")][System.UriBuilder[]]
        [parameter(
            Mandatory = $False,
            Position = 4,
            ParameterSetName = "PrincipalResourceNotAction",
            HelpMessage = "The Resource element identifies buckets and objects. With it you can allow or deny permissions to buckets and objects using the uniform resource name (URN) to identify the resource.")][System.UriBuilder[]]
        [parameter(
            Mandatory = $False,
            Position = 4,
            ParameterSetName = "NotPrincipalResourceAction",
            HelpMessage = "The Resource element identifies buckets and objects. With it you can allow or deny permissions to buckets and objects using the uniform resource name (URN) to identify the resource.")][System.UriBuilder[]]
        [parameter(
            Mandatory = $False,
            Position = 4,
            ParameterSetName = "NotPrincipalResourceNotAction",
            HelpMessage = "The Resource element identifies buckets and objects. With it you can allow or deny permissions to buckets and objects using the uniform resource name (URN) to identify the resource.")][System.UriBuilder[]]$Resource = "arn:aws:s3:::*",
        [parameter(
            Mandatory = $False,
            Position = 4,
            ParameterSetName = "PrincipalNotResourceAction",
            HelpMessage = "The NotResource element identifies all but the specified buckets and objects. With it you can allow or deny permissions to all but the specified buckets and objects using the uniform resource name (URN) to identify the resource.")][System.UriBuilder[]]
        [parameter(
            Mandatory = $False,
            Position = 4,
            ParameterSetName = "PrincipalNotResourceNotAction",
            HelpMessage = "The NotResource element identifies all but the specified buckets and objects. With it you can allow or deny permissions to all but the specified buckets and objects using the uniform resource name (URN) to identify the resource.")][System.UriBuilder[]]
        [parameter(
            Mandatory = $False,
            Position = 4,
            ParameterSetName = "NotPrincipalNotResourceAction",
            HelpMessage = "The NotResource element identifies all but the specified buckets and objects. With it you can allow or deny permissions to all but the specified buckets and objects using the uniform resource name (URN) to identify the resource.")][System.UriBuilder[]]
        [parameter(
            Mandatory = $False,
            Position = 4,
            ParameterSetName = "NotPrincipalNotResourceNotAction",
            HelpMessage = "The NotResource element identifies all but the specified buckets and objects. With it you can allow or deny permissions to all but the specified buckets and objects using the uniform resource name (URN) to identify the resource.")][System.UriBuilder[]]$NotResource,
        [parameter(
            Mandatory = $False,
            Position = 5,
            ParameterSetName = "PrincipalResourceAction",
            HelpMessage = "The Action element identifies a list of actions or all actions using a wildcard (e.g. s3:*).")][String[]]
        [parameter(
            Mandatory = $False,
            Position = 5,
            ParameterSetName = "PrincipalNotResourceAction",
            HelpMessage = "The Action element identifies a list of actions or all actions using a wildcard (e.g. s3:*).")][String[]]
        [parameter(
            Mandatory = $False,
            Position = 5,
            ParameterSetName = "NotPrincipalResourceAction",
            HelpMessage = "The Action element identifies a list of actions or all actions using a wildcard (e.g. s3:*).")][String[]]
        [parameter(
            Mandatory = $False,
            Position = 5,
            ParameterSetName = "NotPrincipalNotResourceAction",
            HelpMessage = "The Action element identifies a list of actions or all actions using a wildcard (e.g. s3:*).")][String[]]$Action = "s3:*",
        [parameter(
            Mandatory = $False,
            Position = 5,
            ParameterSetName = "PrincipalResourceNotAction",
            HelpMessage = "The NotAction element identifies all but the specified list of actions or all actions using a wildcard (e.g. s3:*).")][String[]]
        [parameter(
            Mandatory = $False,
            Position = 5,
            ParameterSetName = "PrincipalNotResourceNotAction",
            HelpMessage = "The NotAction element identifies all but the specified list of actions or all actions using a wildcard (e.g. s3:*).")][String[]]
        [parameter(
            Mandatory = $False,
            Position = 5,
            ParameterSetName = "NotPrincipalResourceNotAction",
            HelpMessage = "The NotAction element identifies all but the specified list of actions or all actions using a wildcard (e.g. s3:*).")][String[]]
        [parameter(
            Mandatory = $False,
            Position = 5,
            ParameterSetName = "NotPrincipalNotResourceNotAction",
            HelpMessage = "The NotAction element identifies all but the specified list of actions or all actions using a wildcard (e.g. s3:*).")][String[]]$NotAction,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "The Condition element is optional. Conditions allow you to build expressions to determine when a policy should be applied.")][PSObject]$Condition,
        [parameter(
            Mandatory = $False,
            Position = 7,
            HelpMessage = "Grant full access.")][Switch]$FullAccess,
        [parameter(
            Mandatory = $False,
            Position = 8,
            HelpMessage = "Grant read only access.")][Switch]$ReadOnlyAccess,
        [parameter(
            Mandatory = $False,
            Position = 9,
            HelpMessage = "Explicitly deny write operations.")][Switch]$DenyWriteDeleteAndPolicyChanges,
        [parameter(
            Mandatory = $False,
            Position = 10,
            HelpMessage = "Explicitly deny write operations.")][Alias("WormAccess")][Switch]$WriteOnceReadManyAccess
    )

    Write-Log -Level Verbose -Config $Config -Message "Create or add to AWS Policy"

    # see https://docs.aws.amazon.com/AmazonS3/latest/dev/access-policy-language-overview.html for details on Policies

    if ($CurrentSgwServer -and ($Resource -match "arn:aws" -or $NotResource -match "arn:aws") -or $Principal.Keys -match 'SGWS') {
        Write-Log -Level Warning -Config $Config -Message "Resource starts with arn:aws:"
        Write-Log -Level Warning -Config $Config -Message "If the policy is created for an S3 service different than AWS (e.g. StorageGRID 11.1 and earlier),the Resource may need to be specified as:"
        if ($Resource) {
            foreach ($WrongResource in $Resource) {
                Write-Log -Level Warning -Config $Config -Message $($WrongResource.Uri.OriginalString -replace "arn:aws:", "urn:sgws:")
            }
        }
        else {
            foreach ($WrongNotResource in $NotResource) {
                Write-Log -Level Warning -Config $Config -Message $($WrongNotResource.Uri.OriginalString -replace "arn:aws:", "urn:sgws:")
            }
        }
    }

    if ($FullAccess.IsPresent) {
        $Effect = "Allow"
        $Action = "s3:*"
    }

    if (!$PolicyString) {
        $Policy = [PSCustomObject]@{ Version = "2012-10-17"; Statement = @() }
    }
    else {
        $Policy = ConvertFrom-Json -InputObject $PolicyString
        $Statement = $Policy.Statement | Select-Object -First 1
        $Policy.Statement = $Policy.Statement | Select-Object -Skip 1
    }

    if (!$Statement) {
        $Statement = @{Effect = $Effect }
    }

    if (!$Statement.Sid -and $Sid) {
        $Statement.Sid = $Sid
    }

    if (!$Statement.Principal -and $Principal) {
        # if everyone should be authorized (*) an array is not allowed in the policy
        if ($Principal -eq "*") {
            $Statement.Principal = $Principal[0]
        }
        else {
            $Statement.Principal = $Principal
        }
    }
    if (!$Statement.NotPrincipal -and $NotPrincipal) {
        if ($NotPrincipal -eq "*") {
            $Statement.NotPrincipal = $NotPrincipal[0]
        }
        else {
            $Statement.NotPrincipal = Principal
        }
    }
    if (!$Statement.Resource -and $Resource) {
        $Statement.Resource = $Resource.Uri.AbsoluteUri
    }
    if (!$Statement.NotResource -and $NotResource) {
        $Statement.NotResource = $NotResource.Uri.AbsoluteUri
    }
    if (!$Statement.Action -and $Action) {
        $Statement.Action = $Action
    }
    if (!$Statement.NotAction -and $NotAction) {
        $Statement.NotAction = $NotAction
    }
    if (!$Statement.Condition -and $Condition) {
        $Statement.Condition = $Condition
    }

    if ($ReadOnlyAccess.IsPresent) {
        $Effect = "Allow"
        if ($Principal) {
            # StorageGRID does not allow the full set of actions to be specified, therefore we need to differentiate
            if ($Resource -match "aws") {
                $Statement.Action = @("s3:ListBucket", "s3:ListBucketVersions", "s3:ListBucketMultipartUploads", "s3:ListMultipartUploadParts", "s3:GetAccelerateConfiguration", "s3:GetAnalyticsConfiguration", "s3:GetBucketAcl", "s3:GetBucketCORS", "s3:GetBucketLocation", "s3:GetBucketLogging", "s3:GetBucketNotification", "s3:GetBucketPolicy", "s3:GetBucketRequestPayment", "s3:GetBucketTagging", "s3:GetBucketVersioning", "s3:GetBucketWebsite", "s3:GetInventoryConfiguration", "s3:GetIpConfiguration", "s3:GetLifecycleConfiguration", "s3:GetMetricsConfiguration", "s3:GetObject", "s3:GetObjectAcl", "s3:GetObjectTagging", "s3:GetObjectTorrent", "s3:GetObjectVersion", "s3:GetObjectVersionAcl", "s3:GetObjectVersionForReplication", "s3:GetObjectVersionTagging", "s3:GetObjectVersionTorrent", "s3:GetReplicationConfiguration")
            }
            else {
                $Statement.Action = @("s3:ListBucket", "s3:ListBucketVersions", "s3:ListBucketMultipartUploads", "s3:ListMultipartUploadParts", "s3:GetBucketCORS", "s3:GetBucketLocation", "s3:GetBucketNotification", "s3:GetBucketPolicy", "s3:GetBucketVersioning", "s3:GetObject", "s3:GetObjectAcl", "s3:GetObjectTagging", "s3:GetObjectVersion", "s3:GetObjectVersionAcl", "s3:GetObjectVersionTagging", "s3:GetReplicationConfiguration")
            }
        }
        else {
            # StorageGRID does not allow the full set of actions to be specified, therefore we need to differentiate
            if ($Resource -match "aws") {
                $Statement.Action = @("s3:ListBucket", "s3:ListBucketVersions", "s3:ListAllMyBuckets", "s3:ListBucketMultipartUploads", "s3:ListMultipartUploadParts", "s3:GetAccelerateConfiguration", "s3:GetAnalyticsConfiguration", "s3:GetBucketAcl", "s3:GetBucketCORS", "s3:GetBucketLocation", "s3:GetBucketLogging", "s3:GetBucketNotification", "s3:GetBucketPolicy", "s3:GetBucketRequestPayment", "s3:GetBucketTagging", "s3:GetBucketVersioning", "s3:GetBucketWebsite", "s3:GetInventoryConfiguration", "s3:GetIpConfiguration", "s3:GetLifecycleConfiguration", "s3:GetMetricsConfiguration", "s3:GetObject", "s3:GetObjectAcl", "s3:GetObjectTagging", "s3:GetObjectTorrent", "s3:GetObjectVersion", "s3:GetObjectVersionAcl", "s3:GetObjectVersionForReplication", "s3:GetObjectVersionTagging", "s3:GetObjectVersionTorrent", "s3:GetReplicationConfiguration")
            }
            else {
                $Statement.Action = @("s3:ListBucket", "s3:ListBucketVersions", "s3:ListAllMyBuckets", "s3:ListBucketMultipartUploads", "s3:ListMultipartUploadParts", "s3:GetBucketCORS", "s3:GetBucketLocation", "s3:GetBucketNotification", "s3:GetBucketPolicy", "s3:GetBucketVersioning", "s3:GetObject", "s3:GetObjectAcl", "s3:GetObjectTagging", "s3:GetObjectVersion", "s3:GetObjectVersionAcl", "s3:GetObjectVersionTagging", "s3:GetReplicationConfiguration")
            }
        }
    }

    if ($DenyWriteDeleteAndPolicyChanges.IsPresent) {
        $Effect = "Deny"
        # StorageGRID does not allow the full set of actions to be specified, therefore we need to differentiate
        if ($Resource -match "aws") {
            $Statement.Action = @("s3:AbortMultipartUpload", "s3:DeleteObject", "s3:DeleteObjectTagging", "s3:DeleteObjectVersion", "s3:DeleteObjectVersionTagging", "s3:PutObject", "s3:PutObjectAcl", "s3:PutObjectTagging", "s3:PutObjectVersionAcl", "s3:PutObjectVersionTagging", "s3:RestoreObject", "s3:CreateBucket", "s3:DeleteBucket", "s3:DeleteBucketPolicy", "s3:DeleteBucketWebsite", "s3:PutAccelerateConfiguration", "s3:PutAnalyticsConfiguration", "s3:PutBucketAcl", "s3:PutBucketCORS", "s3:PutBucketLogging", "s3:PutBucketNotification", "s3:PutBucketPolicy", "s3:PutBucketRequestPayment", "s3:PutBucketTagging", "s3:PutBucketVersioning", "s3:PutBucketWebsite", "s3:PutEncryptionConfiguration", "s3:PutInventoryConfiguration", "s3:PutLifecycleConfiguration", "s3:PutMetricsConfiguration", "s3:PutReplicationConfiguration")
        }
        else {
            $Statement.Action = @("s3:AbortMultipartUpload", "s3:DeleteObject", "s3:DeleteObjectTagging", "s3:DeleteObjectVersion", "s3:DeleteObjectVersionTagging", "s3:PutObject", "s3:PutObjectTagging", "s3:PutObjectVersionTagging", "s3:CreateBucket", "s3:DeleteBucket", "s3:DeleteBucketPolicy", "s3:PutBucketCORS", "s3:PutBucketLogging", "s3:PutBucketNotification", "s3:PutBucketPolicy", "s3:PutBucketTagging", "s3:PutBucketVersioning", "s3:PutReplicationConfiguration")
        }
    }

    if ($WriteOnceReadManyAccess) {
        $Statement.Effect = "Allow"
        $Statement.Action = "s3:*"
        $Policy.Statement += $Statement.PSObject.Copy()
        $Statement.Effect = "Deny"
        # StorageGRID does not allow the full set of actions to be specified, therefore we need to differentiate
        if ($Resource -match "aws") {
            Write-Log -Level Warning -Config $Config -Message "Not supported by AWS!"
        }
        $Statement.Action = @("s3:PutOverwriteObject", "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy")
    }

    $Policy.Statement += $Statement

    # convert to JSON
    $PolicyString = ConvertTo-Json -InputObject $Policy -Depth 10

    Write-Output $PolicyString
}

### S3 Cmdlets ###

## Buckets ##

New-Alias -Name Get-S3Bucket -Value Get-S3Buckets
<#
    .SYNOPSIS
    Get S3 Buckets
    .DESCRIPTION
    Get S3 Buckets
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket name
#>
function Global:Get-S3Buckets {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            Mandatory = $False,
            Position = 2,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            Mandatory = $False,
            Position = 3,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Bucket name")][Alias("Name", "Bucket")][String]$BucketName
    )

    Begin {
        trap { Write-Log -Level Critical -Config $Config -ErrorRecord $_ }

        if (!$Config) {
            $Config = Get-AwsConfig -Server $Global:CurrentSgwServer -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccountId $AccountId
        }

        $Method = "GET"
    }

    Process {
        trap { Write-Log -Level Critical -Config $Config -ErrorRecord $_ }

        Write-Log -Level Verbose -Config $Config -Message "Retrieving all buckets"

        # the following ensures that the StorageGRID AccountID is picked up from the pipeline
        if ($AccountId -and $Global:CurrentSgwServer) {
            $Config = $Config | Get-AwsConfig -Server $Global:CurrentSgwServer -AccountId $AccountId
        }

        if ($Config.AccessKey) {
            $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign
            if ($DryRun.IsPresent) {
                Write-Output $AwsRequest
            }
            else {
                $Task = $AwsRequest | Invoke-AwsRequest
                $Result = Test-AwsResponse -Task $Task -Config $Config

                switch ($Result.Status) {
                    "SUCCESS" {
                        if ($Task.Result.Content.Headers.ContentType -notmatch "application/xml") {
                            Throw "Response content type is $($Task.Result.Content.Headers.ContentType), but expecting application/xml"
                        }
                        $Content = $Task.Result.Content.ReadAsStringAsync().Result
                        Write-Log -Level DEBUG -Config $Config -Message "Response content:`n$Content"
                        $Xml = [System.Xml.XmlDocument]$Content

                        if ($Xml.ListAllMyBucketsResult) {
                            if ($BucketName) {
                                $XmlBuckets = $Xml.ListAllMyBucketsResult.Buckets.ChildNodes | Where-Object { $_.Name -eq (ConvertTo-Punycode -Config $Config -BucketName $BucketName) }
                            }
                            else {
                                $XmlBuckets = $Xml.ListAllMyBucketsResult.Buckets.ChildNodes
                            }

                            $Tasks = New-Object -TypeName System.Collections.ArrayList
                            $AwsRequestQueue = New-Object -TypeName System.Collections.Queue

                            foreach ($XmlBucket in $XmlBuckets) {
                                $UnicodeBucketName = ConvertFrom-Punycode -BucketName $XmlBucket.Name
                                # ensure that we keep uppercase letters
                                if ($UnicodeBucketName -eq $XmlBucket.Name) {
                                    $UnicodeBucketName = $XmlBucket.Name
                                }
                                $Bucket = [PSCustomObject]@{
                                    BucketName = $UnicodeBucketName
                                    CreationDate = $XmlBucket.CreationDate
                                    OwnerId = $Xml.ListAllMyBucketsResult.Owner.ID
                                    OwnerDisplayName = $Xml.ListAllMyBucketsResult.Owner.DisplayName
                                    Region = $Location
                                }

                                $AwsRequest= $Bucket | Get-S3BucketLocation -Config $Config -Presign:$Presign -DryRun
                                $AwsRequest | Add-Member -MemberType NoteProperty -Name Bucket -Value $Bucket
                                $AwsRequestQueue.Enqueue($AwsRequest)
                            }

                            while ($AwsRequestQueue.Count -gt 0 -or $Tasks.Count -gt 0) {
                                if ($AwsRequestQueue.Count -gt 0 -and $Tasks.Count -lt $Config.MaxConcurrentRequests) {
                                    $AwsRequest = $AwsRequestQueue.Dequeue()
                                    $Task = $AwsRequest | Invoke-AwsRequest
                                    $Task | Add-Member -MemberType NoteProperty -Name Bucket -Value $AwsRequest.Bucket
                                    $null = $Tasks.Add($Task)
                                }

                                $CompletedTasks = $Tasks | Where-Object { $_.IsCompleted }
                                foreach ($Task in $CompletedTasks) {
                                    $Result = Test-AwsResponse -Task $Task -Config $Config
                                    switch ($Result.Status) {
                                        "SUCCESS" {
                                            # PowerShell does not correctly parse Unicode content, therefore assuming Unicode encoding and parsing ourself
                                            $Content = [System.Xml.XmlDocument]$Task.Result.Content.ReadAsStringAsync().Result

                                            if (!$Content.GetElementsByTagName("LocationConstraint").InnerText) {
                                                # if no location is returned, bucket is in default region us-east-1
                                                $Task.Bucket.Region = "us-east-1"
                                            }
                                            else {
                                                $Task.Bucket.Region = $Content.GetElementsByTagName("LocationConstraint").InnerText
                                            }
                                            Write-Output $Task.Bucket
                                        }
                                        "RETRY" {
                                            $RetryTask = $Task.Bucket | Get-S3BucketLocation -AccessKey $Config.AccessKey -SecretKey $Config.SecretKey -EndpointUrl $Config.EndpointUrl -Presign:$Presign -DryRun
                                            $AwsRequest | Add-Member -MemberType NoteProperty -Name Bucket -Value $Task.Bucket
                                            $Tasks.Add($RetryTask)
                                        }
                                        "FAILED" {
                                            Write-Log -Level Warning -Config $Config -Message $Result.Message
                                            Throw $Task.Exception
                                        }
                                        default {
                                            Throw $Result.Message
                                        }
                                    }
                                    $Tasks.Remove($Task)
                                }

                                Start-Sleep -Milliseconds 10
                            }
                        }
                    }
                    "RETRY" {
                        Get-S3Buckets -Config $Config -Presign:$Presign -BucketName $BucketName
                    }
                    "FAILED" {
                        Write-Log -Level Warning -Config $Config -Message $Result.Message
                        Throw $Task.Exception
                    }
                    default {
                        Throw $Result.Message
                    }
                }
            }
        }
        elseif ($Server.SupportedApiVersions -match "1" -and !$Server.AccountId -and !$AccountId -and $Server.S3EndpointUrl -and !$Server.DisableAutomaticAccessKeyGeneration) {
            Write-Log -Level Information -Config $Config -Message "No config provided, but connected to StorageGRID Webscale. Therefore retrieving all buckets of all tenants."
            $Accounts = Get-SgwAccounts -Capabilities "s3"
            foreach ($Account in $Accounts) {
                $Config = $Config | Get-AwsConfig -Server $Global:CurrentSgwServer -AccountId $Account.Id
                Get-S3Buckets -Config $Config -Presign:$Presign -DryRun:$DryRun
            }
        }
        else {
            Throw "No S3 credentials found"
        }
    }
}

<#
    .SYNOPSIS
    Test if S3 Bucket exists
    .DESCRIPTION
    Test if S3 Bucket exists
    .PARAMETER ProfileName
    AWS Profile to use which contains AWS sredentials and settings
    .PARAMETER ProfileLocation
    AWS Profile location if different than .aws/credentials
    .PARAMETER AccountId
    StorageGRID account ID to execute this command against
    .PARAMETER Config
    AWS config
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER CheckAllRegions
    Check all regions - by default only the specified region (or us-east-1 if no region is specified) will be checked.
    .PARAMETER Force
    Force check of specified bucketname and do not convert it to IDN compatible string
#>
function Global:Test-S3Bucket {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            Mandatory = $False,
            Position = 2,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            Mandatory = $False,
            Position = 3,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $True,
            Position = 6,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Check all regions - by default only the specified region (or us-east-1 if no region is specified) will be checked.")][Switch]$CheckAllRegions,
        [parameter(
            Mandatory = $False,
            Position = 9,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Force check of specified bucketname and do not convert it to IDN compatible string")][Switch]$Force
    )

    Begin {
        trap { Write-Log -Level Critical -Config $Config -ErrorRecord $_ }

        if (!$Config) {
            $Config = Get-AwsConfig -Server $Global:CurrentSgwServer -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccountId $AccountId
        }

        $Method = "HEAD"
    }

    Process {
        trap { Write-Log -Level Critical -Config $Config -ErrorRecord $_ }

        Write-Log -Level Verbose -Config $Config -Message "Test if bucket $BucketName exists"

        # the following ensures that the StorageGRID AccountID is picked up from the pipeline
        if ($AccountId -and $Global:CurrentSgwServer) {
            $Config = $Config | Get-AwsConfig -Server $Global:CurrentSgwServer -AccountId $AccountId
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        if ($Force.IsPresent) {
            $Config.AddressingStyle = "path"
        }
        else {
            $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName
        }

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName
        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest
            $Result = Test-AwsResponse -Task $Task -Config $Config

            switch ($Result.Status) {
                "SUCCESS" {
                    Write-Output $true
                }
                "RETRY" {
                    Test-S3Bucket -Config $Config -Presign:$Presign -RetryCount $Result.RetryCount -BucketName $BucketName -CheckAllRegions:$CheckAllRegions -Force:$Force
                }
                "FAILED" {
                    Write-Log -Level Warning -Config $Config -Message $Result.Message
                    Throw $Task.Exception
                }
                "REDIRECTED" {
                    if ($CheckAllRegions) {
                        Test-S3Bucket -Config $Config -Presign:$Presign -Region $Result.RedirectedRegion -BucketName $BucketName -Force:$Force
                    }
                }
                default {
                    Write-Output $false
                }
            }
        }
    }
}

<#
    .SYNOPSIS
    Create S3 Bucket
    .DESCRIPTION
    Create S3 Bucket
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER CannedAclName
    Canned ACL
    .PARAMETER PublicReadOnly
    If set, applies an ACL making the bucket public with read-only permissions
    .PARAMETER PublicReadWrite
    If set, applies an ACL making the bucket public with read-write permissions
    .PARAMETER PublicReadOnlyPolicy
    If set, applies a Bucket Policy making the bucket public with read-only permissions
    .PARAMETER PublicReadWritePolicy
    If set, applies a Bucket Policy making the bucket public with read-write permissions
    .PARAMETER Force
    Parameter is only used for compatibility with AWS Cmdlets and will be ignored
#>
function Global:New-S3Bucket {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            Mandatory = $False,
            Position = 2,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            Mandatory = $False,
            Position = 3,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $True,
            Position = 6,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $False,
            Position = 8,
            HelpMessage = "Canned ACL")][Alias("CannedAcl", "Acl")][String][ValidateSet("private", "public-read", "public-read-write", "aws-exec-read", "authenticated-read", "bucket-owner-read", "bucket-owner-full-control")]$CannedAclName,
        [parameter(
            Mandatory = $False,
            Position = 9,
            HelpMessage = "Allows grantee to list the objects in the bucket.")][String]$AclGrantRead,
        [parameter(
            Mandatory = $False,
            Position = 10,
            HelpMessage = "Allows grantee to create, overwrite, and delete any object in the bucket.")][String]$AclGrantWrite,
        [parameter(
            Mandatory = $False,
            Position = 11,
            HelpMessage = "Allows grantee to read the bucket ACL.")][String]$AclGrantReadAcp,
        [parameter(
            Mandatory = $False,
            Position = 12,
            HelpMessage = "Allows grantee to write the ACL for the applicable bucket.")][String]$AclGrantWriteAcp,
        [parameter(
            Mandatory = $False,
            Position = 13,
            HelpMessage = "Allows grantee the READ, WRITE, READ_ACP, and WRITE_ACP permissions on the bucket.")][String]$AclGrantFullControl,
        [parameter(
            Mandatory = $False,
            Position = 14,
            HelpMessage = "If set, applies a Bucket Policy making the bucket public with read-only permissions")][Switch]$PublicReadOnlyPolicy,
        [parameter(
            Mandatory = $False,
            Position = 15,
            HelpMessage = "If set, applies a Bucket Policy making the bucket public with read-write permissions")][Switch]$PublicReadWritePolicy,
        [parameter(
            Mandatory = $False,
            Position = 16,
            HelpMessage = "Parameter is only used for compatibility with AWS Cmdlets and will be ignored")][Switch]$Force
    )

    Begin {
        trap { Write-Log -Level Critical -Config $Config -ErrorRecord $_ }

        if (!$Config) {
            $Config = Get-AwsConfig -Server $Global:CurrentSgwServer -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccountId $AccountId
        }

        $Method = "PUT"
    }

    Process {
        trap { Write-Log -Level Critical -Config $Config -ErrorRecord $_ }

        Write-Log -Level Verbose -Config $Config -Message "Creating bucket $BucketName"

        # the following ensures that the StorageGRID AccountID is picked up from the pipeline
        if ($AccountId -and $Global:CurrentSgwServer) {
            $Config = $Config | Get-AwsConfig -Server $Global:CurrentSgwServer -AccountId $AccountId
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        # AWS does not allow to set LocationConstraint for default region us-east-1
        if ($Config.Region -ne "us-east-1") {
            $RequestPayload = "<CreateBucketConfiguration xmlns=`"http://s3.amazonaws.com/doc/2006-03-01/`"><LocationConstraint>$($Config.Region)</LocationConstraint></CreateBucketConfiguration>"
        }

        $PunycodeBucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName -SkipTest

        if ($PunycodeBucketName -ne $BucketName -and $Config.EndpointUrl -match $DEFAULT_AWS_ENDPOINT) {
            $Message = "Since February 2020 AWS does not support names of new buckets to contain special characters (e.g. IDN or Punycode encoded starting with xn--). See https://docs.aws.amazon.com/AmazonS3/latest/dev/BucketRestrictions.html#bucketnamingrules for details."
            throw $Message
        }
        else {
            $BucketName = $PunycodeBucketName
        }

        $Headers = @{ }
        if ($CannedAclName) {
            $Headers["x-amz-acl"] = $CannedAclName
        }
        if ($AclGrantRead) {
            $Headers["x-amz-grant-read"] = $AclGrantRead
        }
        if ($AclGrantWrite) {
            $Headers["x-amz-grant-write"] = $AclGrantWrite
        }
        if ($AclGrantReadAcp) {
            $Headers["x-amz-grant-read-acp"] = $AclGrantReadAcp
        }
        if ($AclGrantWriteAcp) {
            $Headers["x-amz-grant-write-acp"] = $AclGrantWriteAcp
        }
        if ($AclGrantFullControl) {
            $Headers["x-amz-grant-full-control"] = $l
        }

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Headers $Headers -RequestPayload $RequestPayload

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest
            $Result = Test-AwsResponse -Task $Task -Config $Config

            switch ($Result.Status) {
                "SUCCESS" {
                    Write-Log -Level Verbose -Config $Config -Message "Bucket $BucketName successfully created"
                }
                "RETRY" {
                    New-S3Bucket -Config $Config -Presign:$Presign -BucketName $BucketName -CannedAclName $CannedAclName -AclGrantRead $AclGrantRead -AclGrantWrite $AclGrantWrite -AclGrantReadAcp $AclGrantReadAcp -AclGrantWriteAcp $AclGrantWriteAcp -AclGrantFullControl $AclGrantFullControl -PublicReadOnlyPolicy:$PublicReadOnlyPolicy -PublicReadWritePolicy:$PublicReadWritePolicy -Force:$Force
                }
                "FAILED" {
                    Write-Log -Level Warning -Config $Config -Message $Result.Message
                    Throw $Task.Exception
                }
                default {
                    Throw $Result.Message
                }
            }

            if ($PublicReadOnlyPolicy) {
                Set-S3BucketPolicy -Config $Config -BucketName $BucketName -PublicReadOnlyPolicy
            }
            if ($PublicReadWritePolicy) {
                Set-S3BucketPolicy -Config $Config -BucketName $BucketName -PublicReadWritePolicy
            }
        }
    }
}

<#
    .SYNOPSIS
    Remove S3 Bucket
    .DESCRIPTION
    Remove S3 Bucket
    .PARAMETER ProfileName
    AWS Profile to use which contains AWS sredentials and settings
    .PARAMETER ProfileLocation
    AWS Profile location if different than .aws/credentials
    .PARAMETER AccountId
    StorageGRID account ID to execute this command against
    .PARAMETER Config
    AWS config
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER Force
    If set, all remaining objects and/or object versions in the bucket are deleted proir to the bucket itself being deleted
#>
function Global:Remove-S3Bucket {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            Mandatory = $False,
            Position = 2,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            Mandatory = $False,
            Position = 3,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $True,
            Position = 6,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $False,
            Position = 8,
            HelpMessage = "If set, all remaining objects and/or object versions in the bucket are deleted proir to the bucket itself being deleted.")][Alias("DeleteBucketContent")][Switch]$Force
    )

    Begin {
        trap { Write-Log -Level Critical -Config $Config -ErrorRecord $_ }

        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "DELETE"
    }

    Process {
        Write-Log -Level Verbose -Config $Config -Message "Delete bucket $BucketName"

        # the following ensures that the StorageGRID AccountID is picked up from the pipeline
        if ($AccountId -and $Global:CurrentSgwServer) {
            $Config = $Config | Get-AwsConfig -Server $Global:CurrentSgwServer -AccountId $AccountId
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        if ($Force -or $DeleteBucketContent) {
            Write-Log -Level Verbose -Config $Config -Message "Force parameter specified, removing all objects and object versions in the bucket before removing the bucket"
            try {
                $BucketVersioningEnabledOrSuspended = Get-S3BucketVersioning -Config $Config -BucketName $BucketName -Region $Region
                if ($BucketVersioningEnabledOrSuspended) {
                    Get-S3ObjectVersions -Config $Config -BucketName $BucketName -Region $Region | Remove-S3Object -Config $Config
                }
            }
            catch {
            }
            Get-S3Objects -Config $Config -BucketName $BucketName -Region $Region | Remove-S3Object -Config $Config
        }

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest
            $Result = Test-AwsResponse -Task $Task -Config $Config

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            switch ($Result.Status) {
                "SUCCESS" {
                    Write-Log -Level Verbose -Config $Config -Message "Bucket $BucketName successfully removed"
                }
                "RETRY" {
                    Remove-S3Bucket -Config $Config -Presign:$Presign -BucketName $BucketName -Force:$Force
                }
                "FAILED" {
                    Write-Log -Level Warning -Config $Config -Message $Result.Message
                    Throw $Task.Exception
                }
                "CONFLICT" {
                    Throw "Bucket not empty. Please delete all objects and object versions or use -Force parameter."
                }
                default {
                    Throw $Result.Message
                }
            }
        }
    }
}

<#
    .SYNOPSIS
    Retrieve Bucket Encryption
    .DESCRIPTION
    Retrieve Bucket Encryption
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
#>
function Global:Get-S3BucketEncryption {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "GET"
    }

    Process {
        Write-Verbose "Retrieve bucket encryption for bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $Query = @{encryption = "" }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Query $Query

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                $Content = [XML]$Task.Result.Content.ReadAsStringAsync().Result

                foreach ($Rule in $Content.ServerSideEncryptionConfiguration.Rule) {
                    $Output = [PSCustomObject]@{SSEAlgorithm=$Rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm;
                                KMSMasterKeyID=$Rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID}
                    Write-Output $Output
                }
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Get-S3BucketEncryption -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Get-S3BucketEncryption -Config $Config -Presign:$Presign -Region $($RedirectedRegion[0]) -BucketName $BucketName
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message -match "The server side encryption configuration was not found") {
                    # do nothing
                }
                elseif ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

<#
    .SYNOPSIS
    Set Bucket Encryption
    .DESCRIPTION
    Set Bucket Encryption
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER SSEAlgorithm
    The server-side encryption algorithm to use.
    .PARAMETER KMSMasterKeyID
    The AWS KMS master key ID used for the SSE-KMS encryption.
#>
function Global:Set-S3BucketEncryption {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $True,
            Position = 11,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "The server-side encryption algorithm to use.")][ValidateSet("AES256", "aws:kms")][String]$SSEAlgorithm,
        [parameter(
            Mandatory = $False,
            Position = 12,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "The AWS KMS master key ID used for the SSE-KMS encryption.")][System.UriBuilder]$KMSMasterKeyID
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "PUT"
    }

    Process {
        Write-Verbose "Set encryption for bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $Query = @{encryption = "" }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $Body = "<ServerSideEncryptionConfiguration xmlns=`"http://s3.amazonaws.com/doc/2006-03-01/`">"
        $Body += "<Rule>"
        $Body += "<ApplyServerSideEncryptionByDefault>"
        $Body += "<SSEAlgorithm>$SSEAlgorithm</SSEAlgorithm>"
        if ($KMSMasterKeyID) {
            $Body += "<KMSMasterKeyID>$KMSMasterKeyID</KMSMasterKeyID>"
        }
        $Body += "</ApplyServerSideEncryptionByDefault>"
        $Body += "</Rule>"
        $Body += "</ServerSideEncryptionConfiguration>"

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Query $Query -RequestPayload $Body

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck -Body $Body

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                $Content = [XML]$Task.Result.Content.ReadAsStringAsync().Result

                foreach ($Rule in $Content.ServerSideEncryptionConfiguration.Rule) {
                    $Output = [PSCustomObject]@{SSEAlgorithm = $Rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm;
                        KMSMasterKeyID                       = $Rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID
                    }
                    Write-Output $Output
                }
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Set-S3BucketEncryption -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName -SSEAlgorithm $SSEAlgorithm -KMSMasterKeyID $KMSMasterKeyID
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Set-S3BucketEncryption -Config $Config -Presign:$Presign -Region $($RedirectedRegion[0]) -BucketName $BucketName -SSEAlgorithm $SSEAlgorithm -KMSMasterKeyID $KMSMasterKeyID
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

<#
    .SYNOPSIS
    Remove Bucket Encryption
    .DESCRIPTION
    Remove Bucket Encryption
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
#>
function Global:Remove-S3BucketEncryption {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "DELETE"
    }

    Process {
        Write-Verbose "Remove encryption for bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $Query = @{encryption = "" }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Query $Query

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck -Body $Body

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                # do nothing
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Remove-S3BucketEncryption -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Remove-S3BucketEncryption -Config $Config -Presign:$Presign -Region $($RedirectedRegion[0]) -BucketName $BucketName
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

Set-Alias -Name Get-S3BucketCorsConfigurationRule -Value Get-S3BucketCorsConfiguration
Set-Alias -Name Get-S3BucketCors -Value Get-S3BucketCorsConfiguration
Set-Alias -Name Get-S3CORSConfiguration -Value Get-S3BucketCorsConfiguration
<#
    .SYNOPSIS
    Retrieve Bucket CORS Configuration
    .DESCRIPTION
    Retrieve Bucket CORS Configuration
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER Id
    A unique identifier for the rule.
#>
function Global:Get-S3BucketCorsConfiguration {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $False,
            Position = 9,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "A unique identifier for the rule.")][ValidateLength(1, 255)][String]$Id
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "GET"
    }

    Process {
        Write-Verbose "Get CORS configuration for bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $Query = @{cors = "" }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Query $Query

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck -Body $Body

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                $Content = [XML]$Task.Result.Content.ReadAsStringAsync().Result

                foreach ($Rule in $Content.CORSConfiguration.CORSRule) {
                    $Output = [PSCustomObject]@{
                        BucketName    = $BucketName
                        Id            = $Rule.Id
                        AllowedMethod = $Rule.AllowedMethod
                        AllowedOrigin = $Rule.AllowedOrigin
                        AllowedHeader = $Rule.AllowedHeader
                        MaxAgeSeconds = $Rule.MaxAgeSeconds
                        ExposeHeader  = $Rule.ExposeHeader
                    }
                    if (!$Id -or ($Id -and $Output.Id -match $Id)) {
                        Write-Output $Output
                    }
                }
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Get-S3BucketCorsConfiguration -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName -Id $Id
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Get-S3BucketCorsConfiguration -Config $Config -Presign:$Presign -Region $($RedirectedRegion[0]) -BucketName $BucketName -Id $Id
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message -match "The CORS configuration does not exist") {
                    # do nothing
                }
                elseif ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

Set-Alias -Name Add-S3BucketCorsConfiguration -Value Add-S3BucketCorsConfigurationRule
Set-Alias -Name Write-S3CorsConfiguration -Value Add-S3BucketCorsConfigurationRule
Set-Alias -Name Add-S3BucketCorsRule -Value Add-S3BucketCorsConfigurationRule
<#
    .SYNOPSIS
    Add Bucket CORS Configuration Rule
    .DESCRIPTION
    Add Bucket CORS Configuration Rule
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER Id
    A unique identifier for the rule.
    .PARAMETER AllowedMethods
    The HTTP methods the origin shall be allowed to execute.
    .PARAMETER AllowedOrigins
    Origins which shall be allowed to execute.
    .PARAMETER AllowedHeaders
    Specifies which headers are allowed in a pre-flight OPTIONS request via the Access-Control-Request-Headers header.
    .PARAMETER MaxAgeSeconds
    The time in seconds that the browser is to cache the preflight response for the specified resource.
    .PARAMETER ExposeHeaders
    One or more headers in the response that the client is able to access from his applications (for example, from a JavaScript XMLHttpRequest object).
#>
function Global:Add-S3BucketCorsConfigurationRule {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $False,
            Position = 9,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "A unique identifier for the rule.")][ValidateLength(1, 255)][String]$Id,
        [parameter(
            Mandatory = $True,
            Position = 10,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "The HTTP methods the origin shall be allowed to execute.")][ValidateSet("GET", "PUT", "HEAD", "POST", "DELETE")][Alias("AllowedMethod")][String[]]$AllowedMethods,
        [parameter(
            Mandatory = $True,
            Position = 11,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Origins which shall be allowed to execute.")][Alias("AllowedOrigin")][String[]]$AllowedOrigins,
        [parameter(
            Mandatory = $False,
            Position = 12,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Specifies which headers are allowed in a pre-flight OPTIONS request via the Access-Control-Request-Headers header.")][Alias("AllowedHeader")][String[]]$AllowedHeaders,
        [parameter(
            Mandatory = $False,
            Position = 13,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "The time in seconds that the browser is to cache the preflight response for the specified resource.")][Int]$MaxAgeSeconds,
        [parameter(
            Mandatory = $False,
            Position = 14,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "One or more headers in the response that the client is able to access from his applications (for example, from a JavaScript XMLHttpRequest object).")][Alias("ExposeHeader")][String[]]$ExposeHeaders
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "PUT"
    }

    Process {
        Write-Verbose "Add CORS configuration rule for bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        # AWS requires that this request uses payload signing
        $Config.PayloadSigning = $true

        $Query = @{cors = "" }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $CorsConfigurationRules = @()

        $CorsConfigurationRules += Get-S3BucketCorsConfiguration -Config $Config -BucketName $BucketName

        $CorsConfigurationRule = [PSCustomObject]@{
            ID            = $Id
            AllowedMethod = $AllowedMethods
            AllowedOrigin = $AllowedOrigins
            AllowedHeader = $AllowedHeaders
            MaxAgeSeconds = $MaxAgeSeconds
            ExposeHeader  = $ExposeHeaders
        }

        $CorsConfigurationRules += $CorsConfigurationRule

        $Body = "<CORSConfiguration>"
        foreach ($CorsConfigurationRule in $CorsConfigurationRules) {
            $Body += "<CORSRule>"
            if ($CorsConfigurationRule.Id) {
                $Body += "<ID>$($CorsConfigurationRule.Id)</ID>"
            }
            foreach ($AllowedMethod in $CorsConfigurationRule.AllowedMethod) {
                $Body += "<AllowedMethod>$AllowedMethod</AllowedMethod>"
            }
            foreach ($AllowedOrigin in $CorsConfigurationRule.AllowedOrigin) {
                $Body += "<AllowedOrigin>$AllowedOrigin</AllowedOrigin>"
            }
            foreach ($AllowedHeader in $CorsConfigurationRule.AllowedHeader) {
                $Body += "<AllowedHeader>$AllowedHeader</AllowedHeader>"
            }
            if ($MaxAgeSeconds) {
                $Body += "<MaxAgeSeconds>$($CorsConfigurationRule.MaxAgeSeconds)</MaxAgeSeconds>"
            }
            foreach ($ExposeHeader in $CorsConfigurationRule.ExposeHeader) {
                $Body += "<ExposeHeader>$ExposeHeader</ExposeHeader>"
            }
            $Body += "</CORSRule>"
        }
        $Body += "</CORSConfiguration>"

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Query $Query -RequestPayload $Body

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck -Body $Body

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                # do nothing
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Add-S3BucketCorsConfigurationRule -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName -Id $Id -AllowedMethods $AllowedMethods -AllowedOrigins $AllowedOrigins -AllowedHeaders $AllowedHeaders -MaxAgeSeconds $MaxAgeSeconds -ExposeHeaders $ExposeHeaders
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Add-S3BucketCorsConfigurationRule -Config $Config -Presign:$Presign -Region $($RedirectedRegion[0]) -BucketName $BucketName  -Id $Id -AllowedMethods $AllowedMethods -AllowedOrigins $AllowedOrigins -AllowedHeaders $AllowedHeaders -MaxAgeSeconds $MaxAgeSeconds -ExposeHeaders $ExposeHeaders
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

<#
    .SYNOPSIS
    Remove Bucket CORS Configuration Rule
    .DESCRIPTION
    Remove Bucket CORS Configuration Rule
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER Id
    A unique identifier for the rule.
#>
function Global:Remove-S3BucketCorsConfigurationRule {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $True,
            Position = 9,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "A unique identifier for the rule.")][ValidateLength(1, 255)][String]$Id
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
    }

    Process {
        Write-Verbose "Remove CORS configuration rule with ID $Id from bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        # get all rules
        $CorsConfigurationRules = Get-S3BucketCorsConfiguration -Config $Config -BucketName $BucketName

        if (!($CorsConfigurationRules | Where-Object { $_.Id -eq $Id })) {
            Write-Warning "CORS Configuration Rule ID $Id does not exist"
            break
        }

        # remove the rule with the specified ID
        $CorsConfigurationRules = $CorsConfigurationRules | Where-Object { $_.Id -ne $Id }

        Remove-S3BucketCorsConfiguration -Config $Config -BucketName $BucketName

        # write all rules
        $CorsConfigurationRules | Add-S3BucketCorsConfigurationRule -Config $Config -BucketName $BucketName
    }
}

Set-Alias -Name Remove-S3BucketCors -Value Remove-S3BucketCorsConfiguration
Set-Alias -Name Remove-S3CORSConfiguration -Value Remove-S3BucketCorsConfiguration
<#
    .SYNOPSIS
    Remove Bucket CORS Configuration
    .DESCRIPTION
    Remove Bucket CORS Configuration
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
#>
function Global:Remove-S3BucketCorsConfiguration {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "DELETE"
    }

    Process {
        Write-Verbose "Remove CORS configuration from bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $Query = @{cors = "" }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Query $Query

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck -Body $Body

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                # do nothing
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Remove-S3BucketCorsConfiguration -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Remove-S3BucketCorsConfiguration -Config $Config -Presign:$Presign -Region $($RedirectedRegion[0]) -BucketName $BucketName
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

Set-Alias -Name Get-S3BucketReplicationConfigurationRule -Value Get-S3BucketReplicationConfiguration
Set-Alias -Name Get-S3BucketReplication -Value Get-S3BucketReplicationConfiguration
Set-Alias -Name Get-S3ReplicationConfiguration -Value Get-S3BucketReplicationConfiguration
<#
    .SYNOPSIS
    Retrieve Bucket Replication Configuration
    .DESCRIPTION
    Retrieve Bucket Replication Configuration
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER Id
    A unique identifier for the rule.
#>
function Global:Get-S3BucketReplicationConfiguration {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $False,
            Position = 9,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "A unique identifier for the rule.")][ValidateLength(1, 255)][String]$Id
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "GET"
    }

    Process {
        Write-Verbose "Get bucket replication configuration for bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $Query = @{replication = "" }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Query $Query

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck -Body $Body

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                $Content = [XML]$Task.Result.Content.ReadAsStringAsync().Result

                foreach ($Rule in $Content.ReplicationConfiguration.Rule) {
                    $Output = [PSCustomObject]@{
                        BucketName              = ConvertFrom-Punycode -BucketName $BucketName
                        Role                    = $Content.ReplicationConfiguration.Role
                        Id                      = $Rule.Id
                        Status                  = $Rule.Status
                        Prefix                  = $Rule.Prefix
                        DestinationBucketName   = ConvertFrom-Punycode -BucketName ($Rule.Destination.Bucket -replace ".*:::", "")
                        DestinationStorageClass = $Rule.Destination.StorageClass
                        DestinationAccount      = $Rule.Destination.Account
                        DestinationOwner        = $Rule.Destination.AccessControlTranslation.Owner
                    }
                    if (!$Id -or ($Id -and $Output.Id -match $Id)) {
                        Write-Output $Output
                    }
                }
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Get-S3BucketReplicationConfiguration -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName -Id $Id
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Get-S3BucketReplicationConfiguration -Config $Config -Presign:$Presign -Region $($RedirectedRegion[0]) -BucketName $BucketName  -Id $Id
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message -match "The replication configuration was not found" -or $Result.Error.Message -match "The specified bucket does not have bucket replication configured") {
                    # do nothing
                }
                elseif ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

Set-Alias -Name Add-S3BucketReplicationConfiguration -Value Add-S3BucketReplicationConfigurationRule
Set-Alias -Name Write-S3ReplicationConfiguration -Value Add-S3BucketReplicationConfigurationRule
Set-Alias -Name Add-S3BucketReplicationRule -Value Add-S3BucketReplicationConfigurationRule
<#
    .SYNOPSIS
    Add Bucket Replication Configuration Rule
    .DESCRIPTION
    Add Bucket Replication Configuration Rule
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER Id
    A unique identifier for the rule.
    .PARAMETER Role
    IAM role that Amazon S3 can assume when replicating the objects.
    .PARAMETER Status
    The rule is ignored if status is not set to Enabled.
    .PARAMETER Prefix
    Object key name prefix that identifies one or more objects to which the rule applies. Maximum prefix length is 1,024 characters. Prefixes can't overlap.
    .PARAMETER DestinationBucketUrn
    URN or ARN of the bucket where you want store replicas of the object identified by the rule (for AWS it is arn:aws:s3:::<destination-bucket> for StorageGRID it is urn:sgws:s3:::<destination-bucket> ).
    .PARAMETER DestinationBucketName
    Destination bucket name where the objects should be replicated to. Can only be used if the Destination Bucket is in the same Object Store as the Bucket to replicate.
    .PARAMETER DestinationStorageClass
    Optional destination storage class override to use when replicating objects. If a storage class is not specified, Amazon S3 uses the storage class of the source object to create object replicas.
    .PARAMETER DestinationAccount
    Account ID of the destination bucket owner. In a cross-account scenario, if you tell Amazon S3 to change replica ownership to the AWS account that owns the destination bucket by adding the AccessControlTranslation element, this is the account ID of the destination bucket owner.
    .PARAMETER DestinationOwner
    Identifies the replica owner.
#>
function Global:Add-S3BucketReplicationConfigurationRule {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $False,
            Position = 9,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "A unique identifier for the rule.")][ValidateLength(1, 255)][String]$Id,
        [parameter(
            Mandatory = $False,
            Position = 10,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "IAM role that Amazon S3 can assume when replicating the objects.")][String]$Role,
        [parameter(
            Mandatory = $False,
            Position = 11,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "The rule is ignored if status is not set to Enabled.")][ValidateSet("Enabled", "Disabled")][String]$Status = "Enabled",
        [parameter(
            Mandatory = $False,
            Position = 12,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Object key name prefix that identifies one or more objects to which the rule applies. Maximum prefix length is 1,024 characters. Prefixes can't overlap.")][ValidateLength(1, 255)][String]$Prefix,
        [parameter(
            Mandatory = $False,
            Position = 13,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "URN or ARN of the bucket where you want store replicas of the object identified by the rule (for AWS it is arn:aws:s3:::<destination-bucket> for StorageGRID it is urn:sgws:s3:::<destination-bucket> ).")][Alias("DestinationBucketArn")][System.UriBuilder]$DestinationBucketUrn,
        [parameter(
            Mandatory = $False,
            Position = 14,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Destination bucket name where the objects should be replicated to. Can only be used if the Destination Bucket is in the same Object Store as the Bucket to replicate.")][Alias("DestinationBucket")][String]$DestinationBucketName,
        [parameter(
            Mandatory = $False,
            Position = 15,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Optional destination storage class override to use when replicating objects. If a storage class is not specified, Amazon S3 uses the storage class of the source object to create object replicas.")][ValidateSet("STANDARD", "STANDARD_IA", "ONEZONE_IA", "REDUCED_REDUNDANCY")][String]$DestinationStorageClass,
        [parameter(
            Mandatory = $False,
            Position = 16,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Account ID of the destination bucket owner. In a cross-account scenario, if you tell Amazon S3 to change replica ownership to the AWS account that owns the destination bucket by adding the AccessControlTranslation element, this is the account ID of the destination bucket owner.")][String]$DestinationAccount,
        [parameter(
            Mandatory = $False,
            Position = 17,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Identifies the replica owner.")][String]$DestinationOwner
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "PUT"
    }

    Process {
        Write-Verbose "Add bucket replication configuration rule for bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        # AWS requires that this request has Content-MD5 sum, therefore enforcing PayloadSigning
        $Config.PayloadSigning = $True

        $Query = @{replication = "" }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        if ($DestinationBucketName) {
            # Convert Destination Bucket Name to IDN mapping to support Unicode Names
            $DestinationBucketName = ConvertTo-Punycode -Config $Config -BucketName $DestinationBucketName
        }

        if ($DestinationBucketUrn) {
            $DestinationBucketName = $DestinationBucketUrn.Uri.ToString() -replace ".*:.*:.*:.*:.*:(.*)", '$1'
            # Convert Destination Bucket Name to IDN mapping to support Unicode Names
            $DestinationBucketName = ConvertTo-Punycode -Config $Config -BucketName $DestinationBucketName
            $DestinationBucketUrnPrefix = $DestinationBucketUrn.Uri.ToString() -replace "(.*:.*:.*:.*:.*:).*", '$1'
            $DestinationBucketUrn = [System.UriBuilder]"$DestinationBucketUrnPrefix$DestinationBucketName"
        }

        $ReplicationConfigurationRules = @()

        $ReplicationConfigurationRules += Get-S3BucketReplicationConfiguration -Config $Config -BucketName $BucketName

        $ReplicationConfigurationRule = [PSCustomObject]@{
            ID                      = $Id
            Role                    = $Role
            Status                  = $Status
            Prefix                  = $Prefix
            DestinationBucketName   = $DestinationBucketName
            DestinationStorageClass = $DestinationStorageClass
            DestinationAccount      = $DestinationAccount
            DestinationOwner        = $DestinationOwner
        }

        $ReplicationConfigurationRules += $ReplicationConfigurationRule

        $Body = "<ReplicationConfiguration>"
        if ($Role) {
            $Body += "<Role>$Role</Role>"
        }
        foreach ($ReplicationConfigurationRule in $ReplicationConfigurationRules) {
            if (!$DestinationBucketUrn) {
                $DestinationBucketUrn = "arn:aws:s3:::$($ReplicationConfigurationRule.DestinationBucketName)"
            }

            $Body += "<Rule>"
            if ($ReplicationConfigurationRule.Id) {
                $Body += "<ID>$($ReplicationConfigurationRule.Id)</ID>"
            }
            $Body += "<Status>$($ReplicationConfigurationRule.Status)</Status>"
            $Body += "<Prefix>$($ReplicationConfigurationRule.Prefix)</Prefix>"
            $Body += "<Destination>"
            $Body += "<Bucket>$($DestinationBucketUrn)</Bucket>"
            if ($ReplicationConfigurationRule.StorageClass) {
                $Body += "<StorageClass>$($ReplicationConfigurationRule.StorageClass)</StorageClass>"
            }
            if ($ReplicationConfigurationRule.Account) {
                $Body += "<Account>$($ReplicationConfigurationRule.Account)</Account>"
            }
            if ($ReplicationConfigurationRule.Owner) {
                $Body += "<AccessControlTranslation><Owner>$($ReplicationConfigurationRule.Account)</Owner></AccessControlTranslation>"
            }
            $Body += "</Destination>"
            $Body += "</Rule>"
        }
        $Body += "</ReplicationConfiguration>"

        Write-Verbose "Body:`n$Body"

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Query $Query -RequestPayload $Body

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck -Body $Body

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                # do nothing
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Add-S3BucketReplicationConfigurationRule -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName -Id $Id -Role $Role -Status $Status -Prefix $Prefix -DestinationBucketUrn $DestinationBucketUrn -DestinationBucketName $DestinationBucketName -DestinationStorageClass $DestinationStorageClass -DestinationAccount $DestinationAccount -DestinationOwner $DestinationOwner
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Add-S3BucketReplicationConfigurationRule -Config $Config -Presign:$Presign -Region $($RedirectedRegion[0]) -BucketName $BucketName  -Id $Id -Role $Role -Status $Status -Prefix $Prefix -DestinationBucketUrn $DestinationBucketUrn -DestinationBucketName $DestinationBucketName -DestinationStorageClass $DestinationStorageClass -DestinationAccount $DestinationAccount -DestinationOwner $DestinationOwner
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

<#
    .SYNOPSIS
    Remove Bucket Replication Configuration Rule
    .DESCRIPTION
    Remove Bucket Replication Configuration Rule
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER Id
    A unique identifier for the rule.
#>
function Global:Remove-S3BucketReplicationConfigurationRule {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $True,
            Position = 9,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "A unique identifier for the rule.")][ValidateLength(1, 255)][String]$Id
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
    }

    Process {
        Write-Verbose "Remove bucket replication configuration rule for bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        # get all rules
        $ReplicationConfigurationRules = Get-S3BucketReplicationConfiguration -Config $Config -BucketName $BucketName

        if (!($ReplicationConfigurationRules | Where-Object { $_.Id -eq $Id })) {
            Write-Warning "Replication Configuration Rule ID $Id does not exist"
            break
        }

        # remove the rule with the specified ID
        $ReplicationConfigurationRules = $ReplicationConfigurationRules | Where-Object { $_.Id -ne $Id }

        Remove-S3BucketReplicationConfiguration -Config $Config -BucketName $BucketName

        # write all rules
        $ReplicationConfigurationRules | Add-S3BucketCorsConfigurationRule -Config $Config -BucketName $BucketName
    }
}

Set-Alias -Name Remove-S3BucketReplication -Value Remove-S3BucketReplicationConfiguration
Set-Alias -Name Remove-S3ReplicationConfiguration -Value Remove-S3BucketReplicationConfiguration
<#
    .SYNOPSIS
    Remove Bucket Replication Configuration
    .DESCRIPTION
    Remove Bucket Replication Configuration
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
#>
function Global:Remove-S3BucketReplicationConfiguration {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "DELETE"
    }

    Process {
        Write-Verbose "Remove bucket replication configuration for bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $Query = @{replication = "" }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Query $Query

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck -Body $Body

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                # do nothing
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Remove-S3BucketReplicationConfiguration -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Remove-S3BucketReplicationConfiguration -Config $Config -Presign:$Presign -Region $($RedirectedRegion[0]) -BucketName $BucketName
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

Set-Alias -Name Get-S3BucketSearchConfigurationRule -Value Get-S3BucketSearchConfiguration
Set-Alias -Name Get-S3BucketMetadataNotificationConfigurationRule -Value Get-S3BucketSearchConfiguration
Set-Alias -Name Get-S3SearchConfiguration -Value Get-S3BucketSearchConfiguration
Set-Alias -Name Get-S3MetadataNotificationConfiguration -Value Get-S3BucketSearchConfiguration
<#
    .SYNOPSIS
    Retrieve Bucket Search Configuration
    .DESCRIPTION
    Retrieve Bucket Search Configuration
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER Id
    A unique identifier for the rule.
#>
function Global:Get-S3BucketSearchConfiguration {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $False,
            Position = 9,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "A unique identifier for the rule.")][ValidateLength(1, 255)][String]$Id
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "GET"
    }

    Process {
        Write-Verbose "Get bucket search configuration for bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $Query = @{"x-ntap-sg-metadata-notification" = "" }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Query $Query

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck -Body $Body

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                $Content = [XML]$Task.Result.Content.ReadAsStringAsync().Result

                foreach ($Rule in $Content.MetadataNotificationConfiguration.Rule) {
                    $Output = [PSCustomObject]@{
                        BucketName              = ConvertFrom-Punycode -BucketName $BucketName
                        Id                      = $Rule.Id
                        Status                  = $Rule.Status
                        Prefix                  = $Rule.Prefix
                        DestinationUrn          = $Rule.Destination.Urn
                    }
                    if (!$Id -or ($Id -and $Output.Id -match $Id)) {
                        Write-Output $Output
                    }
                }
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Get-S3BucketSearchConfiguration -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName -Id $Id
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Get-S3BucketSearchConfiguration -Config $Config -Presign:$Presign -Region $($RedirectedRegion[0]) -BucketName $BucketName  -Id $Id
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message -match "The replication configuration was not found" -or $Result.Error.Message -match "The specified bucket does not have bucket replication configured") {
                    # do nothing
                }
                elseif ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

Set-Alias -Name Add-S3BucketSearchConfiguration -Value Add-S3BucketSearchConfigurationRule
Set-Alias -Name Write-S3BucketMetadataNotificationConfiguration -Value Add-S3BucketSearchConfigurationRule
Set-Alias -Name Add-S3BucketSearchRule -Value Add-S3BucketSearchConfigurationRule
Set-Alias -Name Add-S3BucketMetadataNotificationRule -Value Add-S3BucketSearchConfigurationRule
<#
    .SYNOPSIS
    Add Bucket Replication Configuration Rule
    .DESCRIPTION
    Add Bucket Replication Configuration Rule
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER Id
    A unique identifier for the rule.
    .PARAMETER Status
    The rule is ignored if status is not set to Enabled
    .PARAMETER Prefix
    Object key name prefix that identifies one or more objects to which the rule applies. Maximum prefix length is 1,024 characters. Prefixes can't overlap.
    .PARAMETER DestinationUrn
    URN of the ElasticSearch Instance including domain and index (for AWS ElasticSearch the format is arn:aws:es:region:account-ID:domain/mydomain/myindex/mytype else it is urn:mysite:es:::mydomain/myindex/mytype).
#>
function Global:Add-S3BucketSearchConfigurationRule {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory=$False,
            Position=11,
            ValueFromPipelineByPropertyName=$True,
            HelpMessage="A unique identifier for the rule.")][ValidateLength(1,255)][String]$Id,
        [parameter(
            Mandatory=$False,
            Position=13,
            ValueFromPipelineByPropertyName=$True,
            HelpMessage="The rule is ignored if status is not set to Enabled.")][ValidateSet("Enabled","Disabled")][String]$Status="Enabled",
        [parameter(
            Mandatory=$False,
            Position=14,
            ValueFromPipelineByPropertyName=$True,
            HelpMessage="Object key name prefix that identifies one or more objects to which the rule applies. Maximum prefix length is 1,024 characters. Prefixes can't overlap.")][ValidateLength(1,255)][String]$Prefix,
        [parameter(
            Mandatory=$True,
            Position=15,
            ValueFromPipelineByPropertyName=$True,
            HelpMessage="URN of the ElasticSearch Instance including domain and index (for AWS ElasticSearch the format is arn:aws:es:region:account-ID:domain/mydomain/myindex/mytype else it is urn:mysite:es:::mydomain/myindex/mytype).")][System.UriBuilder]$DestinationUrn
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "PUT"
    }

    Process {
        Write-Verbose "Add bucket search configuration rule for bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $Query = @{"x-ntap-sg-metadata-notification" = "" }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $SearchConfigurationRules = @()

        $SearchConfigurationRules += Get-S3BucketSearchConfiguration -Config $Config -BucketName $BucketName

        $SearchConfigurationRule = [PSCustomObject]@{
            ID                      = $Id
            Status                  = $Status
            Prefix                  = $Prefix
            DestinationUrn          = $DestinationUrn
        }

        $SearchConfigurationRules += $SearchConfigurationRule

        $Body = "<MetadataNotificationConfiguration>"
        if ($Role) {
            $Body += "<Role>$Role</Role>"
        }
        foreach ($SearchConfigurationRule in $SearchConfigurationRules) {
            $Body += "<Rule>"
            if ($SearchConfigurationRule.Id) {
                $Body += "<ID>$($SearchConfigurationRule.Id)</ID>"
            }
            $Body += "<Status>$($SearchConfigurationRule.Status)</Status>"
            $Body += "<Prefix>$($SearchConfigurationRule.Prefix)</Prefix>"
            $Body += "<Destination>"
            $Body += "<Urn>$($DestinationUrn)</Urn>"
            $Body += "</Destination>"
            $Body += "</Rule>"
        }
        $Body += "</MetadataNotificationConfiguration>"

        Write-Verbose "Body:`n$Body"

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Query $Query -RequestPayload $Body

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck -Body $Body

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                # do nothing
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Add-S3BucketSearchConfigurationRule -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName -Id $Id -Status $Status -Prefix $Prefix -DestinationUrn $DestinationUrn
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Add-S3BucketSearchConfigurationRule -Config $Config -Presign:$Presign -Region $($RedirectedRegion[0]) -BucketName $BucketName -Id $Id -Status $Status -Prefix $Prefix -DestinationUrn $DestinationUrn
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

<#
    .SYNOPSIS
    Remove Bucket Search Configuration Rule
    .DESCRIPTION
    Remove Bucket Search Configuration Rule
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER Id
    A unique identifier for the rule.
#>
function Global:Remove-S3BucketSearchConfigurationRule {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $True,
            Position = 9,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "A unique identifier for the rule.")][ValidateLength(1, 255)][String]$Id
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
    }

    Process {
        Write-Verbose "Remove bucket search configuration rule for bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        # get all rules
        $SearchConfigurationRules = Get-S3BucketSearchConfiguration -Config $Config -BucketName $BucketName

        if (!($SearchConfigurationRules | Where-Object { $_.Id -eq $Id })) {
            Write-Warning "Search Configuration Rule ID $Id does not exist"
            break
        }

        # remove the rule with the specified ID
        $SearchConfigurationRules = $SearchConfigurationRules | Where-Object { $_.Id -ne $Id }

        Remove-S3BucketSearchConfiguration -Config $Config -BucketName $BucketName

        # write all rules
        $SearchConfigurationRules | Add-S3BucketSearchConfigurationRule -Config $Config -BucketName $BucketName
    }
}

Set-Alias -Name Remove-S3BucketReplication -Value Remove-S3BucketReplicationConfiguration
Set-Alias -Name Remove-S3ReplicationConfiguration -Value Remove-S3BucketReplicationConfiguration
<#
    .SYNOPSIS
    Remove Bucket Search Configuration
    .DESCRIPTION
    Remove Bucket Search Configuration
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
#>
function Global:Remove-S3BucketSearchConfiguration {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "DELETE"
    }

    Process {
        Write-Verbose "Remove bucket search configuration for bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $Query = @{"x-ntap-sg-metadata-notification" = "" }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Query $Query

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck -Body $Body

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                # do nothing
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Remove-S3BucketSearchConfiguration -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Remove-S3BucketSearchConfiguration -Config $Config -Presign:$Presign -Region $($RedirectedRegion[0]) -BucketName $BucketName
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

Set-Alias -Name Get-S3BucketNotificationConfigurationRule -Value Get-S3BucketNotificationConfiguration
Set-Alias -Name Get-S3BucketNotification -Value Get-S3BucketNotificationConfiguration
Set-Alias -Name Get-S3NotificationConfiguration -Value Get-S3BucketNotificationConfiguration
<#
    .SYNOPSIS
    Retrieve Bucket Notification Configuration
    .DESCRIPTION
    Retrieve Bucket Notification Configuration
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER Id
    A unique identifier for the rule.
#>
function Global:Get-S3BucketNotificationConfiguration {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $False,
            Position = 9,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "A unique identifier for the rule.")][ValidateLength(1, 255)][String]$Id
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "GET"
    }

    Process {
        Write-Verbose "Get bucket notification configuration for bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $Query = @{"notification" = "" }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Query $Query

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck -Body $Body

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                $Content = [XML]$Task.Result.Content.ReadAsStringAsync().Result

                foreach ($Topic in $Content.NotificationConfiguration.TopicConfiguration) {
                    $Output = [PSCustomObject]@{
                        BucketName              = ConvertFrom-Punycode -BucketName $BucketName
                        Id                      = $Topic.Id
                        Prefix                  = $Topic.Filter.S3Key.FilterRule.Value
                        Topic                   = $Topic.Topic
                        Event                   = $Topic.Event
                    }
                    if (!$Id -or ($Id -and $Output.Id -match $Id)) {
                        Write-Output $Output
                    }
                }
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Get-S3BucketNotificationConfiguration -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName -Id $Id
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Get-S3BucketNotificationConfiguration -Config $Config -Presign:$Presign -Region $($RedirectedRegion[0]) -BucketName $BucketName  -Id $Id
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message -match "The replication configuration was not found" -or $Result.Error.Message -match "The specified bucket does not have bucket replication configured") {
                    # do nothing
                }
                elseif ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

Set-Alias -Name Add-S3BucketNotificationConfiguration -Value Add-S3BucketNotificationConfigurationRule
Set-Alias -Name Write-S3BucketNotificationConfiguration -Value Add-S3BucketNotificationConfigurationRule
Set-Alias -Name Add-S3BucketNotificationRule -Value Add-S3BucketNotificationConfigurationRule
<#
    .SYNOPSIS
    Add Bucket Notification Configuration Rule
    .DESCRIPTION
    Add Bucket Notification Configuration Rule
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER Id
    A unique identifier for the rule.
    .PARAMETER Status
    The rule is ignored if status is not set to Enabled
    .PARAMETER Prefix
    Object key name prefix that identifies one or more objects to which the rule applies. Maximum prefix length is 1,024 characters. Prefixes can't overlap.
    .PARAMETER Topic
    URN of the SNS topic.
    .PARAMETER Event
    Bucket event for which to send notifications (e.g. s3:ObjectCreated:* or s3:ObjectRemoved:*).
#>
function Global:Add-S3BucketNotificationConfigurationRule {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory=$False,
            Position=11,
            ValueFromPipelineByPropertyName=$True,
            HelpMessage="A unique identifier for the rule.")][ValidateLength(1,255)][String]$Id,
        [parameter(
            Mandatory=$False,
            Position=13,
            ValueFromPipelineByPropertyName=$True,
            HelpMessage="The rule is ignored if status is not set to Enabled.")][ValidateSet("Enabled","Disabled")][String]$Status="Enabled",
        [parameter(
            Mandatory=$False,
            Position=14,
            ValueFromPipelineByPropertyName=$True,
            HelpMessage="Object key name prefix that identifies one or more objects to which the rule applies. Maximum prefix length is 1,024 characters. Prefixes can't overlap.")][ValidateLength(1,255)][String]$Prefix,
        [parameter(
            Mandatory=$True,
            Position=15,
            ValueFromPipelineByPropertyName=$True,
            HelpMessage="URN of the SNS topic.")][Alias("DestinationUrn","TopicUrn")][System.UriBuilder]$Topic,
        [parameter(
            Mandatory=$True,
            Position=16,
            ValueFromPipelineByPropertyName=$True,
            HelpMessage="Bucket event for which to send notifications (e.g. s3:ObjectCreated:* or s3:ObjectRemoved:*).")][String[]]$Event
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "PUT"
    }

    Process {
        Write-Verbose "Add bucket notification configuration rule for bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $Query = @{"notification" = "" }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $NotificationConfigurationRules = @()

        $NotificationConfigurationRules += Get-S3BucketNotificationConfiguration -Config $Config -BucketName $BucketName

        $NotificationConfigurationRule = [PSCustomObject]@{
            ID                      = $Id
            Prefix                  = $Prefix
            Topic                   = $Topic
            Event                   = $Event
        }

        $NotificationConfigurationRules += $NotificationConfigurationRule

        $Body = "<NotificationConfiguration>"
        foreach ($NotificationConfigurationRule in $NotificationConfigurationRules) {
            $Body += "<TopicConfiguration>"
            if ($SearchConfigurationRule.Id) {
                $Body += "<ID>$($NotificationConfigurationRule.Id)</ID>"
            }
            if ($NotificationConfigurationRule.Prefix) {
                $Body += "<FilterRule><Name>prefix</Name><Value>$($NotificationConfigurationRule.Prefix)</Value></FilterRule>"
            }
            $Body += "<Topic>$($NotificationConfigurationRule.Topic)</Topic>"
            foreach ($Event in $NotificationConfigurationRule.Event) {
                $Body += "<Event>$($Event)</Event>"
            }
            $Body += "</TopicConfiguration>"
        }
        $Body += "</NotificationConfiguration>"

        Write-Verbose "Body:`n$Body"

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Query $Query -RequestPayload $Body

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck -Body $Body

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                # do nothing
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Add-S3BucketNotificationConfigurationRule -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName -Id $Id -Prefix $Prefix -Topic $Topic -Event $Event
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Add-S3BucketNotificationConfigurationRule -Config $Config -Presign:$Presign -Region $($RedirectedRegion[0]) -BucketName $BucketName -Id $Id -Prefix $Prefix -Topic $Topic -Event $Event
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

<#
    .SYNOPSIS
    Remove Bucket Notification Configuration Rule
    .DESCRIPTION
    Remove Bucket Notification Configuration Rule
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER Id
    A unique identifier for the rule.
#>
function Global:Remove-S3BucketNotificationConfigurationRule {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $True,
            Position = 9,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "A unique identifier for the rule.")][ValidateLength(1, 255)][String]$Id
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
    }

    Process {
        Write-Verbose "Remove bucket notification configuration rule for bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        # get all rules
        $NotificationConfigurationRules = Get-S3BucketNotificationConfiguration -Config $Config -BucketName $BucketName

        if (!($NotificationConfigurationRules | Where-Object { $_.Id -eq $Id })) {
            Write-Warning "Notification Configuration Rule ID $Id does not exist"
            break
        }

        # remove the rule with the specified ID
        $NotificationConfigurationRules = $NotificationConfigurationRules | Where-Object { $_.Id -ne $Id }

        Remove-S3BucketNotificationConfiguration -Config $Config -BucketName $BucketName

        # write all rules
        $NotificationConfigurationRules | Add-S3BucketNotificationConfigurationRule -Config $Config -BucketName $BucketName
    }
}

Set-Alias -Name Remove-S3BucketNotification -Value Remove-S3BucketNotificationConfiguration
Set-Alias -Name Remove-S3NotificationConfiguration -Value Remove-S3BucketNotificationConfiguration
<#
    .SYNOPSIS
    Remove Bucket Notification Configuration
    .DESCRIPTION
    Remove Bucket Notification Configuration
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
#>
function Global:Remove-S3BucketNotificationConfiguration {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "PUT"
    }

    Process {
        Write-Verbose "Remove bucket notification configuration for bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $Query = @{"notification"=""}

        $Body = "<NotificationConfiguration></NotificationConfiguration>"

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Query $Query -RequestPayload $Body

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck -Body $Body

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                # do nothing
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Remove-S3BucketNotificationConfiguration -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Remove-S3BucketNotificationConfiguration -Config $Config -Presign:$Presign -Region $($RedirectedRegion[0]) -BucketName $BucketName
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

<#
    .SYNOPSIS
    Get S3 Bucket Policy
    .DESCRIPTION
    Get S3 Bucket Policy
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
#>
function Global:Get-S3BucketPolicy {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "GET"
    }

    Process {
        Write-Verbose "Get bucket policy for bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $Query = @{policy = "" }

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Query $Query

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck -Body $Body

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                $Content = $Task.Result.Content.ReadAsStringAsync().Result
                # pretty print JSON
                $Policy = ConvertFrom-Json -InputObject $Content | ConvertTo-Json -Depth 10
                Write-Output $Policy
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Get-S3BucketPolicy -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Get-S3BucketPolicy -Config $Config -Presign:$Presign -Region $($RedirectedRegion[0]) -BucketName $BucketName
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message -match "The specified bucket does not have a bucket policy.") {
                    Write-Warning "The specified bucket does not have a bucket policy."
                }
                elseif ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

Set-Alias -Name Add-S3BucketPolicy -Value Set-S3BucketPolicy
Set-Alias -Name Write-S3BucketPolicy -Value Set-S3BucketPolicy
<#
    .SYNOPSIS
    Replace S3 Bucket Policy
    .DESCRIPTION
    Replace S3 Bucket Policy
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER Policy
    The bucket policy as a JSON document
    .PARAMETER PublicReadOnlyPolicy
    If set, applies a Bucket Policy making the bucket public with read-only permissions
    .PARAMETER PublicReadWritePolicy
    If set, applies a Bucket Policy making the bucket public with read-write permissions
#>
function Global:Set-S3BucketPolicy {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $False,
            Position = 9,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "The bucket policy as a JSON document")][String]$Policy = "",
        [parameter(
            Mandatory = $False,
            Position = 10,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Enable Payload Signing")][Switch]$PayloadSigning,
        [parameter(
            Mandatory = $False,
            Position = 11,
            HelpMessage = "If set, applies an ACL making the bucket public with read-only permissions")][Switch]$PublicReadOnlyPolicy,
        [parameter(
            Mandatory = $False,
            Position = 12,
            HelpMessage = "If set, applies an ACL making the bucket public with read-write permissions")][Switch]$PublicReadWritePolicy
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "PUT"
    }

    Process {
        Write-Verbose "Set bucket policy for bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $Query = @{policy = "" }

        $Resource = @("arn:aws:s3:::$BucketName", "arn:aws:s3:::$BucketName/*")

        if (!$Policy -and $PublicReadOnlyPolicy.IsPresent) {
            $Policy = New-AwsPolicy -Resource $Resource -ReadOnlyAccess -Principal "*"
        }
        if (!$Policy -and $PublicReadWritePolicy.IsPresent) {
            $Policy = New-AwsPolicy -Resource $Resource -Action "*" -Principal "*"
        }

        # pretty print JSON to simplify debugging
        $Body = ConvertFrom-Json -InputObject $Policy | ConvertTo-Json -Depth 10

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Query $Query -RequestPayload $Body

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck -Body $Body

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                $Content = $Task.Result.Content.ReadAsStringAsync().Result
                # pretty print JSON
                $Policy = ConvertFrom-Json -InputObject $Content | ConvertTo-Json -Depth 10
                Write-Output $Policy
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Set-S3BucketPolicy -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName -Policy $Policy -PublicReadOnlyPolicy:$PublicReadOnlyPolicy -PublicReadWritePolicy:$PublicReadWritePolicy
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Set-S3BucketPolicy -Config $Config -Presign:$Presign -Region $($RedirectedRegion[0]) -BucketName $BucketName  -Policy $Policy -PublicReadOnlyPolicy:$PublicReadOnlyPolicy -PublicReadWritePolicy:$PublicReadWritePolicy
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message -match "The specified bucket does not have a bucket policy.") {
                    Write-Warning "The specified bucket does not have a bucket policy."
                }
                elseif ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

<#
    .SYNOPSIS
    Remove S3 Bucket Policy
    .DESCRIPTION
    Remove S3 Bucket Policy
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
#>
function Global:Remove-S3BucketPolicy {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "DELETE"
    }

    Process {
        Write-Verbose "Remove bucket policy from bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $Query = @{policy = "" }

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Query $Query

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck -Body $Body

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                $Content = $Task.Result.Content.ReadAsStringAsync().Result
                # pretty print JSON
                $Policy = ConvertFrom-Json -InputObject $Content | ConvertTo-Json -Depth 10
                Write-Output $Policy
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Remove-S3BucketPolicy -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Remove-S3BucketPolicy -Config $Config -Presign:$Presign -Region $($RedirectedRegion[0]) -BucketName $BucketName
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message -match "The specified bucket does not have a bucket policy.") {
                    Write-Warning "The specified bucket does not have a bucket policy."
                }
                elseif ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

<#
    .SYNOPSIS
    Retrieve Bucket Tagging
    .DESCRIPTION
    Retrieve Bucket Tagging
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
#>
function Global:Get-S3BucketTagging {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "GET"
    }

    Process {
        Write-Verbose "Get bucket tagging for bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $Query = @{tagging = "" }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Query $Query

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck -Body $Body

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                $Content = [XML]$Task.Result.Content.ReadAsStringAsync().Result

                foreach ($Tag in $Content.Tagging.TagSet.Tag) {
                    $Output = [System.Collections.DictionaryEntry]@{Name = $Tag.Key; Value = $Tag.Value }
                    Write-Output $Output
                }
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Get-S3BucketTagging -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Get-S3BucketTagging -Config $Config -Presign:$Presign -Region $($RedirectedRegion[0]) -BucketName $BucketName
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

<#
    .SYNOPSIS
    Set Bucket Tagging
    .DESCRIPTION
    Set Bucket Tagging
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER Tags
    List of Name Value pairs e.g. @(@{Name='Key1';Value='Value1'},@{Name='Key1';Value='Value1'})
#>
function Global:Set-S3BucketTagging {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $True,
            Position = 9,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "List of Name Value pairs e.g. @(@{Name='Key1';Value='Value1'},@{Name='Key1';Value='Value1'})")][System.Collections.DictionaryEntry[]]$Tags
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "PUT"
    }

    Process {
        Write-Verbose "Set bucket tagging for bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        # AWS requires that this request has Content-MD5 sum, therefore enforcing PayloadSigning
        $Config.PayloadSigning = $True

        $Query = @{tagging = "" }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $Body = "<Tagging>"
        $Body += "<TagSet>"
        foreach ($Tag in $Tags) {
            $Body += "<Tag><Key>$($Tag.Name)</Key><Value>$($Tag.Value)</Value></Tag>"
        }
        $Body += "</TagSet>"
        $Body += "</Tagging>"

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Query $Query -RequestPayload $Body

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck -Body $Body

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                $Content = [XML]$Task.Result.Content.ReadAsStringAsync().Result

                foreach ($Tag in $Content.Tagging.TagSet.Tag) {
                    $Output = [System.Collections.DictionaryEntry]@{Name = $Tag.Key; Value = $Tag.Value }
                    Write-Output $Output
                }
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Set-S3BucketTagging -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName -Tags $Tags
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Set-S3BucketTagging -Config $Config -Presign:$Presign -Region $($RedirectedRegion[0]) -BucketName $BucketName -Tags $Tags
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

<#
    .SYNOPSIS
    Remove Bucket Tagging
    .DESCRIPTION
    Remove Bucket Tagging
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
#>
function Global:Remove-S3BucketTagging {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "DELETE"
    }

    Process {
        Write-Verbose "Remove bucket tagging from bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $Query = @{tagging = "" }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Query $Query

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck -Body $Body

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                $Content = [XML]$Task.Result.Content.ReadAsStringAsync().Result

                foreach ($Tag in $Content.Tagging.TagSet.Tag) {
                    $Output = [System.Collections.DictionaryEntry]@{Name = $Tag.Key; Value = $Tag.Value }
                    Write-Output $Output
                }
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Remove-S3BucketTagging -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Remove-S3BucketTagging -Config $Config -Presign:$Presign -Region $($RedirectedRegion[0]) -BucketName $BucketName
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

<#
    .SYNOPSIS
    Get S3 Bucket Versioning
    .DESCRIPTION
    Get S3 Bucket Versioning
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
#>
function Global:Get-S3BucketVersioning {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "GET"
    }

    Process {
        Write-Verbose "Retrieve versioning status for bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $Query = @{versioning = "" }

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Query $Query

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                $Content = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                Write-Output $Content.VersioningConfiguration.Status
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Get-S3BucketVersioning -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Get-S3BucketVersioning -Config $Config -Presign:$Presign -Region $($RedirectedRegion[0]) -BucketName $BucketName
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

<#
    .SYNOPSIS
    Enable S3 Bucket Versioning
    .DESCRIPTION
    Enable S3 Bucket Versioning
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
#>
function Global:Enable-S3BucketVersioning {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "PUT"
    }

    Process {
        Write-Verbose "Enable bucket versiong for bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $Query = @{versioning = "" }

        $RequestPayload = "<VersioningConfiguration xmlns=`"http://s3.amazonaws.com/doc/2006-03-01/`"><Status>Enabled</Status></VersioningConfiguration>"

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Query $Query -RequestPayload $RequestPayload

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck -Body $RequestPayload

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                $Content = [XML]$Task.Result.Content.ReadAsStringAsync().Result

                Write-Output $Content.VersioningConfiguration.Status
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Enable-S3BucketVersioning -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Enable-S3BucketVersioning -Config $Config -Presign:$Presign -Region $($RedirectedRegion[0]) -BucketName $BucketName
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

<#
    .SYNOPSIS
    Suspend S3 Bucket Versioning
    .DESCRIPTION
    Suspend S3 Bucket Versioning
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
#>
function Global:Suspend-S3BucketVersioning {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "PUT"
    }

    Process {
        Write-Verbose "Enable bucket versiong for bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $Query = @{versioning = "" }

        $RequestPayload = "<VersioningConfiguration xmlns=`"http://s3.amazonaws.com/doc/2006-03-01/`"><Status>Suspended</Status></VersioningConfiguration>"

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Query $Query -RequestPayload $RequestPayload

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck -Body $RequestPayload

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                $Content = [XML]$Task.Result.Content.ReadAsStringAsync().Result

                Write-Output $Content.VersioningConfiguration.Status
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Suspend-S3BucketVersioning -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Suspend-S3BucketVersioning -Config $Config -Presign:$Presign -Region $($RedirectedRegion[0]) -BucketName $BucketName
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

Set-Alias -Name Get-S3BucketRegion -Value Get-S3BucketLocation
<#
    .SYNOPSIS
    Get S3 Bucket Location
    .DESCRIPTION
    Get S3 Bucket Location
    .PARAMETER ProfileName
    AWS Profile to use which contains AWS sredentials and settings
    .PARAMETER ProfileLocation
    AWS Profile location if different than .aws/credentials
    .PARAMETER AccountId
    StorageGRID account ID to execute this command against
    .PARAMETER Config
    AWS config
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER BucketName
    Bucket Name
#>
function Global:Get-S3BucketLocation {
    [CmdletBinding()]

    PARAM (
        [parameter(
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            Mandatory = $False,
            Position = 2,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            Mandatory = $False,
            Position = 3,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $True,
            Position = 6,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName
    )

    Begin {
        trap { Write-Log -Level Critical -Config $Config -ErrorRecord $_ }

        if (!$Config) {
            $Config = Get-AwsConfig -Server $Global:CurrentSgwServer -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccountId $AccountId
        }

        $Method = "GET"
    }

    Process {
        trap { Write-Log -Level Critical -Config $Config -ErrorRecord $_ }

        Write-Log -Level Verbose -Config $Config -Message "Retrieving location for bucket $BucketName"

        # the following ensures that the StorageGRID AccountID is picked up from the pipeline
        if ($AccountId -and $Global:CurrentSgwServer) {
            $Config = $Config | Get-AwsConfig -Server $Global:CurrentSgwServer -AccountId $AccountId
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $Uri = "/"

        $Query = @{location = "" }

        # location requests must use path style, as virtual-host style will fail if the bucket is not in the same region as the request
        $Config.AddressingStyle = "path"
        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Query $Query

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest
            $Result = Test-AwsResponse -Task $Task -Config $Config

            switch ($Result.Status) {
                "SUCCESS" {
                    $Content = [System.Xml.XmlDocument]$Task.Result.Content.ReadAsStringAsync().Result

                    if (!$Content.GetElementsByTagName("LocationConstraint").InnerText) {
                        # if no location is returned, bucket is in default region us-east-1
                        Write-Output "us-east-1"
                    }
                    else {
                        Write-Output $Content.GetElementsByTagName("LocationConstraint").InnerText
                    }
                }
                "RETRY" {
                    Get-S3BucketLocation -Config $Config -Presign:$Presign -BucketName $BucketName
                }
                "FAILED" {
                    Write-Log -Level Warning -Config $Config -Message $Result.Message
                    Throw $Task.Exception
                }
                default {
                    Write-Output $false
                }
            }
        }
    }
}

<#
    .SYNOPSIS
    Get S3 active Multipart Uploads for Bucket
    .DESCRIPTION
    Get S3 active Multipart Uploads for Bucket
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER Prefix
    Lists in-progress uploads only for those keys that begin with the specified prefix
    .PARAMETER EncodingType
    Encoding type (Only allowed value is url).
    .PARAMETER MaxUploads
    Maximum Number of uploads to return
    .PARAMETER KeyMarker
    Continuation part number marker
    .PARAMETER UploadIdMarker
    Continuation part number marker
#>
function Global:Get-S3MultipartUploads {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $False,
            Position = 9,
            HelpMessage = "Lists in-progress uploads only for those keys that begin with the specified prefix.")][String]$Prefix,
        [parameter(
            Mandatory = $False,
            Position = 10,
            HelpMessage = "Encoding type (Only allowed value is url).")][String][ValidateSet("url")]$EncodingType = "url",
        [parameter(
            Mandatory = $False,
            Position = 11,
            HelpMessage = "Maximum Number of uploads to return")][Int][ValidateRange(0, 1000)]$MaxUploads = 0,
        [parameter(
            Mandatory = $False,
            Position = 12,
            HelpMessage = "Continuation part number marker")][String]$KeyMarker,
        [parameter(
            Mandatory = $False,
            Position = 13,
            HelpMessage = "Continuation part number marker")][String]$UploadIdMarker
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "GET"
    }

    Process {
        Write-Verbose "Get multipart uploads for bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $Query = @{uploads = "" }
        if ($EncodingType) {
            $Query["encoding-type"] = $EncodingType
        }
        if ($MaxUploads -ge 1) {
            $Query["max-uploads"] = $MaxUploads
        }
        if ($KeyMarker) {
            $Query["key-marker"] = $KeyMarker
        }
        if ($UploadIdMarker) {
            $Query["upload-id-marker"] = $UploadIdMarker
        }

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Query $Query

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck -Body $Body

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                $Content = [XML]$Task.Result.Content.ReadAsStringAsync().Result

                $UnicodeBucket = ConvertFrom-Punycode -BucketName $Content.ListMultipartUploadsResult.Bucket

                foreach ($Upload in $Content.ListMultipartUploadsResult.Upload) {
                    $Upload = [PSCustomObject]@{BucketName = $UnicodeBucket;
                        Key                                = [System.Net.WebUtility]::UrlDecode($Upload.Key);
                        UploadId                           = [System.Net.WebUtility]::UrlDecode($Upload.UploadId);
                        InitiatorId                        = [System.Net.WebUtility]::UrlDecode($Upload.Initiator.Id);
                        InitiatorDisplayName               = [System.Net.WebUtility]::UrlDecode($Upload.Initiator.DisplayName);
                        OwnerId                            = [System.Net.WebUtility]::UrlDecode($Upload.Owner.Id);
                        OwnerDisplayName                   = [System.Net.WebUtility]::UrlDecode($Upload.Owner.DisplayName);
                        StorageClass                       = [System.Net.WebUtility]::UrlDecode($Upload.StorageClass);
                        Initiated                          = [System.Net.WebUtility]::UrlDecode($Upload.Initiated)
                    }

                    Write-Output $Upload
                }

                if ($Content.ListMultipartUploadsResult.IsTruncated -eq "true" -and $MaxUploads -eq 0) {
                    Write-Verbose "1000 Uploads were returned and max uploads was not limited so continuing to get all uploads"
                    Write-Verbose "NextKeyMarker: $($Content.ListMultipartUploadsResult.NextKeyMarker)"
                    Write-Verbose "NextUploadIdMarker: $($Content.ListMultipartUploadsResult.NextUploadIdMarker)"
                    Get-S3MultipartUploads -Config $Config -BucketName $BucketName -MaxUploads $MaxUploads -KeyMarker $Content.ListMultipartUploadsResult.NextKeyMarker -UploadIdMarker $Content.ListMultipartUploadsResult.UploadIdMarker
                }
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Get-S3MultipartUploads -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName -Prefix $Prefix -EncodingType $EndpointUrl -MaxUploads $MaxUploads -KeyMarker $KeyMarker -UploadIdMarker $UploadIdMarker
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Get-S3MultipartUploads -Config $Config -Presign:$Presign -Region $($RedirectedRegion[0]) -BucketName $BucketName -Prefix $Prefix -EncodingType $EndpointUrl -MaxUploads $MaxUploads -KeyMarker $KeyMarker -UploadIdMarker $UploadIdMarker
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
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
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER MaxKeys
    Maximum Number of keys to return
    .PARAMETER Prefix
    Bucket prefix for filtering
    .PARAMETER Delimiter
    A delimiter is a character you use to group keys.
    .PARAMETER FetchOwner
    Return Owner information (Only valid for list type 2).
    .PARAMETER StartAfter
    Return key names after a specific object key in your key space. The S3 service lists objects in UTF-8 character encoding in lexicographical order (Only valid for list type 2).
    .PARAMETER Marker
    Continuation token (Only valid for list type 1).
    .PARAMETER ContinuationToken
    Continuation token (Only valid for list type 2).
    .PARAMETER EncodingType
    Encoding type (Only allowed value is url).
    .PARAMETER ListType
    Bucket list type.
#>
function Global:Get-S3Objects {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $False,
            Position = 9,
            HelpMessage = "Maximum Number of keys to return")][Int][ValidateRange(0, 1000)]$MaxKeys = 0,
        [parameter(
            Mandatory = $False,
            Position = 10,
            HelpMessage = "Bucket prefix for filtering")][Alias("Key")][String]$Prefix,
        [parameter(
            Mandatory = $False,
            Position = 11,
            HelpMessage = "A delimiter is a character you use to group keys.")][String]$Delimiter,
        [parameter(
            Mandatory = $False,
            Position = 12,
            HelpMessage = "Return Owner information (Only valid for list type 2).")][Switch]$FetchOwner = $False,
        [parameter(
            Mandatory = $False,
            Position = 13,
            HelpMessage = "Return key names after a specific object key in your key space. The S3 service lists objects in UTF-8 character encoding in lexicographical order (Only valid for list type 2).")][String]$StartAfter,
        [parameter(
            Mandatory = $False,
            Position = 14,
            HelpMessage = "Continuation token (Only valid for list type 1).")][String]$Marker,
        [parameter(
            Mandatory = $False,
            Position = 15,
            HelpMessage = "Continuation token (Only valid for list type 2).")][String]$ContinuationToken,
        [parameter(
            Mandatory = $False,
            Position = 16,
            HelpMessage = "Encoding type (Only allowed value is url).")][String][ValidateSet("url")]$EncodingType = "url",
        [parameter(
            Mandatory = $False,
            Position = 17,
            HelpMessage = "Bucket list type.")][String][ValidateSet(1, 2)]$ListType = 1
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "GET"
    }

    Process {
        Write-Verbose "Retrieve objects for bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $Query = @{ }

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

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Query $Query

        if ($DryRun) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                $Content = [XML]$Task.Result.Content.ReadAsStringAsync().Result

                $Objects = $Content.ListBucketResult.Contents | Where-Object { $_ }

                $UnicodeBucket = ConvertFrom-Punycode -BucketName $Content.ListBucketResult.Name

                foreach ($Object in $Objects) {
                    $Object = [PSCustomObject]@{
                        BucketName       = $UnicodeBucket;
                        Region           = $Config.Region;
                        Key              = [System.Net.WebUtility]::UrlDecode($Object.Key);
                        LastModified     = (Get-Date $Object.LastModified);
                        ETag             = ([System.Net.WebUtility]::UrlDecode($Object.ETag) -replace '"', '');
                        Size             = [long]$Object.Size;
                        OwnerId          = [System.Net.WebUtility]::UrlDecode($Object.Owner.ID);
                        OwnerDisplayName = [System.Net.WebUtility]::UrlDecode($Object.Owner.DisplayName);
                        StorageClass     = [System.Net.WebUtility]::UrlDecode($Object.StorageClass)
                    }
                    Write-Output $Object
                }

                if ($Content.ListBucketResult.IsTruncated -eq "true" -and $MaxKeys -eq 0) {
                    Write-Verbose "1000 Objects were returned and max keys was not limited so continuing to get all objects"
                    Write-Verbose "NextMarker: $($Content.ListBucketResult.NextMarker)"
                    Get-S3Objects -Config $Config -Presign:$Presign -BucketName $BucketName -MaxKeys $MaxKeys -Prefix $Prefix -FetchOwner:$FetchOwner -StartAfter $StartAfter -ContinuationToken $Content.ListBucketResult.NextContinuationToken -Marker $Content.ListBucketResult.NextMarker
                }
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Get-S3Objects -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName -MaxKeys $MaxKeys -Prefix $Prefix -FetchOwner:$FetchOwner -StartAfter $StartAfter -ContinuationToken $ContinuationToken -Marker $Marker
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Get-S3Objects -Config $Config -Presign:$Presign -BucketName $BucketName -Region $($RedirectedRegion[0]) -MaxKeys $MaxKeys -Prefix $Prefix -FetchOwner:$FetchOwner -StartAfter $StartAfter -ContinuationToken $ContinuationToken -Marker $Marker
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

Set-Alias -Name Get-S3BucketVersions -Value Get-S3ObjectVersions
<#
    .SYNOPSIS
    Get S3 Object Versions
    .DESCRIPTION
    Get S3 Object Versions
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER Key
    Object Key
    .PARAMETER MaxKeys
    Maximum Number of keys to return
    .PARAMETER Prefix
    Bucket prefix for filtering
    .PARAMETER Delimiter
    A delimiter is a character you use to group keys.
    .PARAMETER KeyMarker
    Continuation token for keys.
    .PARAMETER VersionIdMarker
    Specifies the object version you want to start listing from. Also, see key-marker.
    .PARAMETER EncodingType
    Encoding type (Only allowed value is url).
    .PARAMETER Type
    Version types to return
#>
function Global:Get-S3ObjectVersions {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $False,
            Position = 9,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Object Key")][Alias("Object")][String]$Key,
        [parameter(
            Mandatory = $False,
            Position = 10,
            HelpMessage = "Maximum Number of keys to return")][Int][ValidateRange(0, 1000)]$MaxKeys = 0,
        [parameter(
            Mandatory = $False,
            Position = 11,
            HelpMessage = "Bucket prefix for filtering")][String]$Prefix,
        [parameter(
            Mandatory = $False,
            Position = 12,
            HelpMessage = "Bucket prefix for filtering")][String][ValidateLength(1, 1)]$Delimiter,
        [parameter(
            Mandatory = $False,
            Position = 13,
            HelpMessage = "Continuation token for keys.")][String]$KeyMarker,
        [parameter(
            Mandatory = $False,
            Position = 14,
            HelpMessage = "Specifies the object version you want to start listing from. Also, see key-marker.")][String]$VersionIdMarker,
        [parameter(
            Mandatory = $False,
            Position = 15,
            HelpMessage = "Encoding type (Only allowed value is url).")][String][ValidateSet("url")]$EncodingType = "url",
        [parameter(
            Mandatory = $False,
            Position = 16,
            HelpMessage = "Version types to return")][String][ValidateSet("Version", "DeleteMarker")]$Type
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "GET"
    }

    Process {
        Write-Verbose "Retrieve object versions for bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $Query = @{versions = "" }

        if ($Delimiter) { $Query["delimiter"] = $Delimiter }
        if ($EncodingType) { $Query["encoding-type"] = $EncodingType }
        if ($MaxKeys -ge 1) { $Query["max-keys"] = $MaxKeys }
        if ($Key) { $Query["prefix"] = $Key }
        if ($Prefix) { $Query["prefix"] = $Prefix }
        if ($KeyMarker) { $Query["key-marker"] = $KeyMarker }
        if ($VersionIdMarker) { $Query["version-id-marker"] = $VersionIdMarker }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Query $Query

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                $Content = [XML]$Task.Result.Content.ReadAsStringAsync().Result

                $Versions = @($Content.ListVersionsResult.Version | Where-Object { $_ })
                $Versions | Add-Member -MemberType NoteProperty -Name Type -Value "Version"
                $DeleteMarkers = $Content.ListVersionsResult.DeleteMarker | Where-Object { $_ }
                $DeleteMarkers | Add-Member -MemberType NoteProperty -Name Type -Value "DeleteMarker"
                $Versions += $DeleteMarkers

                $Versions = $Versions | Sort-Object -Property Key

                if ($Key) {
                    $Versions = $Versions | Where-Object { $_.Key -eq $Key }
                }

                if ($Type) {
                    $Versions = $Versions | Where-Object { $_.Type -eq $Type }
                }

                $UnicodeBucket = ConvertFrom-Punycode -BucketName $Content.ListVersionsResult.Name

                foreach ($Version in $Versions) {
                    $Version = [PSCustomObject]@{
                        BucketName       = $UnicodeBucket;
                        Region           = $Config.Region;
                        Key              = [System.Net.WebUtility]::UrlDecode($Version.Key);
                        VersionId        = $Version.VersionId;
                        IsLatest         = [System.Convert]::ToBoolean($Version.IsLatest);
                        Type             = $Version.Type;
                        LastModified     = [DateTime]$Version.LastModified;
                        ETag             = ([System.Net.WebUtility]::UrlDecode($Version.ETag) -replace '"', '');
                        Size             = [long]$Version.Size;
                        OwnerId          = [System.Net.WebUtility]::UrlDecode($Version.Owner.ID);
                        OwnerDisplayName = [System.Net.WebUtility]::UrlDecode($Version.Owner.DisplayName);
                        StorageClass     = [System.Net.WebUtility]::UrlDecode($Version.StorageClass)
                    }
                    Write-Output $Version
                }

                if ($Content.ListVersionsResult.IsTruncated -eq "true" -and $MaxKeys -eq 0) {
                    Write-Verbose "1000 Versions were returned and max keys was not limited so continuing to get all Versions"
                    Get-S3ObjectVersions -Config $Config -Presign:$Presign -BucketName $BucketName -Key $Key -MaxKeys $MaxKeys -Prefix $Prefix -Delimiter $Delimiter -KeyMarker $Content.ListVersionsResult.NextKeyMarker -VersionIdMarker $Content.ListVersionsResult.NextVersionIdMarker -EncodingType $EncodingType -Type $Type
                }
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Get-S3ObjectVersions -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName -Key $Key -MaxKeys $MaxKeys -Prefix $Prefix -Delimiter $Delimiter -KeyMarker $KeyMarker -VersionIdMarker $VersionIdMarker -EncodingType $EncodingType -Type $Type
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Get-S3ObjectVersions -Config $Config -Presign:$Presign -BucketName $BucketName -Region $($RedirectedRegion[0]) -Key $Key -MaxKeys $MaxKeys -Prefix $Prefix -Delimiter $Delimiter -KeyMarker $KeyMarker -VersionIdMarker $VersionIdMarker -EncodingType $EncodingType -Type $Type
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

<#
    .SYNOPSIS
    Get S3 Presigned URL
    .DESCRIPTION
    Get S3 Presigned URL
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER Key
    Object Key
    .PARAMETER VersionId
    Object version ID
    .PARAMETER Metadata
    Metadata
    .PARAMETER Expires
    Expiration Date of presigned URL (default 60 minutes from now)
    .PARAMETER Method
    HTTP Request Method (Default GET)
    .PARAMETER ContentMd5
    Content MD5
    .PARAMETER ContentType
    Content Type
    .PARAMETER ContentLength
    Content Length
#>
function Global:Get-S3PresignedUrl {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $True,
            Position = 9,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Object key")][Alias("Object")][String]$Key,
        [parameter(
            Mandatory = $False,
            Position = 10,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Object version ID")][String]$VersionId,
        [parameter(
            Mandatory = $False,
            Position = 11,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Metadata")][Hashtable]$Metadata,
        [parameter(
            Mandatory = $False,
            Position = 12,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Expiration Date of presigned URL (default 60 minutes from now)")][System.Datetime]$Expires = (Get-Date).AddHours(1),
        [parameter(
            Mandatory = $False,
            Position = 13,
            HelpMessage = "HTTP Request Method (Default GET)")][ValidateSet("OPTIONS", "GET", "HEAD", "PUT", "DELETE", "TRACE", "CONNECT")][String]$Method = "GET",
        [parameter(
            Mandatory = $False,
            Position = 14,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Content MD5")][String]$ContentMd5,
        [parameter(
            Mandatory = $False,
            Position = 15,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Content Type")][String]$ContentType,
        [parameter(
            Mandatory = $False,
            Position = 16,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Content Length")][String]$ContentLength
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
    }

    Process {
        Write-Verbose "Get presigned URL"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $Uri = "/$Key"
        $Presign = $true

        if ($VersionId) {
            $Query = @{versionId = $VersionId }
        }
        else {
            $Query = @{ }
        }

        $Headers = @{ }

        if ($Metadata) {
            foreach ($Key in $Metadata.Keys) {
                $Key = $Key -replace "^x-amz-meta-", ""
                $Headers["x-amz-meta-$Key"] = $Metadata[$Key]
            }
        }

        if ($ContentMd5) {
            $Headers["Content-MD5"] = $ContentMd5
        }
        if ($ContentType) {
            $Headers["content-type"] = $ContentType
        }
        if ($ContentLength) {
            $Headers["Content-Length"] = $ContentLength
        }

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Query $Query -Headers $Headers -Expires $Expires

        Write-Output $AwsRequest.Uri.ToString()
    }
}

<#
    .SYNOPSIS
    Get S3 Object Metadata
    .DESCRIPTION
    Get S3 Object Metadata
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER Key
    Object key
    .PARAMETER VersionId
    Object version ID
#>
function Global:Get-S3ObjectMetadata {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $True,
            Position = 9,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Object key")][Alias("Object")][String]$Key,
        [parameter(
            Mandatory = $False,
            Position = 10,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Object version ID")][String]$VersionId
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "HEAD"
    }

    Process {
        Write-Verbose "Retrieve object metadata for key $Key in bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $Uri = "/$Key"

        if ($VersionId) {
            $Query = @{versionId = $VersionId }
        }
        else {
            $Query = @{ }
        }

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -Uri $Uri -Query $Query -BucketName $BucketName

        if ($DryRun) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                $Headers = $Task.Result.Headers
                $Metadata = @{ }
                foreach ($Header in $Headers.GetEnumerator()) {
                    if ($Header.Key -match "x-amz-meta-") {
                        $MetadataKey = $Header.Key -replace "x-amz-meta-", ""
                        $Metadata[$MetadataKey] = $Header.Value -join ","
                    }
                }

                # TODO: Implement missing Metadata

                $ETag = $Headers.ETag -replace '"', '' | Select-Object -First 1
                if ($ETag -match "-") {
                    $PartCount = $Etag -split "-" | Select-Object -Last 1
                }
                else {
                    $PartCount = $null
                }

                $UnicodeBucketName = ConvertFrom-Punycode -BucketName $BucketName

                $Output = [PSCustomObject]@{Headers               = $Headers;
                    BucketName                                    = $UnicodeBucketName;
                    Region                                        = $Config.Region;
                    Key                                           = $Key;
                    Metadata                                      = $Metadata;
                    Size                                          = $Task.Result.Content.Headers.ContentLength | Select-Object -First 1;
                    ContentType                                   = $Task.Result.Content.Headers.ContentType | Select-Object -First 1;
                    DeleteMarker                                  = $null;
                    AcceptRanges                                  = $Headers.'Accept-Ranges' | Select-Object -First 1;
                    Expiration                                    = $Headers["x-amz-expiration"] | Select-Object -First 1;
                    RestoreExpiration                             = $null;
                    RestoreInProgress                             = $null;
                    LastModified                                  = $Task.Result.Content.Headers.LastModified | Select-Object -First 1;
                    ETag                                          = $Headers.ETag -replace '"', '' | Select-Object -First 1;
                    MissingMeta                                   = [int]$Headers["x-amz-missing-meta"] | Select-Object -First 1;
                    VersionId                                     = $Headers["x-amz-version-id"] | Select-Object -First 1;
                    Expires                                       = $null;
                    WebsiteRedirectLocation                       = $null;
                    ServerSideEncryptionMethod                    = $Headers["x-amz-server-side-encryption"] | Select-Object -First 1;
                    ServerSideEncryptionCustomerMethod            = $Headers["x-amz-server-side-encryption-customer-algorithm"] | Select-Object -First 1;
                    ServerSideEncryptionKeyManagementServiceKeyId = $Headers["x-amz-server-side-encryption-aws-kms-key-id"] | Select-Object -First 1;
                    ReplicationStatus                             = $Headers["x-amz-replication-status"] | Select-Object -First 1;
                    PartCount                                     = $PartCount;
                    StorageClass                                  = $Headers["x-amz-storage-class"] | Select-Object -First 1;
                }

                Write-Output $Output
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Get-S3ObjectMetadata -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName -Key $Key -VersionId $VersionId
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Get-S3ObjectMetadata -Config $Config -Presign:$Presign -BucketName $BucketName -Region $($RedirectedRegion[0]) -Key $Key -VersionId $VersionId
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

Set-Alias -Name Get-S3ObjectVersion -Value Read-S3Object
Set-Alias -Name Read-S3ObjectVersion -Value Read-S3Object
Set-Alias -Name Get-S3Object -Value Read-S3Object
<#
    .SYNOPSIS
    Read an S3 Object
    .DESCRIPTION
    Read an S3 Object
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER Key
    Object Key
    .PARAMETER VersionId
    Object version ID
    .PARAMETER Range
    Byte range to retrieve from object (e.g. "bytes=1024-2047")
    .PARAMETER Path
    Path where the object content should be stored
#>
function Global:Read-S3Object {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $True,
            Position = 9,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Object key")][Alias("Object")][String]$Key,
        [parameter(
            Mandatory = $False,
            Position = 10,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Object version ID")][String]$VersionId,
        [parameter(
            Mandatory = $False,
            Position = 11,
            HelpMessage = "Byte range to retrieve from object (e.g. `"bytes=1024-2047`")")][String]$Range,
        [parameter(
            Mandatory = $False,
            Position = 12,
            HelpMessage = "Path where the object content should be stored")][Alias("OutFile")][String]$Path
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "GET"
    }

    Process {
        Write-Verbose "Read object data for key $Key in bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $Uri = "/$Key"

        if ($VersionId) {
            $Query = @{versionId = $VersionId }
        }
        else {
            $Query = @{ }
        }

        $Headers = @{ }
        if ($Range) {
            if ($Range -notmatch "^bytes=\d*-\d*(,\d*-\d*)*$") {
                if ($Range -match "\d*-\d*(,\d*-\d*)*$") {
                    $Range = "bytes=" + $Range
                }
                else {
                    Throw "Byte range $Range is not a valid HTTP byte range"
                }
            }
            $Headers["Range"] = $Range
        }

        if ($Path) {
            if ($Path -match "^./|^.\\" -or $Path -notmatch "^/|^\\") {
                $Path = Join-Path -Path $PWD -ChildPath ($Path -replace "^./|^.\\","")
            }
            $DirectoryPath = [System.IO.DirectoryInfo]$Path
            if ($DirectoryPath.Exists) {
                $Item = Get-Item $DirectoryPath
                if ($Item -is [System.IO.FileInfo]) {
                    $OutFile = $Item
                }
                else {
                    $OutFile = Join-Path -Path $DirectoryPath -ChildPath $Key
                    # Key may contain one or multiple slashes, therefore we need to make sure that we create them as directories
                    if (!(Test-Path $(Split-Path $OutFile))) {
                        New-Item $(Split-Path $OutFile) -ItemType Directory | Out-Null
                    }
                }
            }
            elseif ($DirectoryPath.Parent.Exists) {
                $OutFile = $DirectoryPath
            }
            else {
                Throw "Path $DirectoryPath does not exist and parent directory $($DirectoryPath.Parent) also does not exist"
            }
        }

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -Uri $Uri -Query $Query -BucketName $BucketName

        if ($DryRun.IsPresent) {
            return $AwsRequest
        }

        Write-Verbose "Getting object metadata to determine file size and content type"
        $ObjectMetadata = Get-S3ObjectMetadata -Config $Config -Bucket $BucketName -Key $Key -VersionId $VersionId
        $Size = $ObjectMetadata.Size
        $ContentType = $ObjectMetadata.ContentType

        if (!$Path -and $ContentType -match "text|xml|json") {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                $Content = $Task.Result.Content.ReadAsStringAsync().Result

                Write-Output $Content
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Read-S3Object -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName -Key $Key -VersionId $VersionId -Range $Range
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Read-S3Object -Config $Config -Presign:$Presign -BucketName $BucketName -Region $($RedirectedRegion[0]) -Key $Key -VersionId $VersionId -Range $Range
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
            return
        }
        elseif (!$Path) {
            throw "No path specified and object is not of content-type text, XML or JSON"
        }

        $StartTime = Get-Date
        Write-Progress -Activity "Downloading object $BucketName/$Key to file $($OutFile.Name)" -Status "0 MiB written (0% Complete) / 0 MiB/s / estimated time to completion: 0" -PercentComplete 0

        Write-Verbose "Create new file of size $Size"
        $FileStream = [System.IO.FileStream]::new($OutFile, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $FileStream.SetLength($Size)
        $FileStream.Close()

        Write-Verbose "Initializing Memory Mapped File"
        $MemoryMappedFile = [System.IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile($OutFile, [System.IO.FileMode]::Open)

        if ($Config.MaxConcurrentRequests) {
            $MaxRunspaces = $Config.MaxConcurrentRequests
        }
        else {
            $MaxRunspaces = [Environment]::ProcessorCount * 2
        }
        Write-Verbose "Downloading maximum $MaxRunspaces parts in parallel"

        # when using range reads, we should choose the chunksize such that every runspace has at least one chunk
        $Chunksize = [Math]::Pow(2, [Math]::Floor([Math]::Log($Size / $MaxRunspaces) / [Math]::Log(2)))
        #  the min chunksize should be 1MB and the max chunksize should be 1GB
        $Chunksize = [Math]::Max($Chunksize, 1MB)
        $Chunksize = [Math]::Min($Chunksize, 1GB)
        Write-Verbose "Chunksize of $($Chunksize/1MB)MB will be used"

        $PartCount = [Math]::Ceiling($Size / $ChunkSize)

        Write-Verbose "File will be downloaded in $PartCount parts"

        try {
            Write-Verbose "Initializing Runspace Pool"
            $CancellationTokenSource = [System.Threading.CancellationTokenSource]::new()
            $CancellationToken = $CancellationTokenSource.Token
            $CancellationTokenVariable = [System.Management.Automation.Runspaces.SessionStateVariableEntry]::new('CancellationToken', $CancellationToken, $Null)
            $PartDownloadProgress = [Hashtable]::Synchronized(@{ })
            $PartDownloadProgressVariable = [System.Management.Automation.Runspaces.SessionStateVariableEntry]::new('PartDownloadProgress', $PartDownloadProgress, $Null)
            $InitialSessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
            $InitialSessionState.Variables.Add($CancellationTokenVariable)
            $InitialSessionState.Variables.Add($PartDownloadProgressVariable)
            $RunspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxRunspaces, $InitialSessionState, $Host)
            $RunspacePool.Open()

            Write-Verbose "Initializing Part Download Jobs"
            $Jobs = New-Object System.Collections.ArrayList

            foreach ($PartNumber in 1..$PartCount) {
                $Runspace = [PowerShell]::Create()
                $Runspace.RunspacePool = $RunspacePool
                [void]$Runspace.AddScript( {
                        Param (
                            [parameter(
                                Mandatory = $True,
                                Position = 0,
                                HelpMessage = "Content Stream")][System.IO.Stream]$Stream,
                            [parameter(
                                Mandatory = $True,
                                Position = 1,
                                HelpMessage = "Request URI")][Uri]$Uri,
                            [parameter(
                                Mandatory = $True,
                                Position = 2,
                                HelpMessage = "Request Headers")][Hashtable]$Headers,
                            [parameter(
                                Mandatory = $True,
                                Position = 3,
                                HelpMessage = "Part number")][Int]$PartNumber,
                            [parameter(
                                Mandatory = $False,
                                Position = 4,
                                HelpMessage = "Skip Certificate Check")][Boolean]$SkipCertificateCheck,
                            [parameter(
                                Mandatory = $False,
                                Position = 5,
                                HelpMessage = "Cancellation Token")][System.Threading.CancellationToken]$CancellationToken
                        )

                        $HttpClientHandler = [System.Net.Http.HttpClientHandler]::new()
                        if ($SkipCertificateCheck -and $PSVersionTable.PSVersion.Major -lt 6) {
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

                            [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
                        }
                        elseif ($SkipCertificateCheck) {
                            $HttpClientHandler.ServerCertificateCustomValidationCallback = [System.Net.Http.HttpClientHandler]::DangerousAcceptAnyServerCertificateValidator
                        }

                        $HttpClient = [System.Net.Http.HttpClient]::new($HttpClientHandler)

                        Write-Verbose "Set Timeout proportional to size of data to be downloaded (assuming at least 10 KByte/s)"
                        $HttpClient.Timeout = [Timespan]::FromSeconds([Math]::Max($Stream.Length / 10KB, 60))
                        Write-Verbose "Timeout set to $($HttpClient.Timeout)"

                        $GetRequest = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $Uri)

                        Write-Verbose "Adding headers"
                        foreach ($HeaderKey in $Headers.Keys) {
                            # AWS Authorization Header is not RFC compliant, therefore we need to skip header validation
                            if ($HeaderKey -eq "Authorization") {
                                $null = $GetRequest.Headers.TryAddWithoutValidation($HeaderKey, $Headers[$HeaderKey])
                            }
                            else {
                                $null = $GetRequest.Headers.Add($HeaderKey, $Headers[$HeaderKey])
                            }
                        }

                        $StreamLength = $Stream.Length

                        try {
                            $Task = $HttpClient.SendAsync($GetRequest, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead, $CancellationToken)

                            $Response = $Task.Result

                            if (!$Response.EnsureSuccessStatusCode()) {
                                Write-Output $Task
                            }
                            $Task = $Response.Content.CopyToAsync($Stream)

                            while ($Stream.Position -ne $Stream.Length -and !$CancellationToken.IsCancellationRequested -and !$Task.IsCanceled -and !$Task.IsFaulted -and !$Task.IsCompleted) {
                                Start-Sleep -Milliseconds 500
                                $PartDownloadProgress.$PartNumber = $Stream.Position
                            }
                            $PartDownloadProgress.$PartNumber = $StreamLength

                            if ($Task.IsCanceled -or $Task.IsFaulted) {
                                Write-Output $Task
                            }
                        }
                        catch {
                            Write-Output $_
                        }
                        finally {
                            $Task.Dispose()
                            $GetRequest.Dispose()
                            $Stream.Dispose()
                        }
                    })

                if (($PartNumber * $Chunksize) -gt $Size) {
                    $ViewSize = $Chunksize - ($PartNumber * $Chunksize - $Size)
                }
                else {
                    $ViewSize = $Chunksize
                }

                Write-Verbose "Creating File view from position $(($PartNumber -1) * $Chunksize) with size $ViewSize"
                $Stream = $MemoryMappedFile.CreateViewStream(($PartNumber - 1) * $Chunksize, $ViewSize)

                $StartRange = ($PartNumber - 1) * $Chunksize
                $EndRange = $StartRange + $ViewSize - 1

                if ($ViewSize -lt $Size) {
                    $Range = "bytes=" + $StartRange + "-" + $EndRange
                    Write-Verbose "Using HTTP byte range $Range"
                    $AwsRequest.Headers["range"] = $Range
                }

                $Parameters = @{
                    Stream               = $Stream
                    Uri                  = $AwsRequest.Uri
                    Headers              = $AwsRequest.Headers.PSObject.Copy()
                    PartNumber           = $PartNumber
                    SkipCertificateCheck = $Config.SkipCertificateCheck
                    CancellationToken    = $CancellationToken
                }
                [void]$Runspace.AddParameters($Parameters)
                $Job = [PSCustomObject]@{
                    Pipe       = $Runspace
                    Status     = $Runspace.BeginInvoke()
                    PartNumber = $PartNumber
                }
                [void]$Jobs.Add($Job)
            }

            $PercentCompleted = 0

            Write-Progress -Activity "Downloading object $BucketName/$Key to $($OutFile.Name)" -Status "0 MiB written (0% Complete) / 0 MiB/s /  / estimated time to completion: 0" -PercentComplete $PercentCompleted

            $StartTime = Get-Date

            while ($Jobs) {
                Start-Sleep -Milliseconds 500
                $CompletedJobs = $Jobs | Where-Object { $_.Status.IsCompleted -eq $true }
                foreach ($Job in $CompletedJobs) {
                    $Output = $Job.Pipe.EndInvoke($Job.Status)
                    if ($Output[0]) {
                        Write-Verbose (ConvertTo-Json -InputObject $Output)
                        foreach ($Job in $Jobs) {
                            $CancellationToken = $CancellationTokenSource.Cancel()
                            $Job.Pipe.Stop()
                        }
                        throw "Download of part $($Job.PartNumber) failed with output`n$(ConvertTo-Json -InputObject $Output)"
                    }
                    Write-Verbose "Part $($Job.PartNumber) has completed"
                    $Job.Pipe.Dispose()
                    $Jobs.Remove($Job)
                }

                # report progress
                $WrittenBytes = $PartDownloadProgress.Clone().Values | Measure-Object -Sum | Select-Object -ExpandProperty Sum
                $PercentCompleted = $WrittenBytes / $Size * 100
                $Duration = ((Get-Date) - $StartTime).TotalSeconds
                $Throughput = $WrittenBytes / 1MB / $Duration
                if ($Throughput -gt 0) {
                    $EstimatedTimeToCompletion = [TimeSpan]::FromSeconds([Math]::Round(($Size - $WrittenBytes) / 1MB / $Throughput))
                }
                else {
                    $EstimatedTimeToCompletion = 0
                }

                $Activity = "Downloading object $BucketName/$Key to file $($OutFile.Name)"
                $Status = "{0:F2} MiB written | {1:F2}% Complete | {2:F2} MiB/s  | estimated time to completion: {3:g}" -f ($WrittenBytes / 1MB), $PercentCompleted, $Throughput, $EstimatedTimeToCompletion
                Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentCompleted
            }
        }
        catch {
            Write-Warning "Something has gone wrong"
            throw $_
        }
        finally {
            Write-Verbose "Cleaning up"
            $MemoryMappedFile.Dispose()
            $RunspacePool.Close()
            $RunspacePool.Dispose()
        }

        if ($Jobs) {
            throw "Job(s) with partnumber(s) $($Jobs.PartNumber -join ',') did not complete"
        }
        else {
            Write-Progress -Activity "Downloading object $BucketName/$Key to file $($OutFile.Name) completed" -Completed
            Write-Host "Downloading object $BucketName/$Key of size $([Math]::Round($Size/1MB,4))MiB to file $($OutFile.Name) completed in $([Math]::Round($Duration,2)) seconds with average throughput of $Throughput MiB/s"
        }
    }
}

<#
    .SYNOPSIS
    Write S3 Object
    .DESCRIPTION
    Write S3 Object
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER Key
    Object Key
#>
function Global:Write-S3Object {
    [CmdletBinding(DefaultParameterSetName = "Profile")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $False,
            Position = 9,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Object key. If not provided, filename will be used")][Alias("Object")][String]$Key,
        [parameter(
            Mandatory = $False,
            Position = 10,
            HelpMessage = "Path where object should be stored")][Alias("Path", "File")][System.IO.FileInfo]$InFile,
        [parameter(
            Mandatory = $False,
            Position = 11,
            HelpMessage = "Content type")][String]$ContentType,
        [parameter(
            Mandatory = $False,
            Position = 12,
            HelpMessage = "Content of object")][Alias("InputObject")][String]$Content,
        [parameter(
            Mandatory = $False,
            Position = 13,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Metadata")][Hashtable]$Metadata,
        [parameter(
            Mandatory = $False,
            Position = 14,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Specifies the algorithm to use to when encrypting the object.")][ValidateSet("aws:kms", "AES256")][String]$ServerSideEncryption
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "PUT"
    }

    Process {
        Write-Verbose "Write object data for key $Key in bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        if ($InFile -match "^./|^.\\" -or $InFile -notmatch "^/|^\\") {
            $InFile = Join-Path -Path $PWD -ChildPath ($InFile -replace "^./|^.\\","")
        }

        if ($InFile -and !$InFile.Exists) {
            Throw "File $InFile does not exist"
        }

        if (!$Key) {
            $Key = $InFile.Name
        }
        elseif (!$Content) {
            $Content = ""
        }

        # if the file size is larger than the multipart threshold, then a multipart upload should be done
        if (!$Content -and $Config.MultipartThreshold -and $InFile.Length -ge $Config.MultipartThreshold) {
            Write-Verbose "Using multipart upload as file is larger than multipart threshold of $($Config.MultipartThreshold)"
            Write-S3MultipartUpload -Config $Config -BucketName $BucketName -Key $Key -InFile $InFile -Metadata $Metadata
        }
        # if the file size is larger than 5GB multipart upload must be used as PUT Object is only allowed up to 5GB files
        elseif ($InFile.Length -gt 5GB) {
            Write-Warning "Using multipart upload as PUT uploads are only allowed for files smaller than 5GB and file is larger than 5GB."
            Write-S3MultipartUpload -Config $Config -BucketName $BucketName -Key $Key -InFile $InFile -Metadata $Metadata
        }
        else {
            $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

            $Headers = @{ }

            if (!$InFile -and $Content -and !$ContentType) {
                $Headers["content-type"] = "text/plain"
            }
            elseif ($InFile -and !$ContentType) {
                $Headers["content-type"] = $MIME_TYPES[$InFile.Extension]
            }
            elseif ($ContentType) {
                $Headers["content-type"] = $ContentType
            }

            if (!$Headers["content-type"]) {
                $Headers["content-type"] = "application/octet-stream"
            }

            if ($Metadata) {
                foreach ($MetadataKey in $Metadata.Keys) {
                    $MetadataKey = $MetadataKey -replace "^x-amz-meta-", ""
                    $MetadataKey = $MetadataKey.ToLower()
                    $Headers["x-amz-meta-$MetadataKey"] = $Metadata[$MetadataKey]
                    # TODO: check that metadata is valid HTTP Header
                }
            }
            if ($ServerSideEncryption) {
                $Headers["x-amz-server-side-encryption"] = $ServerSideEncryption
            }
            Write-Verbose "Metadata:`n$($Headers | ConvertTo-Json)"

            $Uri = "/$Key"

            $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -Uri $Uri -Query $Query -BucketName $BucketName -InFile $InFile -RequestPayload $Content -Headers $Headers

            if ($DryRun.IsPresent) {
                Write-Output $AwsRequest
            }
            else {
                try {
                    if (!$InFile -or $InFile.Length -eq 0) {
                        $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck -Body $Content
                        $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

                        if ($Task.Result.IsSuccessStatusCode) {
                            Write-Output ([PSCustomObject]@{ETag = $Task.Result.Headers.ETag.Tag })
                        }
                        elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                            $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                            $RetryCount++
                            Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                            Start-Sleep -Seconds $SleepSeconds
                            Write-S3Object -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName -Key $Key -Content $Content
                        }
                        elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                            Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
                        }
                        elseif ($Task.Exception -match "Device not configured") {
                            Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
                        }
                        elseif ($Task.IsFaulted) {
                            Throw $Task.Exception
                        }
                        elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                            Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                            Write-S3Object -Config $Config -Presign:$Presign -BucketName $BucketName -Region $($RedirectedRegion[0]) -Key $Key -Content $Content
                        }
                        elseif ($Task.Result) {
                            $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                            if ($Result.Error.Message) {
                                Throw $Result.Error.Message
                            }
                            else {
                                Throw $Task.Result.StatusCode
                            }
                        }
                        else {
                            Throw "Task failed with status $($Task.Status)"
                        }
                        return
                    }
                    else {
                        $StartTime = Get-Date

                        $Activity = "Uploading file $($InFile.Name) to $BucketName/$Key"

                        Write-Progress -Activity $Activity -Status "0 MiB written (0% Complete) / 0 MiB/s / estimated time to completion: 0" -PercentComplete 0

                        Write-Verbose "Creating HTTP Client Handler"
                        $HttpClientHandler = [System.Net.Http.HttpClientHandler]::new()
                        if ($SkipCertificateCheck -and $PSVersionTable.PSVersion.Major -lt 6) {
                            [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
                        }
                        elseif ($SkipCertificateCheck) {
                            $HttpClientHandler.ServerCertificateCustomValidationCallback = [System.Net.Http.HttpClientHandler]::DangerousAcceptAnyServerCertificateValidator
                        }

                        Write-Verbose "Creating Stream"
                        $Stream = [System.IO.FileStream]::new($InFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)

                        # using CryptoSteam to calculate the MD5 sum while uploading the file
                        # this allows to only read the stream once and increases performance compared with other S3 clients
                        $Md5 = [System.Security.Cryptography.MD5]::Create()
                        $CryptoStream = [System.Security.Cryptography.CryptoStream]::new($Stream, $Md5, [System.Security.Cryptography.CryptoStreamMode]::Read)

                        Write-Verbose "Creating HTTP Client"
                        $HttpClient = [System.Net.Http.HttpClient]::new($HttpClientHandler)

                        Write-Verbose "Set Timeout proportional to size of data to be uploaded (assuming at least 10 KByte/s)"
                        $HttpClient.Timeout = [Timespan]::FromSeconds([Math]::Max($Stream.Length / 10KB, 60))
                        Write-Verbose "Timeout set to $($HttpClient.Timeout)"

                        Write-Verbose "Creating PUT request"
                        $PutRequest = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Put, $AwsRequest.Uri)

                        $StreamLength = $Stream.Length
                        $StreamContent = [System.Net.Http.StreamContent]::new($CryptoStream)
                        $StreamContent.Headers.ContentLength = $Stream.Length
                        if ($ContentType) {
                            $StreamContent.Headers.ContentType = $ContentType
                        }
                        if ($AwsRequest.Headers['Content-MD5']) {
                            $StreamContent.Headers.ContentMd5 = $AwsRequest.Md5
                        }
                        $PutRequest.Content = $StreamContent

                        Write-Verbose "Adding headers"

                        if ($AwsRequest.Headers["Content-MD5"]) {
                            $PutRequest.Content.Headers.ContentMD5 = [Convert]::FromBase64String($AwsRequest.Headers["Content-MD5"])
                            $AwsRequest.Headers.Remove("Content-MD5")
                        }
                        elseif ($AwsRequest.Headers["Content-MD5"] -ne $null) {
                            Throw "Content-MD5 header specified but empty"
                        }

                        if ($AwsRequest.Headers["content-type"]) {
                            $PutRequest.Content.Headers.ContentType = $AwsRequest.Headers["content-type"]
                            $AwsRequest.Headers.Remove("content-type")
                        }
                        elseif ($AwsRequest.Headers["content-type"] -ne $null) {
                            Throw "content-type header specified but empty"
                        }

                        foreach ($HeaderKey in $AwsRequest.Headers.Keys) {
                            # AWS Authorization Header is not RFC compliant, therefore we need to skip header validation
                            if ($HeaderKey -eq "Authorization") {
                                $null = $PutRequest.Headers.TryAddWithoutValidation($HeaderKey, $Headers[$HeaderKey])
                            }
                            else {
                                $null = $PutRequest.Headers.Add($HeaderKey, $Headers[$HeaderKey])
                            }
                        }

                        Write-Verbose "PUT $($AwsRequest.Uri) with $($Stream.Length)-byte payload"

                        try {
                            Write-Verbose "Start upload"
                            $CancellationTokenSource = [System.Threading.CancellationTokenSource]::new()
                            $CancellationToken = $CancellationTokenSource.Token
                            $Task = $HttpClient.SendAsync($PutRequest, $CancellationToken)

                            Write-Verbose "Report progress"
                            while ($Stream.Position -ne $Stream.Length -and !$Task.IsCanceled -and !$Task.IsFaulted -and !$Task.IsCompleted) {
                                Start-Sleep -Milliseconds 500
                                $WrittenBytes = $Stream.Position
                                $PercentCompleted = $WrittenBytes / $InFile.Length * 100
                                $Duration = ((Get-Date) - $StartTime).TotalSeconds
                                $Throughput = $WrittenBytes / 1MB / $Duration
                                if ($Throughput -gt 0) {
                                    $EstimatedTimeToCompletion = [TimeSpan]::FromSeconds([Math]::Round(($InFile.Length - $WrittenBytes) / 1MB / $Throughput))
                                }
                                else {
                                    $EstimatedTimeToCompletion = 0
                                }
                                $Status = "{0:F2} MiB written | {1:F2}% Complete | {2:F2} MiB/s  | estimated time to completion: {3:g}" -f ($WrittenBytes / 1MB), $PercentCompleted, $Throughput, $EstimatedTimeToCompletion
                                Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentCompleted
                            }
                            $WrittenBytes = $StreamLength

                            if ($Task.Exception) {
                                throw $Task.Exception
                            }

                            if ($Task.IsCanceled) {
                                throw "Upload was canceled with result $($Task.Result)"
                            }

                            $Etag = New-Object 'System.Collections.Generic.List[string]'
                            [void]$Task.Result.Headers.TryGetValues("ETag", [ref]$Etag)
                            $Etag = ($Etag | Select-Object -First 1) -replace '"', ''

                            $CryptoStream.Dispose()
                            $Md5Sum = [BitConverter]::ToString($Md5.Hash) -replace "-", ""

                            Write-Verbose "Response Headers:`n$(ConvertTo-Json -InputObject $Task.Result.Headers)"

                            if ($Task.Result.StatusCode -ne "OK") {
                                return $Task.Result
                            }
                            elseif ($Etag -ne $MD5Sum) {
                                throw "Etag $Etag does not match calculated MD5 sum $MD5Sum"
                            }
                            else {
                                Write-Output ([PSCustomObject]@{ETag = $Etag })
                            }
                        }
                        catch {
                            throw $_
                        }
                        finally {
                            if (!$Task.IsCompleted) {
                                Write-Verbose "Cancel upload task"
                                $CancellationTokenSource.Cancel()
                            }
                            Write-Verbose "Dispose used resources"
                            if ($Task) { $Task.Dispose() }
                            if ($PutRequest) { $PutRequest.Dispose() }
                            if ($HttpClient) { $HttpClient.Dispose() }
                            if ($StreamContent) { $StreamContent.Dispose() }
                        }

                        Write-Host "Uploading file $($InFile.Name) of size $([Math]::Round($InFile.Length/1MB,4)) MiB to $BucketName/$Key completed in $([Math]::Round($Duration,2)) seconds with average throughput of $Throughput MiB/s"
                    }
                }
                catch {
                    if ($_.Exception.Response) {
                        $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'
                        if ([int]$_.Exception.Response.StatusCode -match "^3" -and $_.Exception.Response.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                            Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                            if ($InFile) {
                                Write-S3Object -SkipCertificateCheck:$Config.SkipCertificateCheck -Presign:$Presign -DryRun:$DryRun -SignerType $SignerType -EndpointUrl $Config.EndpointUrl -AccessKey $Config.AccessKey -SecretKey $Config.SecretKey -Region $($RedirectedRegion[0]) -UrlStyle $UrlStyle -Bucket $BucketName -Key $Key -InFile $InFile -Metadata $Metadata
                            }
                            else {
                                Write-S3Object -SkipCertificateCheck:$Config.SkipCertificateCheck -Presign:$Presign -DryRun:$DryRun -SignerType $SignerType -EndpointUrl $Config.EndpointUrl -AccessKey $Config.AccessKey -SecretKey $Config.SecretKey -Region $($RedirectedRegion[0]) -UrlStyle $UrlStyle -Bucket $BucketName -Key $Key -Content $Content -Metadata $Metadata
                            }
                        }
                        else {
                            Throw
                        }
                    }
                    else {
                        Throw
                    }
                }
            }

            if ($Stream) { $Stream.Dispose() }
        }
    }
}

<#
    .SYNOPSIS
    Initiate Multipart Upload
    .DESCRIPTION
    Initiate Multipart Upload
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER Key
    Object key
    .PARAMETER Metadata
    Metadata
#>
function Global:Start-S3MultipartUpload {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $True,
            Position = 9,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Object key")][Alias("Object")][String]$Key,
        [parameter(
            Mandatory = $False,
            Position = 10,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Metadata")][Hashtable]$Metadata,
        [parameter(
            Mandatory = $False,
            Position = 11,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Enable Payload Signing")][Switch]$PayloadSigning,
        [parameter(
            Mandatory = $False,
            Position = 12,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Specifies the algorithm to use to when encrypting the object.")][ValidateSet("aws:kms", "AES256")][String]$ServerSideEncryption,
        [parameter(
            Mandatory = $False,
            Position = 13,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Content Type.")][String]$ContentType
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "POST"
    }

    Process {
        Write-Verbose "Start multipart upload for key $Key in bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $Headers = @{ }
        if ($Metadata) {
            foreach ($MetadataKey in $Metadata.Keys) {
                $MetadataKey = $MetadataKey -replace "^x-amz-meta-", ""
                $MetadataKey = $MetadataKey.ToLower()
                $Headers["x-amz-meta-$MetadataKey"] = $Metadata[$MetadataKey]
                # TODO: check that metadata is valid HTTP Header
            }
        }
        Write-Verbose "Metadata:`n$($Headers | ConvertTo-Json)"

        if ($ServerSideEncryption) {
            $Headers["x-amz-server-side-encryption"] = $ServerSideEncryption
        }

        if ($ContentType) {
            $Headers["content-type"] = $ContentType
        }

        $Uri = "/$Key"

        $Query = @{uploads = "" }

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -Uri $Uri -Query $Query -BucketName $BucketName -Headers $Headers

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck
            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                $Content = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                $InitiateMultipartUploadResult = [PSCustomObject]@{Bucket = $Content.InitiateMultipartUploadResult.Bucket; Key = $Content.InitiateMultipartUploadResult.Key; UploadId = $Content.InitiateMultipartUploadResult.UploadId; Etags = [System.Collections.Generic.SortedDictionary[int, string]]::new() }
                Write-Output $InitiateMultipartUploadResult
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Write-S3Object -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName -Key $Key -Content $Content
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Write-S3Object -Config $Config -Presign:$Presign -BucketName $BucketName -Region $($RedirectedRegion[0]) -Key $Key -Content $Content
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

<#
    .SYNOPSIS
    Abort Multipart Upload
    .DESCRIPTION
    Abort Multipart Upload
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER Key
    Object key
#>
function Global:Stop-S3MultipartUpload {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $True,
            Position = 9,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Object key")][Alias("Object")][String]$Key,
        [parameter(
            Mandatory = $True,
            Position = 10,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Multipart Upload ID")][String]$UploadId
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "DELETE"
    }

    Process {
        Write-Verbose "Aborting multipart upload for key $Key and bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $Uri = "/$Key"

        $Query = @{uploadId = $uploadId }

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -Uri $Uri -BucketName $BucketName -Query $Query

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                # do nothing
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Stop-S3MultipartUpload -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName -Key $Key
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Stop-S3MultipartUpload -Config $Config -Presign:$Presign -BucketName $BucketName -Region $($RedirectedRegion[0]) -Key $Key
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

<#
    .SYNOPSIS
    Complete Multipart Upload
    .DESCRIPTION
    Complete Multipart Upload
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER Key
    Object key
#>
function Global:Complete-S3MultipartUpload {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $True,
            Position = 9,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Object key")][Alias("Object")][String]$Key,
        [parameter(
            Mandatory = $True,
            Position = 10,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Multipart Upload ID")][String]$UploadId,
        [parameter(
            Mandatory = $True,
            Position = 11,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Part Etags in the format partNumber=ETag")][System.Collections.Generic.SortedDictionary[int, string]]$Etags
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "POST"
    }

    Process {
        Write-Verbose "Complete multipart upload of key $Key in bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $Uri = "/$Key"

        $RequestPayload = "<CompleteMultipartUpload xmlns=`"http://s3.amazonaws.com/doc/2006-03-01/`">"
        foreach ($Part in $Etags.Keys) {
            $RequestPayload += "<Part><ETag>$( $Etags[$Part] )</ETag><PartNumber>$Part</PartNumber></Part>"
        }
        $RequestPayload += "</CompleteMultipartUpload>"

        $Query = @{uploadId = $uploadId }

        $Headers = @{"content-type" = "application/xml"}

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -Uri $Uri -BucketName $BucketName -Query $Query -Headers $Headers -RequestPayload $RequestPayload

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck -Body $RequestPayload

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                $Content = [XML]$Task.Result.Content.ReadAsStringAsync().Result

                $CompleteMultipartUploadResult = [PSCustomObject]@{ Location = [System.Net.WebUtility]::UrlDecode($Content.CompleteMultipartUploadResult.Location);
                    BucketName                                               = [System.Net.WebUtility]::UrlDecode($Content.CompleteMultipartUploadResult.Bucket);
                    Key                                                      = [System.Net.WebUtility]::UrlDecode($Content.CompleteMultipartUploadResult.Key);
                    ETag                                                     = ([System.Net.WebUtility]::UrlDecode($Content.CompleteMultipartUploadResult.ETag) -replace '"', '')
                }

                Write-Output $CompleteMultipartUploadResult
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Complete-S3MultipartUpload -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName -Key $Key -UploadId $UploadId -Etags $Etags
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Complete-S3MultipartUpload -Config $Config -Presign:$Presign -BucketName $BucketName -Region $($RedirectedRegion[0]) -Key $Key -UploadId $UploadId -Etags $Etags
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

Set-Alias -Name Invoke-S3MultipartUpload -Value Write-S3MultipartUpload
<#
    .SYNOPSIS
    Write S3 Object as Multipart Upload
    .DESCRIPTION
    Write S3 Object as Multipart Upload
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER Key
    Object key. If not provided, filename will be used.
    .PARAMETER InFile
    Path where object should be stored
    .PARAMETER Metadata
    Metadata
    .PARAMETER MaxConcurrentRequests
    maximum number of concurrent requests
    .PARAMETER Chunksize
    Multipart Part Chunksize
#>
function Global:Write-S3MultipartUpload {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $False,
            Position = 9,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Object key. If not provided, filename will be used.")][Alias("Object")][String]$Key,
        [parameter(
            Mandatory = $True,
            Position = 10,
            HelpMessage = "Path where object should be stored")][Alias("Path", "File")][System.IO.FileInfo]$InFile,
        [parameter(
            Mandatory = $False,
            Position = 11,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Metadata")][Hashtable]$Metadata,
        [parameter(
            Mandatory = $False,
            Position = 12,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Maximum number of concurrent requests")][Alias("max_concurrent_requests")][UInt16]$MaxConcurrentRequests,
        [parameter(
            Mandatory = $False,
            Position = 13,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Multipart Part Chunksize")][ValidateRange(1, 5GB)][int64]$Chunksize
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "PUT"
    }

    Process {
        Write-Verbose "Upload object data using multipart upload to bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck -MaxConcurrentRequests $MaxConcurrentRequests -MultipartChunksize $Chunksize
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        if ($InFile -match "^./|^.\\" -or $InFile -notmatch "^/|^\\") {
            $InFile = Join-Path -Path $PWD -ChildPath ($InFile -replace "^./|^.\\","")
        }

        if ($InFile -and !$InFile.Exists) {
            Throw "File $InFile does not exist"
        }

        $ContentType = $MIME_TYPES[$InFile.Extension]

        if (!$Key) {
            $Key = $InFile.Name
        }

        $FileSize = $InFile.Length

        if ($FileSize -eq 0) {
            Write-Warning "Empty file cannot be uploaded as multipart upload, therefore transferring as normal upload"
            Write-S3Object -SkipCertificateCheck:$Config.SkipCertificateCheck -AccessKey $Config.AccessKey -SecretKey $Config.SecretKey -SignerType $SignerType -EndpointUrl $Config.EndpointUrl -Region $Region -BucketName $BucketName -InFile $InFile -Key $Key -Metadata $Metadata -ContentType $ContentType
            return
        }

        if ($Config.MaxConcurrentRequests) {
            $MaxRunspaces = $Config.MaxConcurrentRequests
        }
        else {
            $MaxRunspaces = [Environment]::ProcessorCount * 2
        }
        Write-Verbose "Uploading maximum $MaxRunspaces parts in parallel"

        if ($Config.MultipartChunksize -gt 0) {
            # Chunksize must be at least 1/1000 of the file size, as max 1000 parts are allowed
            if (($FileSize / $Config.MultipartChunksize) -le 1000) {
                # division by one necessary as we need to convert string in number format (e.g. 16MB) to integer
                $Chunksize = ($Config.MultipartChunksize / 1)
            }
        }

        if (!$Chunksize) {
            if ($FileSize -gt ([int64]$MaxRunspaces * 1GB)) {
                # chunksize of 1GB is optimal for fast, lossless connections which we assume
                $Chunksize = 1GB
            }
            elseif (($FileSize / $MaxRunspaces) -ge 8MB) {
                # if filesize is smaller than max number of runspaces times 1GB
                # then we need to make sure that we reduce the chunksize so that all runspaces are used
                $Chunksize = [Math]::Pow(2, [Math]::Floor([Math]::Log($FileSize / $MaxRunspaces) / [Math]::Log(2)))
            }
            else {
                # minimum chunksize for S3 is 5MB
                $Chunksize = 5MB
            }
        }
        Write-Verbose "Chunksize of $($Chunksize/1MB)MB will be used"

        $PartCount = [Math]::Ceiling($FileSize / $ChunkSize)

        Write-Verbose "File will be uploaded in $PartCount parts"

        Write-Verbose "Initiating Multipart Upload"
        $MultipartUpload = Start-S3MultipartUpload -Config $Config -BucketName $BucketName -Key $Key -Metadata $Metadata -ContentType $ContentType

        Write-Verbose "Multipart Upload ID: $($MultipartUpload.UploadId)"

        try {
            Write-Verbose "Initializing Runspace Pool"
            $CancellationTokenSource = [System.Threading.CancellationTokenSource]::new()
            $CancellationToken = $CancellationTokenSource.Token
            $CancellationTokenVariable = [System.Management.Automation.Runspaces.SessionStateVariableEntry]::new('CancellationToken', $CancellationToken, $Null)
            $PartUploadProgress = [Hashtable]::Synchronized(@{ })
            $PartUploadProgressVariable = [System.Management.Automation.Runspaces.SessionStateVariableEntry]::new('PartUploadProgress', $PartUploadProgress, $Null)
            $InitialSessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
            $InitialSessionState.Variables.Add($CancellationTokenVariable)
            $InitialSessionState.Variables.Add($PartUploadProgressVariable)
            $RunspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxRunspaces, $InitialSessionState, $Host)
            $RunspacePool.Open()

            Write-Verbose "Initializing Memory Mapped File"
            $MemoryMappedFile = [System.IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile($InFile, [System.IO.FileMode]::Open)

            Write-Verbose "Initializing Part Upload Jobs"
            $Etags = New-Object 'System.Collections.Generic.SortedDictionary[int, string]'
            $Jobs = New-Object System.Collections.ArrayList

            foreach ($PartNumber in 1..$PartCount) {
                $Runspace = [PowerShell]::Create()
                $Runspace.RunspacePool = $RunspacePool
                [void]$Runspace.AddScript( {
                        Param (
                            [parameter(
                                Mandatory = $True,
                                Position = 0,
                                HelpMessage = "Content Stream")][System.IO.Stream]$Stream,
                            [parameter(
                                Mandatory = $True,
                                Position = 1,
                                HelpMessage = "Request URI")][Uri]$Uri,
                            [parameter(
                                Mandatory = $True,
                                Position = 2,
                                HelpMessage = "Request Headers")][Hashtable]$Headers,
                            [parameter(
                                Mandatory = $True,
                                Position = 3,
                                HelpMessage = "Part number")][Int]$PartNumber,
                            [parameter(
                                Mandatory = $False,
                                Position = 4,
                                HelpMessage = "Skip Certificate Check")][Boolean]$SkipCertificateCheck,
                            [parameter(
                                Mandatory = $False,
                                Position = 5,
                                HelpMessage = "Cancellation Token")][System.Threading.CancellationToken]$CancellationToken
                        )

                        $HttpClientHandler = [System.Net.Http.HttpClientHandler]::new()
                        if ($SkipCertificateCheck -and $PSVersionTable.PSVersion.Major -lt 6) {
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

                            [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
                        }
                        elseif ($SkipCertificateCheck) {
                            $HttpClientHandler.ServerCertificateCustomValidationCallback = [System.Net.Http.HttpClientHandler]::DangerousAcceptAnyServerCertificateValidator
                        }

                        # using CryptoSteam to calculate the MD5 sum while uploading the part
                        # this allows to only read the stream once and increases performance compared with other S3 clients
                        $Md5 = [System.Security.Cryptography.MD5]::Create()
                        $CryptoStream = [System.Security.Cryptography.CryptoStream]::new($Stream, $Md5, [System.Security.Cryptography.CryptoStreamMode]::Read)

                        $HttpClient = [System.Net.Http.HttpClient]::new($HttpClientHandler)

                        # set Timeout proportional to size of data to be uploaded (assuming at least 10 KByte/s)
                        $HttpClient.Timeout = [Timespan]::FromSeconds([Math]::Max($Stream.Length / 10KB, 60))
                        Write-Verbose "Timeout set to $($HttpClient.Timeout)"

                        $PutRequest = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Put, $Uri)

                        $PutRequest.Headers.Add("Host", $Headers["Host"])

                        $StreamLength = $Stream.Length
                        $StreamContent = [System.Net.Http.StreamContent]::new($CryptoStream)
                        $StreamContent.Headers.ContentLength = $Stream.Length
                        $PutRequest.Content = $StreamContent

                        if ($Headers["Content-MD5"]) {
                            $PutRequest.Content.Headers.ContentMD5 = [Convert]::FromBase64String($Headers["Content-MD5"])
                            $Headers.Remove("Content-MD5")
                        }
                        elseif ($Headers["Content-MD5"] -ne $null) {
                            Throw "Content-MD5 header specified but empty"
                        }

                        if ($Headers["content-type"]) {
                            $Content.Headers.ContentType = $AwsRequest.Headers["content-type"]
                            $Headers.Remove("content-type")
                        }
                        elseif ($Headers["content-type"] -ne $null) {
                            Throw "content-type header specified but empty"
                        }

                        foreach ($HeaderKey in $Headers.Keys) {
                            # AWS Authorization Header is not RFC compliant, therefore we need to skip header validation
                            if ($HeaderKey -eq "Authorization") {
                                $null = $PutRequest.Headers.TryAddWithoutValidation($HeaderKey, $Headers[$HeaderKey])
                            }
                            else {
                                $null = $PutRequest.Headers.Add($HeaderKey, $Headers[$HeaderKey])
                            }
                        }

                        try {
                            $Task = $HttpClient.SendAsync($PutRequest, $CancellationToken)

                            while ($Stream.Position -ne $Stream.Length -and !$CancellationToken.IsCancellationRequested -and !$Task.IsCanceled -and !$Task.IsFaulted -and !$Task.IsCompleted) {
                                Start-Sleep -Milliseconds 500
                                $PartUploadProgress.$PartNumber = $Stream.Position
                            }
                            $PartUploadProgress.$PartNumber = $StreamLength

                            $Etag = New-Object 'System.Collections.Generic.List[string]'
                            [void]$Task.Result.Headers.TryGetValues("ETag", [ref]$Etag)
                            $Etag = ($Etag | Select-Object -First 1) -replace '"', ''

                            $CryptoStream.Dispose()
                            $Md5Sum = [BitConverter]::ToString($Md5.Hash) -replace "-", ""

                            if ($Task.Result.StatusCode -ne "OK") {
                                Write-Output $Task
                            }
                            elseif ($Etag -ne $MD5Sum) {
                                $Output = [PSCustomObject]@{Etag = $Etag; MD5Sum = $MD5Sum }
                                Write-Output $Output
                            }
                            else {
                                Write-Output $Etag
                            }
                        }
                        catch {
                            Write-Output $_
                        }
                        finally {
                            $Task.Dispose()
                            $PutRequest.Dispose()
                            $StreamContent.Dispose()
                            $Stream.Dispose()
                        }
                    })

                if (($PartNumber * $Chunksize) -gt $FileSize) {
                    $ViewSize = $Chunksize - ($PartNumber * $Chunksize - $FileSize)
                }
                else {
                    $ViewSize = $Chunksize
                }

                Write-Verbose "Creating File view from position $(($PartNumber -1) * $Chunksize) with size $ViewSize"
                $Stream = $MemoryMappedFile.CreateViewStream(($PartNumber - 1) * $Chunksize, $ViewSize)

                $AwsRequest = $MultipartUpload | Write-S3ObjectPart -Config $Config -DryRun -PartNumber $PartNumber -Stream $Stream

                $Parameters = @{
                    Stream               = $Stream
                    Uri                  = $AwsRequest.Uri
                    Headers              = $AwsRequest.Headers
                    PartNumber           = $PartNumber
                    SkipCertificateCheck = $Config.SkipCertificateCheck
                    CancellationToken    = $CancellationToken
                }
                [void]$Runspace.AddParameters($Parameters)
                $Job = [PSCustomObject]@{
                    Pipe       = $Runspace
                    Status     = $Runspace.BeginInvoke()
                    PartNumber = $PartNumber
                }
                [void]$Jobs.Add($Job)
            }

            $PercentCompleted = 0

            Write-Progress -Activity "Uploading file $($InFile.Name) to $BucketName/$Key" -Status "0 MiB written (0% Complete) / 0 MiB/s /  / estimated time to completion: 0" -PercentComplete $PercentCompleted

            $StartTime = Get-Date

            while ($Jobs) {
                Start-Sleep -Milliseconds 500
                $CompletedJobs = $Jobs | Where-Object { $_.Status.IsCompleted -eq $true }
                foreach ($Job in $CompletedJobs) {
                    $Output = $Job.Pipe.EndInvoke($Job.Status)
                    if ($Output[0] -isnot [String]) {
                        Write-Verbose (ConvertTo-Json -InputObject $Output)
                        foreach ($Job in $Jobs) {
                            $CancellationToken = $CancellationTokenSource.Cancel()
                            $Job.Pipe.Stop()
                        }
                        throw "Upload of part $($Job.PartNumber) failed, Multipart Upload aborted with output`n$(ConvertTo-Json -InputObject $Output)"
                    }
                    $Etags[$Job.PartNumber] = $Output
                    Write-Verbose "Part $($Job.PartNumber) has completed with ETag $Output"
                    $Job.Pipe.Dispose()
                    $Jobs.Remove($Job)
                }

                # report progress
                $WrittenBytes = $PartUploadProgress.Clone().Values | Measure-Object -Sum | Select-Object -ExpandProperty Sum
                $PercentCompleted = $WrittenBytes / $InFile.Length * 100
                $Duration = ((Get-Date) - $StartTime).TotalSeconds
                $Throughput = $WrittenBytes / 1MB / $Duration
                if ($Throughput -gt 0) {
                    $EstimatedTimeToCompletion = [TimeSpan]::FromSeconds([Math]::Round(($InFile.Length - $WrittenBytes) / 1MB / $Throughput))
                }
                else {
                    $EstimatedTimeToCompletion = 0
                }

                $Activity = "Uploading file $($InFile.Name) to $BucketName/$Key"
                $Status = "{0:F2} MiB written | {1:F2}% Complete | {2:F2} MiB/s  | estimated time to completion: {3:g}" -f ($WrittenBytes / 1MB), $PercentCompleted, $Throughput, $EstimatedTimeToCompletion
                Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentCompleted
            }
        }
        catch {
            Write-Warning "Something has gone wrong, aborting Multipart Upload"
            $MultipartUpload | Stop-S3MultipartUpload -Config $Config
            throw $_
        }
        finally {
            Write-Verbose "Cleaning up"
            $MemoryMappedFile.Dispose()
            $RunspacePool.Close()
            $RunspacePool.Dispose()
        }

        if ($Jobs) {
            Write-Warning "Job(s) with partnumber(s) $($Jobs.PartNumber -join ',') did not complete, therfore aborting Multipart Upload"
            $MultipartUpload | Stop-S3MultipartUpload -Config $Config -Region $Region
        }
        else {
            Write-Progress -Activity "Uploading file $($InFile.Name) to $BucketName/$Key completed" -Completed
            Write-Host "Uploading file $($InFile.Name) of size $([Math]::Round($InFile.Length/1MB,4))MiB to $BucketName/$Key completed in $([Math]::Round($Duration,2)) seconds with average throughput of $Throughput MiB/s"
            Write-Verbose "Completing multipart upload"
            $MultipartUpload | Complete-S3MultipartUpload -Config $Config -Etags $Etags
            Write-Verbose "Completed multipart upload"
        }
    }
}

<#
    .SYNOPSIS
    Write S3 Object Part
    .DESCRIPTION
    Write S3 Object Part
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER Key
    Object key
    .PARAMETER UploadId
    Multipart Upload ID
    .PARAMETER PartNumber
    Multipart part number (from 1 to 10000)
    .PARAMETER Stream
    Content Stream
    .PARAMETER Content
    UTF-8 encoded content
    .PARAMETER Etags
    Part Etags in the format partNumber="ETag"
#>
function Global:Write-S3ObjectPart {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $True,
            Position = 9,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Object key")][Alias("Object")][String]$Key,
        [parameter(
            Mandatory = $True,
            Position = 10,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Multipart Upload ID")][String]$UploadId,
        [parameter(
            Mandatory = $True,
            Position = 11,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Multipart part number (from 1 to 10000)")][ValidateRange(1, 10000)][Int]$PartNumber,
        [parameter(
            Mandatory = $False,
            Position = 12,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Content Stream")][System.IO.Stream]$Stream,
        [parameter(
            Mandatory = $False,
            Position = 13,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "UTF-8 encoded content")][String]$Content,
        [parameter(
            Mandatory = $False,
            Position = 14,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Part Etags in the format partNumber=`"ETag`"")][System.Collections.Generic.SortedDictionary[int, string]]$Etags
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "PUT"
    }

    Process {
        Write-Verbose "Upload object part with key $Key to bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $Uri = "/$Key"

        $Query = @{partNumber = $PartNumber; uploadId = $UploadId }

        if ($Content) {
            $Stream = [System.IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes($Content))
        }

        $ContentLength = $Stream.Length

        $Headers = @{"content-length" = $ContentLength }

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Uri $Uri -Query $Query -BucketName $BucketName -Headers $Headers -Stream $Stream

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            try {
                # using CryptoSteam to calculate the MD5 sum while uploading the part
                # this allows to only read the stream once and increases performance compared with other S3 clients
                $Md5 = [System.Security.Cryptography.MD5]::Create()
                $CryptoStream = [System.Security.Cryptography.CryptoStream]::new($Stream, $Md5, [System.Security.Cryptography.CryptoStreamMode]::Read)

                $HttpClient = [System.Net.Http.HttpClient]::new()

                $PutRequest = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Put, $AwsRequest.Uri)

                $PutRequest.Headers.Add("Host", $AwsRequest.Headers["Host"])

                $StreamContent = [System.Net.Http.StreamContent]::new($CryptoStream)
                $StreamContent.Headers.ContentLength = $ContentLength
                $PutRequest.Content = $StreamContent

                if ($AwsRequest.Headers["Content-MD5"]) {
                    $PutRequest.Content.Headers.ContentMD5 = [Convert]::FromBase64String($AwsRequest.Headers["Content-MD5"])
                    $AwsRequest.Headers.Remove("Content-MD5")
                }
                elseif ($AwsRequest.Headers["Content-MD5"] -ne $null) {
                    Throw "Content-MD5 header specified but empty"
                }

                if ($AwsRequest.Headers["content-type"]) {
                    $PutRequest.Content.Headers.ContentType = $AwsRequest.Headers["content-type"]
                    $AwsRequest.Headers.Remove("content-type")
                }
                elseif ($AwsRequest.Headers["content-type"] -ne $null) {
                    Throw "content-type header specified but empty"
                }

                foreach ($HeaderKey in $AwsRequest.Headers.Keys) {
                    # AWS Authorization Header is not RFC compliant, therefore we need to skip header validation
                    if ($HeaderKey -eq "Authorization") {
                        $null = $PutRequest.Headers.TryAddWithoutValidation($HeaderKey, $Headers[$HeaderKey])
                    }
                    else {
                        $null = $PutRequest.Headers.Add($HeaderKey, $Headers[$HeaderKey])
                    }
                }

                Write-Verbose "Start upload of part $PartNumber"

                $StartTime = Get-Date

                $CancellationTokenSource = [System.Threading.CancellationTokenSource]::new()
                $CancellationToken = $CancellationTokenSource.Token
                $Task = $HttpClient.SendAsync($PutRequest, $CancellationToken)

                Write-Verbose "Report progress"
                while ($Stream.Position -ne $ContentLength -and !$Task.IsCanceled -and !$Task.IsFaulted -and !$Task.IsCompleted) {
                    Start-Sleep -Milliseconds 500
                    $WrittenBytes = $Stream.Position
                    $PercentCompleted = $WrittenBytes / $ContentLength * 100
                    $Duration = ((Get-Date) - $StartTime).TotalSeconds
                    $Throughput = $WrittenBytes / 1MB / $Duration
                    if ($Throughput -gt 0) {
                        $EstimatedTimeToCompletion = [TimeSpan]::FromSeconds([Math]::Round(($InFile.Length - $WrittenBytes) / 1MB / $Throughput))
                    }
                    else {
                        $EstimatedTimeToCompletion = 0
                    }
                    $Activity = "Uploading part to $BucketName/$Key"
                    $Status = "{0:F2} MiB written | {1:F2}% Complete | {2:F2} MiB/s  | estimated time to completion: {3:g}" -f ($WrittenBytes / 1MB), $PercentCompleted, $Throughput, $EstimatedTimeToCompletion
                    Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentCompleted
                }

                if ($Task.Exception) {
                    throw $Task.Exception
                }

                if ($Task.IsCanceled) {
                    Write-Warning "Upload was canceled with result $($Task.Result)"
                }

                $Etag = New-Object 'System.Collections.Generic.List[string]'
                [void]$Task.Result.Headers.TryGetValues("ETag", [ref]$Etag)
                $Etag = ($Etag | Select-Object -First 1) -replace '"', ''

                $CryptoStream.Dispose()
                $Md5Sum = [BitConverter]::ToString($Md5.Hash) -replace "-", ""

                Write-Verbose "Response Headers:`n$(ConvertTo-Json -InputObject $Task.Result.Headers)"

                if ($Task.Result.StatusCode -ne "OK") {
                    return $Task.Result
                }
                elseif ($Etag -ne $MD5Sum) {
                    throw "Etag $Etag does not match calculated MD5 sum $MD5Sum"
                }
                else {
                    $Etags[$PartNumber] = $Etag
                    Write-Output ([PSCustomObject]@{ETag = $Etag })
                }

                #$Task.Dispose()
                $PutRequest.Dispose()
                $StreamContent.Dispose()
                $CryptoStream.Dispose()
                $Stream.Dispose()
            }
            catch {
                $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'
                if ([int]$_.Exception.Response.StatusCode -match "^3" -and $_.Exception.Response.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                    Write-Warning "Request was redirected as bucket does not belong to region $Region. Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                    Write-S3Object -Config $Config -Region $($RedirectedRegion[0]) -Bucket $BucketName -Key $Key -UploadId $UploadId -PartNumber $PartNumber -Stream $Stream
                }
                else {
                    Throw
                }
            }
        }
    }
}

<#
    .SYNOPSIS
    Get S3 Object Parts
    .DESCRIPTION
    Get S3 Object Parts
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER Key
    Object key
    .PARAMETER UploadId
    Multipart Upload ID
    .PARAMETER EncodingType
    Encoding type (Only allowed value is url).
    .PARAMETER MaxParts
    Maximum Number of parts to return
    .PARAMETER PartNumberMarker
    Continuation part number marker
#>
function Global:Get-S3ObjectParts {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $True,
            Position = 9,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Object key")][Alias("Object")][String]$Key,
        [parameter(
            Mandatory = $True,
            Position = 10,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Multipart Upload ID")][String]$UploadId,
        [parameter(
            Mandatory = $False,
            Position = 11,
            HelpMessage = "Encoding type (Only allowed value is url).")][String][ValidateSet("url")]$EncodingType = "url",
        [parameter(
            Mandatory = $False,
            Position = 12,
            HelpMessage = "Maximum Number of parts to return")][Int][ValidateRange(0, 1000)]$MaxParts = 0,
        [parameter(
            Mandatory = $False,
            Position = 13,
            HelpMessage = "Continuation part number marker")][Alias("Marker")][String]$PartNumberMarker
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "GET"
    }

    Process {
        Write-Verbose "Get object parts for key $Key in bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $Uri = "/$Key"

        $Query = @{uploadId = $UploadId }
        if ($EncodingType) {
            $Query["encoding-type"] = $EncodingType
        }
        if ($MaxParts -ge 1) {
            $Query["max-parts"] = $MaxParts
        }
        if ($PartNumberMarker) {
            $Query["part-number-marker"] = $PartNumberMarker
        }

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -Uri $Uri -Query $Query -BucketName $BucketName

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                $Content = [XML]$Task.Result.Content.ReadAsStringAsync().Result

                $Parts = $Content.ListPartsResult.Part | Where-Object { $_ }

                $UnicodeBucket = ConvertFrom-Punycode -BucketName $Content.ListPartsResult.Bucket

                foreach ($Part in $Parts) {
                    $Part = [PSCustomObject]@{  Region = $Region;
                        BucketName                     = $UnicodeBucket;
                        Key                            = [System.Net.WebUtility]::UrlDecode($Content.ListPartsResult.Key);
                        UploadId                       = [System.Net.WebUtility]::UrlDecode($Content.ListPartsResult.UploadId);
                        InitiatorId                    = [System.Net.WebUtility]::UrlDecode($Content.ListPartsResult.Initiator.ID);
                        InitiatorDisplayName           = [System.Net.WebUtility]::UrlDecode($Content.ListPartsResult.Initiator.DisplayName);
                        OwnerId                        = [System.Net.WebUtility]::UrlDecode($Content.ListPartsResult.Owner.ID);
                        OwernDisplayName               = [System.Net.WebUtility]::UrlDecode($Content.ListPartsResult.Owner.DisplayName);
                        StorageClass                   = [System.Net.WebUtility]::UrlDecode($Content.ListPartsResult.StorageClass);
                        PartNumber                     = $Part.PartNumber;
                        LastModified                   = [DateTime]$Part.LastModified;
                        ETag                           = [System.Net.WebUtility]::UrlDecode($Part.ETag);
                        Size                           = $Part.Size
                    }

                    Write-Output $Part
                }

                if ($Content.ListPartsResult.IsTruncated -eq "true" -and $MaxParts -eq 0) {
                    Write-Verbose "1000 Parts were returned and max parts was not limited so continuing to get all parts"
                    Write-Verbose "NextPartNumberMarker: $($Content.ListPartsResult.NextPartNumberMarker)"
                    Get-S3ObjectParts -Config $Config -Presign:$Presign -BucketName $BucketName -Key $Key -UploadId $UploadId -EncodingType $EncodingType -MaxParts $MaxParts -PartNumberMarker $Content.ListPartsResult.NextPartNumberMarker
                }
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Get-S3ObjectParts -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName -Key $Key -UploadId $UploadId -EncodingType $EncodingType -MaxParts $MaxParts -PartNumberMarker $PartNumberMarker
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Get-S3ObjectParts -Config $Config -Presign:$Presign -BucketName $BucketName -Region $($RedirectedRegion[0]) -Key $Key -UploadId $UploadId -EncodingType $EncodingType -MaxParts $MaxParts -PartNumberMarker $PartNumberMarker
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

New-Alias -Name Remove-S3ObjectVersion -Value Remove-S3Object
<#
    .SYNOPSIS
    Remove S3 Object
    .DESCRIPTION
    Remove S3 Object
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER Key
    Object Key
    .PARAMETER VersionId
    Object version ID
#>
function Global:Remove-S3Object {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $True,
            Position = 9,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Object key")][Alias("Object")][String]$Key,
        [parameter(
            Mandatory = $False,
            Position = 10,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Object version ID")][String]$VersionId
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "DELETE"
    }

    Process {
        Write-Verbose "Delete key $Key in bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $Uri = "/$Key"

        if ($VersionId) {
            $Query = @{versionId = $VersionId }
        }
        else {
            $Query = @{ }
        }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Uri $Uri -Query $Query

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                # do nothing
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Remove-S3Object -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName -Key $Key -VersionId $VersionId
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Remove-S3Object -Config $Config -Presign:$Presign -Region $($RedirectedRegion[0]) -BucketName $BucketName -Key $Key -VersionId $VersionId
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

New-Alias -Name Copy-S3ObjectToObject -Value Copy-S3Object
New-Alias -Name Copy-S3ObjectToFile -Value Copy-S3Object
New-Alias -Name Copy-S3FileToObject -Value Copy-S3Object
<#
    .SYNOPSIS
    Copy S3 Object
    .DESCRIPTION
    Copy S3 Object
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER Key
    Object key
    .PARAMETER VersionId
    Object version ID
    .PARAMETER DestinationServer
    Destination StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
    .PARAMETER DestinationProfileName
    Destination AWS Profile to use which contains AWS credentials and settings
    .PARAMETER DestinationProfileLocation
    Destination AWS Profile location if different than .aws/credentials
    .PARAMETER DestinationAccessKey
    Destination S3 Access Key
    .PARAMETER DestinationSecretKey
    Destination S3 Secret Access Key
    .PARAMETER DestinationAccountId
    Destination StorageGRID account ID to execute this command against
    .PARAMETER DestinationConfig
    Destination AWS config
    .PARAMETER DestinationBucketName
    Destination Bucket (if not specified will be same as source)
    .PARAMETER DestinationRegion
    Destination region to be used
    .PARAMETER DestinationKey
    Destination object key (if not specified will be same as source)
    .PARAMETER MetadataDirective
    Object version ID
    .PARAMETER Metadata
    Metadata
    .PARAMETER Etag
    Copies the object if its entity tag (ETag) matches the specified Etag
    .PARAMETER NotEtag
    Copies the object if its entity tag (ETag) is different than the specified NotETag
    .PARAMETER UnmodifiedSince
    Copies the object if it hasn't been modified since the specified time
    .PARAMETER ModifiedSince
    Copies the object if it has been modified since the specified time
    .PARAMETER StorageClass
    Destination S3 Storage Class
    .PARAMETER TaggingDirective
    Specifies whether the object tags are copied from the source object or replaced with tags provided in the request
    .PARAMETER Tags
    Object tags
    .PARAMETER ServerSideEncryption
    Server side encryption
#>
function Global:Copy-S3Object {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket","SourceBucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $True,
            Position = 9,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Object key")][Alias("Object","SourceKey")][String]$Key,
        [parameter(
            Mandatory = $False,
            Position = 10,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Object version ID")][String]$VersionId,
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 11,
            HelpMessage = "Destination StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$DestinationServer,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 11,
            HelpMessage = "Destination AWS Profile to use which contains AWS credentials and settings")][Alias("DestinationProfile")][String]$DestinationProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 11,
            HelpMessage = "Destination AWS Profile location if different than .aws/credentials")][String]$DestinationProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 11,
            HelpMessage = "Destination S3 Access Key")][String]$DestinationAccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 12,
            HelpMessage = "Destination S3 Secret Access Key")][Alias("DestinationSecretAccessKey")][String]$DestinationSecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 11,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Destination StorageGRID account ID to execute this command against")][Alias("DestinationOwnerId")][String]$DestinationAccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 11,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Destination AWS config")][PSCustomObject]$DestinationConfig,
        [parameter(
            Mandatory = $False,
            Position = 13,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Destination Bucket (if not specified will be same as source)")][Alias("DestinationBucket")][String]$DestinationBucketName,
        [parameter(
            Mandatory = $False,
            Position = 14,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Destination region to be used")][String]$DestinationRegion,
        [parameter(
            Mandatory = $False,
            Position = 15,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Destination object key (if not specified will be same as source)")][String]$DestinationKey,
        [parameter(
            Mandatory = $False,
            Position = 16,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Object version ID")][ValidateSet("COPY", "REPLACE")][String]$MetadataDirective,
        [parameter(
            Mandatory = $False,
            Position = 17,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Metadata")][Hashtable]$Metadata,
        [parameter(
            Mandatory = $False,
            Position = 18,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Copies the object if its entity tag (ETag) matches the specified Etag")][String]$Etag,
        [parameter(
            Mandatory = $False,
            Position = 19,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Copies the object if its entity tag (ETag) is different than the specified NotETag")][String]$NotEtag,
        [parameter(
            Mandatory = $False,
            Position = 20,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Copies the object if it hasn't been modified since the specified time")][String]$UnmodifiedSince,
        [parameter(
            Mandatory = $False,
            Position = 21,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Copies the object if it has been modified since the specified time")][String]$ModifiedSince,
        [parameter(
            Mandatory = $False,
            Position = 22,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Destination S3 Storage Class")][ValidateSet("", "STANDARD", "STANDARD_IA", "REDUCED_REDUNDANCY")][String]$StorageClass,
        [parameter(
            Mandatory = $False,
            Position = 23,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Specifies whether the object tags are copied from the source object or replaced with tags provided in the request")][ValidateSet("", "COPY", "REPLACE")][String]$TaggingDirective,
        [parameter(
            Mandatory = $False,
            Position = 24,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Object tags")][HashTable]$Tags,
        [parameter(
            Mandatory = $False,
            Position = 25,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Server side encryption")][ValidateSet("", "aws:kms", "AES256")][String]$ServerSideEncryption,
        [parameter(
            Mandatory = $False,
            Position = 25,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Force client side copy")][System.Management.Automation.SwitchParameter]$ClientSideCopy
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        if (!$DestinationConfig -and ($DestinationProfileName -or $DestinationAccessKey -or $DestinationAccountId -or $DestinationServer)) {
            $DestinationConfig = Get-AwsConfig -Server $DestinationServer -EndpointUrl $DestinationEndpointUrl -ProfileName $DestinationProfileName -ProfileLocation $DestinationProfileLocation -AccessKey $DestinationAccessKey -SecretKey $DestinationSecretKey -AccountId $DestinationAccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "PUT"
    }

    Process {
        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        if ($DestinationAccountId) {
            $DestinationConfig = Get-AwsConfig -Server $DestinationServer -EndpointUrl $DestinationServer.S3EndpointUrl -AccessKey $DestinationAccessKey -SecretKey $DestinationSecretKey -AccountId $DestinationAccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found for source"
        }

        if (!$DestinationConfig.AccessKey) {
            Write-Verbose "No destination config provided, assuming destination is same as source configuration"
            $DestinationConfig = $Config
        }

        if ($Config.AccessKey -eq $DestinationConfig.AccessKey -and -not $ClientSideCopy.IsPresent) {
            Write-Verbose "Using server side copy (PUT Object Copy)"
            $ServerSideCopy = $true
        }
        else {
            Write-Verbose "Using client side copy (Stream copy)"
            $ServerSideCopy = $false
        }

        if ($Region) {
            $Config.Region = $Region
        }
        if ($DestinationRegion) {
            $DestinationConfig.Region = $DestinationRegion
        }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        if (!$DestinationBucketName) {
            $DestinationBucketName = $BucketName
        }
        if (!$DestinationKey) {
            $DestinationKey = $Key
        }

        $DestinationBucketName = ConvertTo-Punycode -Config $Config -BucketName $DestinationBucketName

        $Headers = @{ }

        if ($Metadata) {
            foreach ($MetadataKey in $Metadata.Keys) {
                $MetadataKey = $MetadataKey -replace "^x-amz-meta-", ""
                $MetadataKey = $MetadataKey.ToLower()
                $Headers["x-amz-meta-$MetadataKey"] = $Metadata[$MetadataKey]
                # TODO: check that metadata is valid HTTP Header
            }
            $MetadataDirective = "REPLACE"
        }

        if ($StorageClass) {
            $Headers["x-amz-storage-class"] = $StorageClass
        }

        if ($ServerSideEncryption) {
            $Headers["x-amz-server-side-encryption"] = $ServerSideEncryption
        }

        $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

        if ($ServerSideCopy) {
            $Uri = "/$DestinationKey"

            if ($Tags) {
                $TaggingDirective = "REPLACE"
            }

            $Headers["x-amz-copy-source"] = "/$BucketName/$Key"
            if ($VersionId) {
                $Headers["x-amz-copy-source"] += "?versionId=$VersionId"
            }
            if ($MetadataDirective) {
                $Headers["x-amz-metadata-directive"] = $MetadataDirective
            }
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
            if ($TaggingDirective) {
                $Headers["x-amz-tagging-directive"] = $TaggingDirective
            }

            $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -Uri $Uri -Headers $Headers -BucketName $DestinationBucketName

            if ($DryRun) {
                Write-Output $AwsRequest
            }
            else {
                $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck

                $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

                if ($Task.Result.IsSuccessStatusCode) {
                    $Content = [XML]$Task.Result.Content.ReadAsStringAsync().Result

                    foreach ($Rule in $Content.ServerSideEncryptionConfiguration.Rule) {
                        $Output = [PSCustomObject]@{SSEAlgorithm = $Rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm;
                            KMSMasterKeyID                       = $Rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID
                        }
                        Write-Output $Output
                    }
                }
                elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                    $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                    $RetryCount++
                    Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                    Start-Sleep -Seconds $SleepSeconds
                    Get-S3BucketEncryption -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName
                }
                elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                    Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
                }
                elseif ($Task.Exception -match "Device not configured") {
                    Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
                }
                elseif ($Task.IsFaulted) {
                    Throw $Task.Exception
                }
                elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                    Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                    Get-S3BucketEncryption -Config $Config -Presign:$Presign -Region $($RedirectedRegion[0]) -BucketName $BucketName
                }
                elseif ($Task.Result) {
                    $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                    if ($Result.Error.Message) {
                        Throw $Result.Error.Message
                    }
                    else {
                        Throw $Task.Result.StatusCode
                    }
                }
                else {
                    Throw "Task failed with status $($Task.Status)"
                }
            }
        }
        else {
            if ($DryRun) {
                Throw "Cannot use -DryRun for client side copy"
            }

            $SourceUri = "/$Key"
            $DestinationUri = "/$DestinationKey"

            $SourceAwsRequest = Get-AwsRequest -Config $Config -Method "GET" -Presign:$Presign -Uri $SourceUri -BucketName $BucketName
            $DestinationAwsRequest = Get-AwsRequest -Config $DestinationConfig -Method "PUT" -Presign:$Presign -Uri $DestinationUri -Headers $Headers -BucketName $DestinationBucketName

            $SourceTask = $SourceAwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck

            if ($SourceTask.Result.IsSuccessStatusCode) {
                Write-Verbose "Source request was successfull"
                $httpCopyClient = [System.Net.Http.HttpCopyClient]::new();
                $putRequest = $DestinationAwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck -DryRun

                # TODO: copy S3 metadata from GET response to PUT request

                # TODO: Move cancellation to beginning of cmdlet
                $CancellationTokenSource = [System.Threading.CancellationTokenSource]::new()
                $CancellationToken = $CancellationTokenSource.Token
                $CancellationTokenVariable = [System.Management.Automation.Runspaces.SessionStateVariableEntry]::new('CancellationToken', $CancellationToken, $Null)

                $DestinationTask = $httpCopyClient.CopyAsync($SourceTask.Result,$putRequest, $CancellationToken);
                try {
                    $DestinationTask.Result.EnsureSuccessStatusCode
                }
                finally {
                    if (!$DestinationTask.IsCompleted) {
                        $CancellationTokenSource.Cancel()
                    }
                }

                # TODO: properly implement retries and dispose GET and PUT requests properly
                if ($DestinationTask.Result.IsSuccessStatusCode) {
                    Write-Host "success"
                }
                elseif ($DestinationTask.IsCanceled -or $DestinationTask.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                    $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                    $RetryCount++
                    Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                    Start-Sleep -Seconds $SleepSeconds
                    Copy-S3Object -Config $Config -DestinationConfig $DestinationConfig -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName -Key $Key -VersionId $VersionId -DestinationBucketName $DestinationBucketName -DestinationKey $DestinationKey -MetadataDirective $MetadataDirective -Metadata $Metadata -Etag $Etag -NotEtag $NotEtag -UnmodifiedSince $UnmodifiedSince -ModifiedSince $ModifiedSince -StorageClass $StorageClass -TaggingDirective $TaggingDirective -Tags $Tags -ServerSideEncryption $ServerSideEncryption
                }
                elseif ($DestinationTask.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                    Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
                }
                elseif ($DestinationTask.Exception -match "Device not configured") {
                    Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
                }
                elseif ($DestinationTask.IsFaulted) {
                    return $DestinationTask
                    Throw $DestinationTask.Exception
                }
                elseif ($DestinationTask.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                    Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                    Copy-S3Object -Config $Config -DestinationConfig $DestinationConfig -Presign:$Presign -DestinationRegion $($RedirectedRegion[0]) -BucketName $BucketName -Key $Key -VersionId $VersionId -DestinationBucketName $DestinationBucketName -DestinationKey $DestinationKey -MetadataDirective $MetadataDirective -Metadata $Metadata -Etag $Etag -NotEtag $NotEtag -UnmodifiedSince $UnmodifiedSince -ModifiedSince $ModifiedSince -StorageClass $StorageClass -TaggingDirective $TaggingDirective -Tags $Tags -ServerSideEncryption $ServerSideEncryption
                }
                elseif ($DestinationTask.Result) {
                    $Result = [XML]$DestinationTask.Result.Content.ReadAsStringAsync().Result
                    if ($Result.Error.Message) {
                        Throw $Result.Error.Message
                    }
                    else {
                        Throw $DestinationTask.Result.StatusCode
                    }
                }
                else {
                    Throw "Task failed with status $($DestinationTask.Status)"
                }
            }
            elseif ($SourceTask.IsCanceled -or $SourceTask.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Copy-S3Object -Config $Config -DestinationConfig $DestinationConfig -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName -Key $Key -VersionId $VersionId -DestinationBucketName $DestinationBucketName -DestinationKey $DestinationKey -MetadataDirective $MetadataDirective -Metadata $Metadata -Etag $Etag -NotEtag $NotEtag -UnmodifiedSince $UnmodifiedSince -ModifiedSince $ModifiedSince -StorageClass $StorageClass -TaggingDirective $TaggingDirective -Tags $Tags -ServerSideEncryption $ServerSideEncryption
            }
            elseif ($SourceTask.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($SourceTask.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($SourceTask.IsFaulted) {
                Throw $SourceTask.Exception
            }
            elseif ($SourceTask.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Copy-S3Object -Config $Config -DestinationConfig $DestinationConfig -Presign:$Presign -Region $($RedirectedRegion[0]) -BucketName $BucketName -Key $Key -VersionId $VersionId -DestinationBucketName $DestinationBucketName -DestinationKey $DestinationKey -MetadataDirective $MetadataDirective -Metadata $Metadata -Etag $Etag -NotEtag $NotEtag -UnmodifiedSince $UnmodifiedSince -ModifiedSince $ModifiedSince -StorageClass $StorageClass -TaggingDirective $TaggingDirective -Tags $Tags -ServerSideEncryption $ServerSideEncryption
            }
            elseif ($SourceTask.Result) {
                $Result = [XML]$SourceTask.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $SourceTask.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($SourceTask.Status)"
            }
        }
    }
}

<#
    .SYNOPSIS
    Retrieve Object Tagging
    .DESCRIPTION
    Retrieve Object Tagging
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER Key
    Object Key
#>
function Global:Get-S3ObjectTagging {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $True,
            Position = 9,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Object key")][Alias("Object")][String]$Key
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "GET"
    }

    Process {
        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $Query = @{tagging = "" }

        $Uri = "/$Key"

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Uri $Uri -Query $Query

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                $Content = [XML]$Task.Result.Content.ReadAsStringAsync().Result

                foreach ($Tag in $Content.Tagging.TagSet.Tag) {
                    $Output = [System.Collections.DictionaryEntry]@{Name = $Tag.Key; Value = $Tag.Value }
                    Write-Output $Output
                }
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Get-S3ObjectTagging -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName -Key $Key
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Get-S3ObjectTagging -Config $Config -Presign:$Presign -Region $($RedirectedRegion[0]) -BucketName $BucketName -Key $Key
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

<#
    .SYNOPSIS
    Set Object Tagging
    .DESCRIPTION
    Set Object Tagging
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER Key
    Object Key
    .PARAMETER Tags
    List of Name Value pairs e.g. @(@{Name='Key1';Value='Value1'},@{Name='Key1';Value='Value1'})
#>
function Global:Set-S3ObjectTagging {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $True,
            Position = 9,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Object key")][Alias("Object")][String]$Key,
        [parameter(
            Mandatory = $True,
            Position = 10,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "List of Key Value pairs e.g. @(@{Key='Key1';Value='Value1'},@{Key='Key2';Value='Value2'})")][System.Collections.DictionaryEntry[]]$Tags
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "PUT"
    }

    Process {
        Write-Verbose "Retrieving object tagging for key $Key in bucket $BucketName"
        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $Query = @{tagging = "" }

        $Uri = "/$Key"

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $Body = "<Tagging>"
        $Body += "<TagSet>"
        foreach ($Tag in $Tags) {
            if ($Tag.Key) {
                $Key = $Tag.Key
            }
            else {
                $Key = $Tag.Name
            }
            $Value = $Tag.Value
            $Body += "<Tag><Key>$Key</Key><Value>$Value</Value></Tag>"
        }
        $Body += "</TagSet>"
        $Body += "</Tagging>"

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Uri $Uri -Query $Query -RequestPayload $Body

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck -Body $Body

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                # do nothing
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Set-S3ObjectTagging -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName -Key $Key -Tags $Tags
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Set-S3ObjectTagging -Config $Config -Presign:$Presign -Region $($RedirectedRegion[0]) -BucketName $BucketName -Key $Key -Tags $Tags
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

<#
    .SYNOPSIS
    Remove Object Tagging
    .DESCRIPTION
    Remove Object Tagging
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER Key
    Object Key
#>
function Global:Remove-S3ObjectTagging {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $True,
            Position = 9,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Object key")][Alias("Object")][String]$Key
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "DELETE"
    }

    Process {
        Write-Verbose "Setting object tagging for key $Key in bucket $BucketName"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $Query = @{tagging = "" }
        $Uri = "/$Key"

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -BucketName $BucketName -Uri $Uri -Query $Query

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                # do nothing
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Remove-S3ObjectTagging -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName -Key $Key
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Remove-S3ObjectTagging -Config $Config -Presign:$Presign -Region $($RedirectedRegion[0]) -BucketName $BucketName -Key $Key
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

# StorageGRID specific #

<#
    .SYNOPSIS
    Get S3 Bucket Consistency Setting
    .DESCRIPTION
    Get S3 Bucket Consistency Setting
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
#>
function Global:Get-S3BucketConsistency {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "GET"
    }

    Process {
        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $Query = @{"x-ntap-sg-consistency" = "" }

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -Uri $Uri -Query $Query -BucketName $BucketName

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                $Content = [XML]$Task.Result.Content.ReadAsStringAsync().Result

                $BucketNameConsistency = [PSCustomObject]@{Bucket = $BucketName; Consistency = $Content.Consistency.InnerText }

                Write-Output $BucketNameConsistency
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Get-S3BucketConsistency -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Get-S3BucketConsistency -Config $Config -Presign:$Presign -BucketName $BucketName -Region $($RedirectedRegion[0])
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

<#
    .SYNOPSIS
    Modify S3 Bucket Consistency Setting
    .DESCRIPTION
    Modify S3 Bucket Consistency Setting
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
    .PARAMETER Consistency
    Bucket consistency
#>
function Global:Update-S3BucketConsistency {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $True,
            Position = 9,
            HelpMessage = "Bucket consistency")][ValidateSet("all", "strong-global", "strong-site", "read-after-new-write", "available", "weak")][String]$Consistency
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "PUT"
    }

    Process {
        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $Query = @{"x-ntap-sg-consistency" = $Consistency }

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -Uri $Uri -Query $Query -BucketName $BucketName

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                # do nothing
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Set-S3BucketConsistency -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName -Consistency $Consistency
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Set-S3BucketConsistency -Config $Config -Presign:$Presign -BucketName $BucketName -Region $($RedirectedRegion[0]) -Consistency $Consistency
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

<#
    .SYNOPSIS
    Get S3 Bucket Storage Usage
    .DESCRIPTION
    Get S3 Bucket Storage Usage
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
#>
function Global:Get-S3StorageUsage {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "GET"
    }

    Process {
        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        $Uri = "/"

        $Query = @{"x-ntap-sg-usage" = "" }

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -Uri $Uri -Query $Query

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                $Content = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                $UsageResult = [PSCustomObject]@{CalculationTime = (Get-Date -Date $Content.UsageResult.CalculationTime); ObjectCount = $Content.UsageResult.ObjectCount; DataBytes = $Content.UsageResult.DataBytes; buckets = $Content.UsageResult.Buckets.ChildNodes }
                Write-Output $UsageResult
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Get-S3StorageUsage -Config $Config -Presign:$Presign -RetryCount $RetryCount
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

<#
    .SYNOPSIS
    Get S3 Bucket Last Access Time
    .DESCRIPTION
    Get S3 Bucket Last Access Time
        .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
#>
function Global:Get-S3BucketLastAccessTime {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "GET"
    }

    Process {
        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $Query = @{"x-ntap-sg-lastaccesstime" = "" }

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -Uri $Uri -Query $Query -BucketName $BucketName

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                $Content = [XML]$Task.Result.Content.ReadAsStringAsync().Result

                $BucketNameLastAccessTime = [PSCustomObject]@{Bucket = $BucketName; LastAccessTime = $Content.LastAccessTime.InnerText }

                Write-Output $BucketNameLastAccessTime
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Get-S3BucketConsistency -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Get-S3BucketConsistency -Config $Config -Presign:$Presign -BucketName $BucketName -Region $($RedirectedRegion[0])
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

<#
    .SYNOPSIS
    Enable S3 Bucket Last Access Time
    .DESCRIPTION
    Enable S3 Bucket Last Access Time
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
#>
function Global:Enable-S3BucketLastAccessTime {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "PUT"
    }

    Process {
        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $Query = @{"x-ntap-sg-lastaccesstime" = "enabled" }

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -Uri $Uri -Query $Query -BucketName $BucketName

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                # do nothing
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Get-S3BucketConsistency -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Get-S3BucketConsistency -Config $Config -Presign:$Presign -BucketName $BucketName -Region $($RedirectedRegion[0])
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

<#
    .SYNOPSIS
    Disable S3 Bucket Last Access Time
    .DESCRIPTION
    Disable S3 Bucket Last Access Time
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
#>
function Global:Disable-S3BucketLastAccessTime {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
        $Method = "PUT"
    }

    Process {
        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if (!$Config.AccessKey) {
            Throw "No S3 credentials found"
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $Query = @{"x-ntap-sg-lastaccesstime" = "disabled" }

        $AwsRequest = Get-AwsRequest -Config $Config -Method $Method -Presign:$Presign -Uri $Uri -Query $Query -BucketName $BucketName

        if ($DryRun.IsPresent) {
            Write-Output $AwsRequest
        }
        else {
            $Task = $AwsRequest | Invoke-AwsRequest -SkipCertificateCheck:$Config.SkipCertificateCheck

            $RedirectedRegion = New-Object 'System.Collections.Generic.List[string]'

            if ($Task.Result.IsSuccessStatusCode) {
                # do nothing
            }
            elseif ($Task.IsCanceled -or $Task.Result.StatusCode -match "500" -and $RetryCount -lt $MAX_RETRIES) {
                $SleepSeconds = [System.Math]::Pow(3, $RetryCount)
                $RetryCount++
                Write-Warning "Command failed, starting retry number $RetryCount of $MAX_RETRIES retries after waiting for $SleepSeconds seconds"
                Start-Sleep -Seconds $SleepSeconds
                Get-S3BucketConsistency -Config $Config -Presign:$Presign -RetryCount $RetryCount -BucketName $BucketName
            }
            elseif ($Task.Status -eq "Canceled" -and $RetryCount -ge $MAX_RETRIES) {
                Throw "Task canceled due to connection timeout and maximum number of $MAX_RETRIES retries reached."
            }
            elseif ($Task.Exception -match "Device not configured") {
                Throw "Task canceled due to issues with the network connection to endpoint $($Config.EndpointUrl)"
            }
            elseif ($Task.IsFaulted) {
                Throw $Task.Exception
            }
            elseif ($Task.Result.Headers.TryGetValues("x-amz-bucket-region", [ref]$RedirectedRegion)) {
                Write-Warning "Request was redirected as bucket does not belong to region $($Config.Region). Repeating request with region $($RedirectedRegion[0]) returned by S3 service."
                Get-S3BucketConsistency -Config $Config -Presign:$Presign -BucketName $BucketName -Region $($RedirectedRegion[0])
            }
            elseif ($Task.Result) {
                $Result = [XML]$Task.Result.Content.ReadAsStringAsync().Result
                if ($Result.Error.Message) {
                    Throw $Result.Error.Message
                }
                else {
                    Throw $Task.Result.StatusCode
                }
            }
            else {
                Throw "Task failed with status $($Task.Status)"
            }
        }
    }
}

<#
    .SYNOPSIS
    Trigger bucket mirroring
    .DESCRIPTION
    Trigger bucket mirroring - requires Bucket replication to already be set up
#>
function Global:Invoke-S3BucketMirroring {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            Mandatory = $False,
            Position = 1,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "AWS Signer type (S3 for V2 Authentication and AWS4 for V4 Authentication)")][String][ValidateSet("S3", "AWS4")]$SignerType = "AWS4",
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $True,
            Position = 6,
            HelpMessage = "AWS Profile to use which contains AWS sredentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 7,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $True,
            Position = 6,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $True,
            Position = 7,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $True,
            Position = 6,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $False,
            Position = 9,
            HelpMessage = "Bucket URL Style (Default: Auto)")][String][ValidateSet("path", "virtual", "auto", "virtual-hosted")]$UrlStyle = "auto",
        [parameter(
            Mandatory = $True,
            Position = 10,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 11,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Enable Payload Signing")][Switch]$PayloadSigning
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -SkipCertificateCheck:$SkipCertificateCheck -PayloadSigning $PayloadSigning
    }

    Process {
        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $BucketName = ConvertTo-Punycode -Config $Config -BucketName $BucketName

        $BucketReplication = Get-S3BucketReplication -EndpointUrl $Config.EndpointUrl -AccessKey $Config.AccessKey -SecretKey $Config.SecretKey -SkipCertificateCheck:$Config.SkipCertificateCheck -BucketName $BucketName

        if (!$BucketReplication) {
            Write-Host "No bucket replication configured for bucket $BucketName"
            $BucketReplicationChoice = $Host.UI.PromptForChoice("Continue without bucket replication",
                "Continue even though no bucket replication is configured?",
                @("&Yes", "&No"),
                1)
            if ($BucketReplicationChoice -eq 1) {
                break
            }
        }

        Get-S3Objects -EndpointUrl $Config.EndpointUrl -AccessKey $Config.AccessKey -SecretKey $Config.SecretKey -SkipCertificateCheck:$Config.SkipCertificateCheck -BucketName $BucketName | Get-S3ObjectMetadata -EndpointUrl $Config.EndpointUrl -AccessKey $Config.AccessKey -SecretKey $Config.SecretKey -SkipCertificateCheck:$Config.SkipCertificateCheck | Copy-S3Object -EndpointUrl $Config.EndpointUrl -AccessKey $Config.AccessKey -SecretKey $Config.SecretKey -SkipCertificateCheck:$Config.SkipCertificateCheck -MetadataDirective REPLACE
    }
}

<#
    .SYNOPSIS
    Test if S3 Object exists and if it matches specific criteria.
    .DESCRIPTION
    Test if S3 Object exists and if it matches specific criteria.
    .PARAMETER Server
    StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.
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
    .PARAMETER Config
    AWS config
    .PARAMETER SkipCertificateCheck
    Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.
    .PARAMETER EndpointUrl
    Custom S3 Endpoint URL
    .PARAMETER Presign
    Use presigned URL
    .PARAMETER DryRun
    Do not execute request, just return request URI and Headers
    .PARAMETER RetryCount
    Current retry count
    .PARAMETER BucketName
    Bucket Name
    .PARAMETER Region
    Bucket Region
#>
function Global:Test-S3Object {
    [CmdletBinding(DefaultParameterSetName = "none")]

    PARAM (
        [parameter(
            ParameterSetName = "server",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "StorageGRID Webscale Management Server object. If not specified, global CurrentSgwServer object will be used.")][PSCustomObject]$Server,
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "AWS Profile to use which contains AWS credentials and settings")][Alias("Profile")][String]$ProfileName = "",
        [parameter(
            ParameterSetName = "profile",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "AWS Profile location if different than .aws/credentials")][String]$ProfileLocation,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 0,
            HelpMessage = "S3 Access Key")][String]$AccessKey,
        [parameter(
            ParameterSetName = "keys",
            Mandatory = $False,
            Position = 1,
            HelpMessage = "S3 Secret Access Key")][Alias("SecretAccessKey")][String]$SecretKey,
        [parameter(
            ParameterSetName = "account",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "StorageGRID account ID to execute this command against")][Alias("OwnerId")][String]$AccountId,
        [parameter(
            ParameterSetName = "config",
            Mandatory = $False,
            Position = 0,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "AWS config")][PSCustomObject]$Config,
        [parameter(
            Mandatory = $False,
            Position = 2,
            HelpMessage = "Skips certificate validation checks. This includes all validations such as expiration, revocation, trusted root authority, etc.")][Switch]$SkipCertificateCheck,
        [parameter(
            Mandatory = $False,
            Position = 3,
            HelpMessage = "Custom S3 Endpoint URL")][System.UriBuilder]$EndpointUrl,
        [parameter(
            Mandatory = $False,
            Position = 4,
            HelpMessage = "Use presigned URL")][Switch]$Presign,
        [parameter(
            Mandatory = $False,
            Position = 5,
            HelpMessage = "Do not execute request, just return request URI and Headers")][Switch]$DryRun,
        [parameter(
            Mandatory = $False,
            Position = 6,
            HelpMessage = "Current retry count")][Int]$RetryCount = 0,
        [parameter(
            Mandatory = $True,
            Position = 7,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Bucket")][Alias("Name", "Bucket")][String]$BucketName,
        [parameter(
            Mandatory = $False,
            Position = 8,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Region to be used")][String]$Region,
        [parameter(
            Mandatory = $True,
            Position = 9,
            ValueFromPipelineByPropertyName = $True,
            HelpMessage = "Object Key")][Alias("Object")][String]$Key
    )

    Begin {
        if (!$Server) {
            $Server = $Global:CurrentSgwServer
        }
        if (!$Config) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $EndpointUrl -ProfileName $ProfileName -ProfileLocation $ProfileLocation -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }
    }

    Process {
        Write-Verbose "Test if key $Key in bucket $BucketName exists"

        if ($AccountId) {
            $Config = Get-AwsConfig -Server $Server -EndpointUrl $Server.S3EndpointUrl -AccessKey $AccessKey -SecretKey $SecretKey -AccountId $AccountId -SkipCertificateCheck:$SkipCertificateCheck
        }

        if ($Region) {
            $Config.Region = $Region
        }

        $Metadata = $null
        try {
            $Metadata = Get-S3ObjectMetadata -Config $Config -BucketName $BucketName -Key $Key
        }
        catch { }

        if ($Metadata) {
            Write-Output $true
        }
        else {
            Write-Output $false
        }
    }
}
