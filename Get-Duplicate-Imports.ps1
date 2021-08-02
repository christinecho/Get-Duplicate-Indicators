<#
# Script requires WindowsDefenderATP\TI.ReadWrite.All API permissions
# Enter your tenant ID, Client ID, and Client Secret in Get-MDEtoken.

.SYNOPSIS
This script takes in a csv file of indicators and identifies duplicates before importing
.DESCRIPTION
Defender for Endpoint allows users to create duplicate indicators which may pose a problem
due to the indicator limit. This script enumerates indicators on the tenant and identifies
multiple types of duplicates. Type duplicates detected are:
1) File indicators already blocked by Defender (checks using Virus Total API). Note the 4 calls/minute limit.
2) File indicators with collisions in MDE (i.e. if importing sha256, checks if equivalent sha1 and md5 in MDE)
3) Indicators with same enforcement target and rbac group but different Action 
Detected duplicates are output, with the option to import the remaining nonduplicate.
.PARAMETER FilePath
Path to csv file with indicators that you want to detect duplicates for and import if desired.
.PARAMETER VTKey
This is your Virus Total API key. Use parameter if importing file indicators.
.PARAMETER IndicatorType
The type of indicator being imported. Options are FileSha1, FileSha256, IpAddress, DomainName, and Url.
.PARAMETER Import
If the -Import switch is specified, the nonduplicate indicators will be imported. If not specified,
the script will still detect and output duplicates but will not import the remaining indicators.
.PARAMETER Action, Severity, Title, Description, RecommendedActions, Expiration, RbacGroup
These parameters are optional. If the parameters are not set, will use default values.
.EXAMPLE
.\Get-Duplicate-Imports.ps1 -FilePath .\TEST.csv -IndicatorType FileSha256 -VTKey 'mykey' -Import
.NOTES
Developed by Christine Cho, Program Manager, Microsoft 365 Defender
This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment. THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that You agree: (i) to not use Our name, logo, or trademarks to market Your software product in which the Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneysâ€™ fees, that arise or result from the use or distribution of the Sample Code.
This sample script is not supported under any Microsoft standard support program or service. The sample script is provided AS IS without warranty of any kind. Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose. The entire risk arising out of the use or performance of the sample scripts and documentation remains with you. In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages.
#>
param (
    [Parameter(Mandatory=$true)]
    [ValidateSet('FileSha1','FileSha256','IpAddress','DomainName','Url')]   #validate that the input contains valid value
    [string]$IndicatorType,

    [Parameter(Mandatory=$false)]
    [ValidateSet('Alert','AlertAndBlock','Allowed')]   #Validate that the input contains valid value
    [string]$Action = 'Alert',                         #Set default Action to 'Alert'

    [Parameter(Mandatory=$false)]
    [ValidateSet('Informational','Low','Medium','High')]   #Validate that the input contains valid value
    [string]$Severity = 'Informational',                   #Set default Severity to 'informational'

    [Parameter(Mandatory=$true)]
    [string]$FilePath, 

    [Parameter(Mandatory=$false)]
    [string]$Title = 'API DEMO Indicator', 
    
    [Parameter(Mandatory=$false)]
    [string]$Description = 'API DEMO Indicator',     

    [Parameter(Mandatory=$false)]
    [string]$RecommendedActions = "Please check",     

    [Parameter(Mandatory=$false)]
    [string]$Expiration = 7,                                #Set default Expiration to 7 days 

    [Parameter(Mandatory=$false)]
    [string]$RbacGroup = "",                                #Set default device group to all devices
    
    [Switch] $Import,

    [Parameter(Mandatory=$false)]
    [string]$VTKey
 )


## function to get MDE Token please add your own keys
function Get-MDEtoken
{
    $tenantId = '' # Paste your own tenant ID here
    $appId = '' # Paste your own app ID here
    $appSecret = ''
    ##https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api-hello-world?view=o365-worldwide

    $resourceAppIdUri = 'https://securitycenter.onmicrosoft.com/windowsatpservice'
    $oAuthUri = "https://login.windows.net/$TenantId/oauth2/token"
    $authBody = [Ordered] @{
        resource = "$resourceAppIdUri"
        client_id = "$appId"
        client_secret = "$appSecret"
        grant_type = 'client_credentials'
    }
    $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
    $global:aadToken = $authResponse.access_token

    $global:headers = @{ 
    'Content-Type' = 'application/json'
    Accept = 'application/json'
    Authorization = "Bearer $aadToken" 
}
}


##Auth for MDE Actions
Get-MDEtoken

$indicator_list = Get-Content $FilePath
[datetime]$datetimeOffsetTest = [DateTime]::Now.AddDays($Expiration)

# call indicators api to get existing indicators
$IndicatorsApi = "https://api.securitycenter.windows.com/api/indicators"
$ExistingIndicatorList = Invoke-WebRequest -Method Get -Uri $IndicatorsApi -Headers $headers -UseBasicParsing -ErrorAction Stop | ConvertFrom-Json


## call VT API to check if indicator is already blocked by Defender
$vt_url = 'https://www.virustotal.com/vtapi/v2/file/report'     

function Check-VT
{
    param(
        $indicator
    )

    $body = @{resource = $indicator; apikey = $VTKey}
    $VTresult = Invoke-RestMethod -Method GET -Uri $vt_url -Body $body
    $isdetected = $VTresult.scans.Microsoft.detected

   if (!($isdetected)) #if not detected in VT
   {
        Write-host "--Is Not detected in VT"
        
        ## get other hashes if available
        $fileCollisions = @() 
        if ($IndicatorType -eq "FileSha256")
        {
            $sha1 = $VTresult.sha1
            $md5 = $VTresult.md5
            
            if ($sha1)
            {
                $fileCollisions += $sha1 
            }
            if ($md5)
            {
                $fileCollisions += $md5
            }
            
        }
        if ($IndicatorType -eq "FileSha1")
        {
            $sha256 = $VTresult.sha256
            $md5 = $VTresult.md5
            
            if ($sha256)
            {
                $fileCollisions += $sha256
            }
            if ($md5)
            {
                $fileCollisions += $md5
            }
        }
        return $fileCollisions
   }
   Else
       {
            Write-host "--Is already marked as detected by MS in VT"
            return "Detected"
       }
}

# check if IoC is already imported or conflict exists
function Get-DuplicateMDE
{
    param(
        $indicator,
        $fileCollisions
    )

    $response_count = 0
    ## check if indicator of other file hash types already in MDE
    foreach ($existingIndicator in $ExistingIndicatorList.value)
        {
            if ($existingIndicator.createdBySource -ne 'TVM' -and $existingIndicator.IndicatorType -ne 'WebCategory')
            {
                if ($existingIndicator.indicatorValue -eq $indicator)
                {
                    if ($RbacGroup -ne "")
                    {
                        foreach ($group in $existingIndicator.rbacGroupNames)
                        {
                            if ($group -eq $RbacGroup)
                            {
                                Write-host "---already in the MDE indicators please check securitycenter for possible conflicts"
                                return
                            }
                        }
                    }
                    else {
                        if ($existingIndicator.rbacGroupNames.count -eq 0)
                        {
                            Write-host "---already in the MDE indicators please check securitycenter for possible conflicts"
                            return
                        }
                    }
                }
                ## check other file hashes
                else
                {
                    foreach ($filecollision in $fileCollisions)
                    {
                        if ($existingIndicator.indicatorValue -eq $filecollision)
                        {
                            if ($RbacGroup -ne "")
                            {
                                foreach ($group in $existingIndicator.rbacGroupNames)
                                {
                                    if ($group -eq $RbacGroup)
                                    {
                                        Write-host "---file collision with " $filecollision " already in the MDE indicators please check securitycenter for possible conflicts"
                                        return
                                    }
                                }
                            }
                            else 
                            {
                                if ($existingIndicator.rbacGroupNames.count -eq 0)
                                {
                                    Write-host "---file collision with " $filecollision " already in the MDE indicators please check securitycenter for possible conflicts"
                                    return
                                }    
                            }
                        }
                    }
                }   
            } 
    }
    
    ## not in MDE, so import
    if ($response_count -eq 0 -and $Import) 
    {

        Write-host "--Is not in MDE indicators"
        $indicatorvalue = $indicator.ToString()
        $indicatorurl = "https://api.securitycenter.windows.com/api/indicators"
        $postParams = @{
            "indicatorValue"= $indicatorvalue;
            "indicatorType"= $IndicatorType;
            "action"= $Action;
            "title"= $Title;
            "severity"= $Severity;
            "description"= $Description;
            "recommendedActions"= $RecommendedActions;
            "expirationTime" = ($datetimeOffsetTest | get-date -Format "yyyy-MM-ddTHH:mm:ssZ");
            "rbacGroupNames" = @($RbacGroup)
        }



        $return = Invoke-RestMethod -Headers $headers -Uri $indicatorurl -Body ($postParams|ConvertTo-Json)  -Method Post -ContentType 'application/json'
        $return
    }
    Else
    {
        Write-host "---already in the MDE indicators please check securitycenter for possible conflicts"
    }
}

## check for duplicates
foreach($indicator in $indicator_list) 
{                                                    #Call Microsoft Defender ATP API for each hash
    if(!($indicator.Startswith("#")))
    {
        $isdetected = $false
        Write-host "checking " + $indicator
        
        ## call VT API, check if in Defender and get possible file collisions
        if (($IndicatorType -eq "FileSha256" -or $IndicatorType -eq "FileSha1") -and $VTKey)
        {
            $fileCollisions = Check-VT -indicator $indicator
        }
        
        ## does it exist in MDE indicators
        if ($fileCollisions -ne "Detected" -or $IndicatorType -eq "IpAddress" -or $IndicatorType -eq "DomainName" -or $IndicatorType -eq "Url")
        {
            Get-DuplicateMDE -indicator $indicator -fileCollisions $fileCollisions
        }
    }        
}