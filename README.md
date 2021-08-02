# Get-Duplicate-Indicators
Sign up for a Virus Total API key: https://support.virustotal.com/hc/en-us/articles/115002088769-Please-give-me-an-API-key#:~:text=You%20do%20not%20need%20to%20ask%20for%20a,this%20page%20you%20can%20find%20your%20apikey%20string%3A 
## Get-Duplicate-Imports
This script takes in a csv file of indicators and identifies duplicates before importing.
Defender for Endpoint allows users to create duplicate indicators which may pose a problem
due to the indicator limit. This script enumerates indicators on the tenant and identifies
multiple types of duplicates. Type of duplicates detected are:
1) File indicators already blocked by Defender (checks using Virus Total API). Note the 4 calls/minute limit.
2) File indicators with collisions in MDE (i.e. if importing sha256, checks if equivalent sha1 and md5 in MDE)
3) Indicators with same enforcement target and device group but different Action 
Detected duplicates are output, with the option to import the remaining nonduplicate.

Example: .\Get-Duplicate-Imports.ps1 -FilePath .\TEST.csv -IndicatorType FileSha256 -VTKey 'mykey' -Import

Make sure to put in your tenant id, client id, and client secret in the script.
Parameters and further description are detailed in the file.

## Get-Duplicate-Existing
This script generates a report of existing duplicate indicators found in Defender for Endpoint and can delete these indicators if desired.
Types of duplicates detected are:
1) File indicators already blocked by Defender (checks using Virus Total API). Note the 4 calls/minute limit.
2) Indicators with same enforcement target and device group but different Action 

Parameters and further description are detailed in the file.
