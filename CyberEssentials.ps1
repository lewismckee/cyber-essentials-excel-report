#cyber Essentials

#Author: Lewis McKee
#email: lewis_mckee@hotmail.co.uk

#Declare variables here
$unallowedsites = get-content -path ".\unallowedsites.txt"
$DNSFILTERADDRESS = "198.168.100.1"
$ComputerName =$ENV:COMPUTERNAME
$dpfw = netsh advfirewall show domainprofile state
$prpfw = netsh advfirewall show privateprofile state
$pupfw = netsh advfirewall show publicprofile state
$AssessorName = "Lewis McKee"
$AssessmentDate = Get-Date
$ReportDate = $AssessmentDate -Replace('[:/]','')
#4. Malware Protection
#firewall Product, AntiSpywareProduct,Antivirus Product
$FirewallProduct = Get-WmiObject -Query "SELECT * FROM AntiVirusProduct" -NameSpace ROOT/SecurityCenter2 -ComputerName $ComputerName -Credential $Credential
$AntiSpywareProduct = Get-WmiObject -Namespace ROOT/SecurityCenter2 -Class AntiSpywareProduct -ComputerName $ComputerName -Credential $Credential
$AntiVirusProduct = Get-WmiObject -Namespace ROOT/SecurityCenter2 -Class AntiVirusProduct -ComputerName $ComputerName -Credential $Credential

#Domain,Private,Public Profile Windows Firewall Check
if($FirewallProduct.DisplayName -like "*Windows Defender*"){if($dpfw[0-3] -like "*ON*"){$dpfwr = "Domain Profile Enabled"}else{$dpfwr ="Domain Profile Disabled"}} else{Write-Host "3rd Party Firewall in use: $FirewallProduct.DisplayName"}
if($FirewallProduct.DisplayName -like "*Windows Defender*"){if($prpfw[0-3] -like "*ON*"){$prpfwr = "Domain Profile Enabled"}else{$prpfwr ="Domain Profile Disabled"}} else{Write-Host "3rd Party Firewall in use: $FirewallProduct.DisplayName"}
if($FirewallProduct.DisplayName -like "*Windows Defender*"){if($pupfw[0-3] -like "*ON*"){$pupfwr = "Domain Profile Enabled"}else{$pupfwr ="Domain Profile Disabled"}} else{Write-Host "3rd Party Firewall in use: $FirewallProduct.DisplayName"}

#Encrypted Disk Stats
$c = manage-bde -status C:
if($c[0-9] -like "*100.0%*"){$DrivesEncrypted = $c[0-9]}else{$DrivesEncrypted = "Not Encrypted"}
#write-host $DrivesEncrypted


$AssetBlockedSites =  New-Object PSObject -Property @{
    tabname = "Web Filtering"}


foreach ($line in $unallowedsites){
#write-host "testing if $line is blocked"
$qry = nslookup.exe $line
$qry = $qry | select -Last 2
#Write-Host $qry[0-0] #$qry[0-1] $qry[0-2] $qry[0-3] $qry[0-4]
if ($qry[0-0] -like "*$DNSFILTERADDRESS*"){
 #   write-host "Website Disallowed"
    $AssetBlockedSites | Add-Member NoteProperty $line "Disallowed"


}else{#Write-Host "Website Allowed"
$AssetBlockedSites | Add-Member NoteProperty $line "Allowed"
}
}

################REPORT BUILDING###############################
$ASSESSMENT = New-Object PSObject -Property @{
    AssessmentDate = $AssessmentDate
    AssessorName = $AssessorName
    tabname = "Assessment"
}

<# $OS = New-Object PSObject -Property @{
    ComputerName = $ComputerName
    Major = [System.Environment]::OSVersion.Version.Major
    Minor = [System.Environment]::OSVersion.Version.Minor
    Build = [System.Environment]::OSVersion.Version.Build
    Revision = [System.Environment]::OSVersion.Version.Revision
    tabname = "OS"
 <#    OSFriendlyName 
     OSUpdateAutoEnabled
 #>
# } #>

clear

function Get-WindowsKey {
   ## function to retrieve the Windows Product Key from any PC
   param ($targets = ".")
   $hklm = 2147483650
   $regPath = "Software\Microsoft\Windows NT\CurrentVersion"
   $regValue = "DigitalProductId"
   Foreach ($target in $targets) {
       $productKey = $null
       $win32os = $null
       $wmi = [WMIClass]"\\$target\root\default:stdRegProv"
       $data = $wmi.GetBinaryValue($hklm,$regPath,$regValue)
       $binArray = ($data.uValue)[52..66]
       $charsArray = "B","C","D","F","G","H","J","K","M","P","Q","R","T","V","W","X","Y","2","3","4","6","7","8","9"
       ## decrypt base24 encoded binary data
       For ($i = 24; $i -ge 0; $i--) {
           $k = 0
           For ($j = 14; $j -ge 0; $j--) {
               $k = $k * 256 -bxor $binArray[$j]
               $binArray[$j] = [math]::truncate($k / 24)
               $k = $k % 24
           }
           $productKey = $charsArray[$k] + $productKey
           If (($i % 5 -eq 0) -and ($i -ne 0)) {
               $productKey = "-" + $productKey
           }
       }

       $DOMAIN = Get-WmiObject win32_computersystem | Select-Object -property Domain
       $MANUFACTURER = Get-WmiObject win32_computersystem | Select-Object -property Manufacturer
       $MODEL = Get-WmiObject win32_computersystem | Select-Object -property Model
       $TOTALPHYSICALMEMORY = Get-WmiObject win32_computersystem | Select-Object -property TotalPhysicalMemory
       $FREEPHYSICALMEMORY = Get-WmiObject win32_computersystem | Select-Object -property FreePhysicalMemory
       $SERIALNUMBER = gwmi win32_bios | Select -property SerialNumber
       $SMBIOSBIOSVersion = gwmi win32_bios | Select -property SMBIOSBIOSVersion
       $BIOSNAME = gwmi win32_bios | Select -property Name
       $win32os = Get-WmiObject Win32_OperatingSystem -computer $target
       $AssetDetails = New-Object Object


       $AssetDetails | Add-Member Noteproperty Computer -value $ComputerName
       $AssetDetails | Add-Member Noteproperty Caption -value $win32os.Caption
       $AssetDetails | Add-Member Noteproperty OSArch -value $win32os.OSArchitecture
       $AssetDetails | Add-Member Noteproperty BuildNumber -value $win32os.BuildNumber
       $AssetDetails | Add-Member NoteProperty InstallDate -Value $win32os.InstallDate
#Licence
       $AssetDetails | Add-Member Noteproperty ProductKey -value $productkey
#Owner
       $AssetDetails | Add-Member Noteproperty RegisteredTo -value $win32os.RegisteredUser
       
       $AssetDetails | Add-Member NoteProperty Domain -Value $DOMAIN.Domain
#Hardware       
       $AssetDetails | Add-Member NoteProperty Manufacturer -Value $MANUFACTURER.Manufacturer
       $AssetDetails | Add-Member NoteProperty Model -Value $MODEL.Model
       $AssetDetails | Add-Member NoteProperty SerialNumber -Value $SERIALNUMBER.SerialNumber
       
       $AssetDetails | Add-Member NoteProperty TotalPhysicalMemory -Value $TOTALPHYSICALMEMORY.TotalPhysicalMemory
            
#Bios
       $AssetDetails | Add-Member NoteProperty SMBIOSBIOSVersion -Value $SMBIOSBIOSVersion.SMBIOSBIOSVersion
       $AssetDetails | Add-Member NoteProperty BIOSName -Value $BIOSNAME.Name

#Tab Name for Excel
       $AssetDetails | Add-Member NoteProperty tabname -value "OS"
       $AssetDetails
   }
}

<# $AssessmentDate = Get-Date
$ReportDate = $AssessmentDate -Replace('[:/]','')
$ReportFileName = "$ComputerName $ReportDate" #>
#Get-WindowsKey | export-excel -path ".\Data\$ReportFileName.xlsx"  -WorkSheetname "Asset"



$AV =New-Object PSObject -Property @{
    AntiVirusProduct = $AntiVirusProduct.DisplayName
    FirewallProduct = $FirewallProduct.DisplayName
    AntiSpywareProduct = $AntiSpywareProduct.DisplayName
    tabname = "AV"
        <#LastAntivirusUpdate
    LastAntivirusScan
    ScheduledTaskAntivirusScan
    ScheduledTaskAntivirusUpdate
    AntivirusProductEnabled #>
}

$FIREWALL = New-Object PSObject -Property @{
    FirewallDomainProfile = $dpfwr
    FirewallPrivateProfile = $prpfwr
    FirewallPublicProfile = $pupfwr
    tabname = "Firewall"
}

$ENCRYPTION = New-Object PSObject -Property @{
    DrivesEncrypted = $DrivesEncrypted
    EncryptionMethod = $c[0-8]
    BitlockerVersion = $c[0-11]
    ProtectionStatus = $c[0-7]
    ConversionStatus = $c[0-10]
    tabname = "Encryption"
}



$wmiAPPSLIST = @(get-wmiobject -Class 'Win32_Product' -ComputerName $ComputerName)


#$ASSESSMENT,$AV, $FIREWALL,$ENCRYPTION, $AssetBlockedSites
$ReportFileName = "$ComputerName $ReportDate"
Get-WindowsKey | export-excel -path ".\Data\$ReportFileName.xlsx"  -WorkSheetname "Asset"
$tabs = @($ASSESSMENT,$AV, $FIREWALL,$ENCRYPTION, $AssetBlockedSites)
foreach($tab in $tabs){
    $tab | Select-Object -Property * -ExcludeProperty tabname | export-excel -path ".\Data\$ReportFileName.xlsx"  -WorkSheetname $tab.tabname
}

$wmiAPPSLIST | export-excel -path ".\Data\$ReportFileName.xlsx"  -WorkSheetname "Installed"

Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | select DisplayName, Publisher, InstallDate | export-excel -path ".\Data\$ReportFileName.xlsx"  -WorkSheetname "Installed2"


Get-Service  | export-excel -path ".\Data\$ReportFileName.xlsx"  -WorkSheetname "Services"

Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | export-excel -path ".\Data\$ReportFileName.xlsx"  -WorkSheetname "Startup Programs"

dism /online /Get-Features | export-excel -path ".\Data\$ReportFileName.xlsx"  -WorkSheetname "Windows Features"

net Users | export-excel -path ".\Data\$ReportFileName.xlsx"  -WorkSheetname "Local User Accounts"

#local groups
net localgroup | export-excel -path ".\Data\$ReportFileName.xlsx"  -WorkSheetname "Local Groups"
#local group members
net localgroup Administrators | export-excel -path ".\Data\$ReportFileName.xlsx"  -WorkSheetname "Local Administrators"