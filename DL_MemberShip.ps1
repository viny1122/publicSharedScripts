
#PreExecution Attribute Configuration

Set-Alias wh Write-Host
Set-Alias wd Write-Debug

$Counter = $null

Start-Transcript "C:\scripts\AD-Security-GroupsMembership-Export\Log\RunTime.txt" -Force

$ExportCsvfile = "AD_SG_MemberReport$((get-date).tostring("yyyyMMddss")).csv"

wh Report will be export to $ExportCsvfile

wh "exporting Security groups in ISSNET Domain"

$AllGroup = Get-ADGroup -Filter 'GroupCategory -eq "Security"' -Properties ManagedBy,CanonicalName

#$AllGroup = Get-ADGroup -Filter 'GroupCategory -eq "Security"' -Properties ManagedBy,CanonicalName | Select-Object -First 20

#Configure Alias



    foreach ($PerDL in $AllGroup) {
      #Using try\Catch for error detection
        $DL = $null
        $SGName = $PerDL.ObjectGUID

        wh starting to export memebership for group $PerDL.Name

  try {
            $DL = Get-ADGroup -Identity $SGName | Get-ADGroupMember

        }
  catch 
        {

           wh Unable to find $PerDL.DL with error $error[0] -ForegroundColor Red


         }

         Foreach ($user in $DL)
         {
            $adexport = $Null
                        
            $Mem = $Null
            
            Try
            {

            $Mem = Get-ADUser -Identity $user.objectGUID -ErrorAction SilentlyContinue
            
            if ($mem.Enabled -eq "False" ){$Counter++}

            }
            catch

            {Wh Unable to find $user.name with property type $user.objectClass The error is $error[0] -ForegroundColor DarkRed -BackgroundColor Black}

            $adproj = New-Object PSObject

            $adproj | Add-Member NoteProperty "DLName" -Value $PerDL.Name

            if(-Not ($mem))
            {
            
            $adproj | Add-Member NoteProperty -Name "Member_UserName" -value $user.Name
            
            }

            else

            {

            $adproj | Add-Member NoteProperty -Name "Member_UserName" -value $mem.Name
            
            }

            $adproj | Add-Member NoteProperty "Member_Class" -Value $Mem.objectClass
            
            #$adproj | Add-Member NoteProperty "EmailID" -Value $Mem.objectClass
            
            $adproj | Add-Member NoteProperty "Member_IsEnabled" -Value $Mem.Enabled
                                               
            $adproj | Add-Member NoteProperty "DL_ManagedBy" -Value $PerDL.ManagedBy

            $adproj | Add-Member NoteProperty "DL_CanonicalName" -Value $PerDL.CanonicalName
                        
            $adexport += $adproj

            $adexport | Select @{N='DL_Name';E={$_.DLName}},Member_UserName,Member_Class,Member_IsEnabled,DL_managedBy,DL_CanonicalName | Export-Csv -path "C:\scripts\AD-Security-GroupsMembership-Export\Reports\$ExportCsvfile" -NoTypeInformation -Append -NoClobber

         }
        
        }

$HTMBody = $null

$HTMBody = New-Object PSObject

$HTMBody | Add-Member NoteProperty "Total Group Count" -Value $AllGroup.count

$HTMBody | Add-Member NoteProperty "Disabled users in Membership" -Value $Counter

#Export Data to HTML and Sending Email

. C:\scripts\AD-Security-GroupsMembership-Export\HTMLTable.ps1

$time = Get-Date -Format g

$HTML = New-HTMLHead -title "AD Security Group Membership Report"

$HTML += "<br><h3>ISSNET AD Security Membership report.</h3><br>"

$HTML += "<br><h3>  Generated on '$Time'</h3>"

$HTML += New-HTMLTable -inputObject $HTMBody

$HTML += "<br>Script Last Modified 19/05/2020<br>"

$HTML = $HTML | Close-HTML

Write-Debug "Sending Email.."

$Attch = "C:\scripts\AD-Security-GroupsMembership-Export\Reports\$ExportCsvfile"

Send-MailMessage -Body $HTML -BodyAsHtml -Encoding ([System.Text.Encoding]::UTF8) -From 'isshgunms@iss-shipping.com' -SmtpServer 'mailrelay.issnet.iss-shipping.com' -Subject 'Automated Email - AD Security Group Membership Report' -To 'Information.Security@iss-shipping.com' -Cc 'VinuLingaRaja.Dharmalingam@iss-shipping.com','bilal.hussain@iss-shipping.com' -Attachments $Attch

Write-Debug "Removing Old CSV Files"

$Retention = (Get-Date).AddDays(-15)

$remove = Get-ChildItem -Path "C:\scripts\AD-Security-GroupsMembership-Export\Reports\" -Recurse -Force | ?{!$_.psIsContainer -and $_.CreationTime -lt $rentention}

$remove | Remove-Item -Force

Stop-Transcript
