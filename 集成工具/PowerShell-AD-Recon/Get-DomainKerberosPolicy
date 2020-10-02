Function Get-KerberosPolicy
    {
        # NOTE: This script REQUIRES the GroupPolicy module installed.
        Import-Module GroupPolicy

        [string]$PDCHostName = (Get-ADDomainController -Discover -Service PrimaryDC).HostName
        [xml]$DefaultDomainPolicyXML = Get-GPO -Name "Default Domain Policy" -Server $PDCHostName | Get-GPOReport -ReportType XML # -Path c:\temp\DDP.xml
        $NameSpaceManager = New-Object System.XML.XmlNamespaceManager($DefaultDomainPolicyXML.NameTable) 
        $NameSpaceManager.AddNamespace('root','http://www.microsoft.com/GroupPolicy/Settings')
        $GPOsettings = [array]$DefaultDomainPolicyXML.SelectNodes('//root:Extension',$NameSpaceManager)
        $KerberosPolicySettings = $GPOsettings.Account |?{$_.type -match "Kerberos"}

        $KerberosPolicySettingsMaxRenewAge = $KerberosPolicySettings.MaxRenewAge
        $KerberosPolicySettingsMaxTicketAge = $KerberosPolicySettings.MaxTicketAge

        return $KerberosPolicySettings
    }
