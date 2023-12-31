Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Confirm:$false
Set-SmbServerConfiguration -EnableSMB2Protocol $false -Confirm:$false
Set-SmbServerConfiguration -AuditSmb1Access $false -Confirm:$false