# phishing-test-bypass-o365
Have you ever strugged to get your phishing assessment to bypass the O365 ATP, these rule may help. 


#Powershell Command

```
#Requires -Modules ("ExchangeOnlineManagement")

$vendorIPs = @(
    "1.2.3.4" # IP address or range
    "5.6.7.0/24" # IP address or range
)

#### Connect to M365:
Connect-ExchangeOnline -ShowBanner:$false

#### Connector:
$vendorconnector = Get-InboundConnector | Where-Object {$_.Name -eq 'vendorconnector'}
if ($null -eq $vendorconnector) {
    # doesn't exist, create:
    Write-Host "Creating Phishing Vendor connector..."
    New-InboundConnector -Name 'vendorconnector' -ConnectorSource AdminUI -Enabled:$True -SenderIPAddresses $vendorIPs -RequireTls:$true -ConnectorType 'OnPremises' -SenderDomains "*" -RestrictDomainsToIPAddresses:$true -TreatMessagesAsInternal:$true
} else {
    # exists, update:
    Write-Host "Updating Phishing Vendor connector..."
    Set-InboundConnector -Identity $vendorconnector.Identity -ConnectorSource AdminUI -Enabled:$True -SenderIPAddresses $vendorIPs -RequireTls:$true -ConnectorType 'OnPremises' -SenderDomains "*" -RestrictDomainsToIPAddresses:$true -TreatMessagesAsInternal:$true
}


#### Connection Policy:
$allconnectionpolicies = Get-HostedConnectionFilterPolicy
$vendorconnectionpolicy = ($allconnectionpolicies | Where-Object {$_.Name -eq 'vendorconnectionpolicy'})

if ($null -eq $vendorconnectionpolicy) {
    # doesn't exist, create:
    Write-Host "Creating Phishing Vendor connection policy..."
    New-HostedConnectionFilterPolicy -Name "vendorconnectionpolicy" -IPAllowList $vendorIPs
} else {
    # exists, update
    Write-Host "Updating Phishing Vendor connection policy..."
    Set-HostedConnectionFilterPolicy -Identity $vendorconnectionpolicy.Identity -IPAllowList $vendorIPs
}


#### Transport Rule :
$ruleName = "!RELEASE-VENDOR.IPs"
$ruleEnabled =  $true
$rulecomments = "Last updated on $((Get-Date).GetDateTimeFormats()[1])"
$ruleauditseverity = "DoNotAudit"
$ruleStopProcessingMore = $true

$global:alletrs = Get-TransportRule

$thisrule = $null
if ($null -ne $global:alletrs.Name) {
	if (-1 -ne $global:alletrs.Name.IndexOf($ruleName)) {
		$thisrule = $global:alletrs[$global:alletrs.Name.IndexOf($ruleName)]

		if ($ruleEnabled) {
			if ('Disabled' -eq $thisrule.State) { Enable-TransportRule -Identity $thisrule.Identity -Confirm:$false }
		} else {
			if ('Enabled' -eq $thisrule.State) { Disable-TransportRule -Identity $thisrule.Identity -Confirm:$false }
		}

		Set-TransportRule -Priority $rulePriority -Identity $global:alletrs.Identity[$global:alletrs.Name.IndexOf($ruleName)] -Name $ruleName -Comments $rulecomments -SentToScope 'InOrganization' -FromScope 'NotInOrganization' -SenderIpRanges $vendorIPs -SetAuditSeverity $ruleauditseverity -SetSCL -1 -StopRuleProcessing $ruleStopProcessingMore

	} else {
		# Create the rule for the first time here
		New-TransportRule -Name $ruleName -Enabled $ruleEnabled -Priority $rulePriority -Comments $rulecomments -SentToScope 'InOrganization' -FromScope 'NotInOrganization' -SenderIpRanges $vendorIPs -SetAuditSeverity $ruleauditseverity -SetSCL -1 -StopRuleProcessing $ruleStopProcessingMore
	}
} else {
	# Create the rule for the first time here
	New-TransportRule -Name $ruleName -Enabled $ruleEnabled -Priority $rulePriority -Comments $rulecomments -SentToScope 'InOrganization' -FromScope 'NotInOrganization' -SenderIpRanges $vendorIPs -SetAuditSeverity $ruleauditseverity -SetSCL -1 -StopRuleProcessing $ruleStopProcessingMore
}



```
