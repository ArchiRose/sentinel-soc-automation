#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Users.Actions, ExchangeOnlineManagement
<#
.SYNOPSIS
    Contains a compromised Microsoft 365 account after an analyst has approved it.

.DESCRIPTION
    Design SOC-04. For an account that shows a risky sign-in and a new forwarding rule:
      1. signs the user out of every session (revokes refresh tokens)
      2. blocks sign-in
      3. removes inbox rules that forward, forward as attachment or redirect mail
    It refuses to run without the name of the analyst who approved containment, and it will not
    touch admin accounts or accounts on the protected list. Those go to a senior analyst.
    Every step is logged with the incident number and the approver.

    It does not reset the password or MFA. The service desk does that after verifying the user by
    phone, so the attacker cannot intercept the new credentials.

.EXAMPLE
    Connect-MgGraph -Scopes 'User.ReadWrite.All', 'User.RevokeSessions.All', 'Directory.Read.All'
    Connect-ExchangeOnline
    .\Invoke-AccountContainment.ps1 -UserPrincipalName j.smith@contoso.com -ApprovedBy 'A. Mani' -Incident 4312 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$')] [string] $UserPrincipalName,
    [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $ApprovedBy,
    [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Incident,
    [string[]] $ProtectedAccounts = @(),
    [string] $LogFile = (Join-Path $PSScriptRoot 'containment-log.csv')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-ContainmentLog {
    param([string] $Step, [string] $Result)
    [pscustomobject]@{
        Timestamp  = (Get-Date).ToString('s')
        Incident   = $Incident
        Account    = $UserPrincipalName
        Step       = $Step
        Result     = $Result
        ApprovedBy = $ApprovedBy
        RunBy      = [Environment]::UserName
    } | Export-Csv -LiteralPath $LogFile -Append -NoTypeInformation
}

$upn       = $UserPrincipalName.ToLower()
$protected = @($ProtectedAccounts | ForEach-Object { $_.ToLower() })
if ($protected -contains $upn) {
    Write-ContainmentLog -Step 'Refused' -Result 'Protected account: escalated to a senior analyst'
    throw "$upn is on the protected list. Escalate to a senior analyst instead of running automated containment."
}

$user = Get-MgUser -UserId $upn -Property Id, UserPrincipalName, AccountEnabled
$adminRoles = @(Get-MgUserMemberOf -UserId $user.Id -All |
    Where-Object { $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.directoryRole' })
if ($adminRoles.Count -gt 0) {
    Write-ContainmentLog -Step 'Refused' -Result 'Account holds an admin role: escalated to a senior analyst'
    throw "$upn holds an admin role. Escalate to a senior analyst instead of running automated containment."
}

if ($PSCmdlet.ShouldProcess($upn, 'Revoke all sign-in sessions')) {
    Revoke-MgUserSignInSession -UserId $user.Id | Out-Null
    Write-ContainmentLog -Step 'Revoke sessions' -Result 'Done'
}

if ($PSCmdlet.ShouldProcess($upn, 'Block sign-in')) {
    Update-MgUser -UserId $user.Id -AccountEnabled:$false
    Write-ContainmentLog -Step 'Block sign-in' -Result 'Done'
}

$rules = @(Get-InboxRule -Mailbox $upn |
    Where-Object { $_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo })
foreach ($rule in $rules) {
    if ($PSCmdlet.ShouldProcess("$upn : $($rule.Name)", 'Remove forwarding inbox rule')) {
        Remove-InboxRule -Mailbox $upn -Identity $rule.Identity -Confirm:$false
        Write-ContainmentLog -Step "Remove inbox rule '$($rule.Name)'" -Result 'Done'
    }
}

$message = ('Contained {0}: sessions revoked, sign-in blocked, {1} forwarding rule(s) removed. ' -f $upn, $rules.Count) +
    'Next: the service desk verifies the user by phone, then resets the password and MFA.'
Write-Output $message
