# Playbooks

| Design | File | Status |
|---|---|---|
| SOC-02 Incident enrichment | [`incident-enrichment.azuredeploy.json`](incident-enrichment.azuredeploy.json) | Deployable ARM template |
| SOC-04 Compromised account containment | [`Invoke-AccountContainment.ps1`](Invoke-AccountContainment.ps1) | Script, run after analyst approval |
| SOC-03 Phishing triage and clean-up | Hunt query: [`../hunting-queries/phishing-recipients.kql`](../hunting-queries/phishing-recipients.kql) | Design; Logic App not yet built |
| SOC-06 Shift handover digest | Query: [`../hunting-queries/open-incidents-handover.kql`](../hunting-queries/open-incidents-handover.kql) | Design; Logic App not yet built |

## SOC-02: Incident enrichment (Logic Apps)

When Sentinel opens an incident, an automation rule runs this playbook:

1. Reads the VirusTotal API key from Azure Key Vault. The key is never stored in the workflow, and run history hides it.
2. Gets every IP entity from the incident.
3. Looks up each IP in VirusTotal and counts the engines that call it malicious.
4. Writes one comment on the incident with a table of IP, malicious votes, country and network owner.
5. Tags the incident `malicious-ip` if any IP meets the threshold (default 3 votes), otherwise `enriched`.

It is read-only on purpose: it never closes an incident or changes its status or severity.

### Deploy

```bash
az deployment group create \
  --resource-group rg-sentinel-lab \
  --template-file incident-enrichment.azuredeploy.json \
  --parameters KeyVaultName=kv-sentinel-lab
```

The deployment outputs the playbook's managed identity (`playbookPrincipalId`). Give it exactly two permissions:

```bash
# comment on and tag incidents
az role assignment create --assignee-object-id <playbookPrincipalId> --assignee-principal-type ServicePrincipal \
  --role "Microsoft Sentinel Responder" --scope /subscriptions/<sub-id>/resourceGroups/<workspace-rg>

# read the API key (Key Vault using Azure RBAC)
az role assignment create --assignee-object-id <playbookPrincipalId> --assignee-principal-type ServicePrincipal \
  --role "Key Vault Secrets User" --scope /subscriptions/<sub-id>/resourceGroups/<kv-rg>/providers/Microsoft.KeyVault/vaults/kv-sentinel-lab
```

Then, in Sentinel, go to **Automation → Create → Automation rule**. Choose the trigger *When incident is created* and the action *Run playbook*, and pick `Enrich-Incident-IPReputation`. Sentinel also needs permission to run playbooks in the playbook's resource group. You grant that under **Settings → Playbook permissions**.

The free VirusTotal API allows 4 lookups a minute and 500 a day. The loop runs one IP at a time, but a busy workspace should use a paid key or add a delay.

## SOC-04: Compromised account containment (PowerShell)

Run it once an analyst has approved containment. In the full design, the approval comes from a Teams adaptive card.

```powershell
Connect-MgGraph -Scopes 'User.ReadWrite.All', 'User.RevokeSessions.All', 'Directory.Read.All'
Connect-ExchangeOnline
.\Invoke-AccountContainment.ps1 -UserPrincipalName j.smith@contoso.com -ApprovedBy 'A. Mani' -Incident 4312 -WhatIf
```

The script:

- revokes every session
- blocks sign-in
- removes inbox rules that forward or redirect mail
- logs each step with the incident number and who approved it

It refuses to run on accounts that hold an admin role, or that appear in `-ProtectedAccounts` (for example break-glass accounts). Those go to a senior analyst. It does not reset the password or MFA: the service desk does that after verifying the user by phone.

## Testing status

The ARM template is valid JSON, and it follows the structure of the playbook templates in the Microsoft Sentinel community repository. It has not been deployed from this repository yet, so deploy it into a test resource group first. The PowerShell script needs a Microsoft 365 tenant and has not been run from here. Use `-WhatIf` on a test account first.
