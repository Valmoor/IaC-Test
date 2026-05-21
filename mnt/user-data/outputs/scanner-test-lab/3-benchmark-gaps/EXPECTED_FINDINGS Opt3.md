# Option 3 – CIS Azure Foundations Benchmark v2.0 Gap Reference

## How to evaluate

### Defender for Cloud (recommended)
1. Deploy the Terraform in this directory
2. In Azure Portal → **Microsoft Defender for Cloud → Regulatory Compliance**
3. Assign the built-in initiative: *CIS Microsoft Azure Foundations Benchmark v2.0.0*
4. Allow 24–48 hours for initial assessment
5. Compare findings against the table below

### Azure Policy CLI
```bash
# List non-compliant resources against CIS initiative
az policy state list \
  --resource-group cis-benchmark-gaps-rg \
  --filter "complianceState eq 'NonCompliant'" \
  --query "[].{Policy:policyDefinitionName, Resource:resourceId, State:complianceState}" \
  -o table
```

### Prisma Cloud / Wiz / Orca
Point the scanner at the subscription or resource group — all resources below
are explicitly tagged for discovery.

---

## Expected Non-Compliant Controls

| CIS Control | Description | Failing Resource | Expected State |
|---|---|---|---|
| 3.1 | Secure transfer required | `azurerm_storage_account.cis_3` | enable_https_traffic_only = false |
| 3.3 | Blob container not public | `azurerm_storage_container.cis_3` | container_access_type = "container" |
| 3.7 | Minimum TLS 1.2 on storage | `azurerm_storage_account.cis_3` | min_tls_version = "TLS1_1" |
| 3.8 | Disable anonymous blob access | `azurerm_storage_account.cis_3` | allow_nested_items_to_be_public = true |
| 3.10 | Network default action deny | `azurerm_storage_account.cis_3` | network_rules.default_action = "Allow" |
| 4.1.1 | SQL auditing enabled | `azurerm_mssql_server.cis_4` | No auditing policy |
| 4.1.2 | SQL audit retention ≥ 90 days | `azurerm_mssql_server.cis_4` | No auditing policy |
| 4.1.3 | Advanced Data Security on SQL | `azurerm_mssql_server.cis_4` | No security alert policy |
| 4.1.4 | Defender for SQL enabled | `azurerm_mssql_server.cis_4` | No Defender plan |
| 4.1.5 | VA reports sent to admins | `azurerm_mssql_server.cis_4` | No VA resource |
| 4.2.1 | SSL enabled for PostgreSQL | `azurerm_postgresql_flexible_server.cis_4` | TLS version below 1.2 |
| 4.3.7 | MySQL Azure services access off | (absent resource) | Control not deployed |
| 5.1.2 | Log retention ≥ 365 days | `azurerm_log_analytics_workspace.cis_5` | retention_in_days = 30 |
| 5.2.2 | Alert: Delete Policy Assignment | (absent) | No alert resource |
| 5.2.3 | Alert: NSG Create/Update | (absent) | No alert resource |
| 5.2.4 | Alert: NSG Delete | (absent) | No alert resource |
| 5.2.5 | Alert: Security Solution delete | (absent) | No alert resource |
| 5.2.6 | Alert: SQL firewall rule change | (absent) | No alert resource |
| 5.2.7 | Alert: Public IP Create/Update | (absent) | No alert resource |
| 6.1 | RDP restricted from internet | `azurerm_network_security_group.cis_6` | source = "Internet" on 3389 |
| 6.2 | SSH restricted from internet | `azurerm_network_security_group.cis_6` | source = "Internet" on 22 |
| 6.3 | UDP restricted from internet | `azurerm_network_security_group.cis_6` | UDP * open to * |
| 6.4 | Network Watcher enabled | (absent) | No Network Watcher resource |
| 6.5 | NSG flow logs enabled | (absent) | No flow log resource |
| 7.2 | OS disk encrypted with CMK | `azurerm_windows_virtual_machine.cis_7` | No disk_encryption_set_id |
| 7.3 | Unattached disks encrypted | `azurerm_managed_disk.cis_7_unattached` | No encryption set |
| 7.5 | Azure Backup enabled for VM | (absent) | No backup_protected_vm resource |
| 7.7 | Endpoint protection installed | `azurerm_windows_virtual_machine.cis_7` | No antimalware extension |
| 8.1 | App Service authentication on | `azurerm_windows_web_app.cis_8` | auth_settings.enabled = false |
| 8.2 | HTTP redirects to HTTPS | `azurerm_windows_web_app.cis_8` | https_only = false |
| 8.3 | Latest TLS on App Service | `azurerm_windows_web_app.cis_8` | minimum_tls_version = "1.0" |
| 8.6 | FTP deployments disabled | `azurerm_windows_web_app.cis_8` | ftps_state = "AllAllowed" |

**Total: 32 non-compliant controls** — one compliant control (5.2.1) is present to verify
your scanner correctly reports PASS alongside failures.
