# Option 1 – Expected Scanner Findings Reference

Run against `main.tf` with any of the tools below. This table is your ground-truth
to validate scanner coverage and tune suppression rules.

## How to run

```bash
# Checkov
pip install checkov
checkov -f main.tf --framework terraform

# tfsec
brew install tfsec   # or: docker run --rm -v $(pwd):/src aquasec/tfsec /src
tfsec .

# Terrascan
brew install terrascan
terrascan scan -i terraform -d .

# Snyk IaC
snyk iac test main.tf

# KICS
docker run -v $(pwd):/path checkmarx/kics scan -p /path
```

---

## Expected Findings

| # | Resource | Config Issue | Checkov ID | tfsec ID | Severity |
|---|---|---|---|---|---|
| 1 | `terraform {}` | No remote backend – state stored locally | CKV_TF_1 | — | LOW |
| 2 | `azurerm_storage_account` | HTTPS not enforced (`enable_https_traffic_only = false`) | CKV_AZURE_33 | azure-storage-enforce-https | HIGH |
| 3 | `azurerm_storage_account` | Public blob access allowed | CKV_AZURE_3, CKV_AZURE_59 | azure-storage-no-public-access | HIGH |
| 4 | `azurerm_storage_account` | Minimum TLS version below 1.2 | CKV_AZURE_44 | azure-storage-use-secure-tls-policy | MEDIUM |
| 5 | `azurerm_storage_account` | No network rules (default allow-all) | CKV_AZURE_36 | azure-storage-default-action-deny | HIGH |
| 6 | `azurerm_storage_container` | Container access type is `blob` (public) | CKV_AZURE_34 | azure-storage-no-public-access | HIGH |
| 7 | `azurerm_key_vault` | Purge protection disabled | CKV_AZURE_42 | azure-keyvault-ensure-purge-protection | MEDIUM |
| 8 | `azurerm_key_vault` | Soft-delete retention only 7 days | CKV_AZURE_110 | azure-keyvault-ensure-soft-delete | MEDIUM |
| 9 | `azurerm_key_vault` | No network ACLs (public internet access) | CKV_AZURE_109 | azure-keyvault-specify-network-acl | HIGH |
| 10 | `azurerm_key_vault_secret` | No expiration date on secret | CKV_AZURE_112 | azure-keyvault-content-type-for-secret | LOW |
| 11 | `azurerm_network_security_group` | RDP (3389) open to `*` | CKV_AZURE_10, CKV_AZURE_160 | azure-network-rdp-blocked-from-internet | CRITICAL |
| 12 | `azurerm_network_security_group` | SSH (22) open to `*` | CKV_AZURE_10, CKV_AZURE_161 | azure-network-ssh-blocked-from-internet | CRITICAL |
| 13 | `azurerm_network_security_group` | Allow-all inbound rule | CKV_AZURE_77 | azure-network-no-public-ingress | CRITICAL |
| 14 | `azurerm_virtual_network` | No DDoS protection plan | CKV2_AZURE_37 | azure-network-enable-ddos-protection | LOW |
| 15 | `azurerm_windows_virtual_machine` | Automatic updates disabled | CKV_AZURE_149 | azure-compute-enable-automatic-updates | MEDIUM |
| 16 | `azurerm_windows_virtual_machine` | VM agent not provisioned | CKV_AZURE_50 | azure-compute-ensure-extensions-not-installed | MEDIUM |
| 17 | `azurerm_windows_virtual_machine` | No managed identity | CKV_AZURE_93 | azure-compute-no-secrets-in-custom-data | MEDIUM |
| 18 | `azurerm_windows_virtual_machine` | OS disk uses Standard_LRS, no CMK | CKV_AZURE_1 | azure-compute-no-unmanaged-disk | MEDIUM |
| 19 | `azurerm_windows_virtual_machine` | Boot diagnostics not enabled | CKV2_AZURE_12 | azure-compute-enable-boot-diagnostics | LOW |
| 20 | `azurerm_network_interface` | IP forwarding enabled | CKV_AZURE_118 | azure-network-disable-rdp-from-internet | MEDIUM |
| 21 | `azurerm_network_interface` | Public IP directly attached to NIC | CKV_AZURE_178 | — | MEDIUM |
| 22 | `azurerm_mssql_server` | Public network access enabled | CKV_AZURE_113 | azure-database-no-public-access | HIGH |
| 23 | `azurerm_mssql_server` | Minimum TLS version 1.0 | — | azure-database-secure-tls-policy | HIGH |
| 24 | `azurerm_mssql_server` | No Azure AD administrator | CKV_AZURE_166 | — | MEDIUM |
| 25 | `azurerm_mssql_server` | Auditing not configured | CKV_AZURE_23 | azure-database-enable-audit | HIGH |
| 26 | `azurerm_mssql_server` | Threat detection not enabled | CKV_AZURE_26 | azure-database-threat-alert | HIGH |
| 27 | `azurerm_mssql_firewall_rule` | Firewall allows 0.0.0.0–255.255.255.255 | CKV_AZURE_25 | azure-database-no-public-firewall-access | CRITICAL |
| 28 | `azurerm_mssql_database` | Geo-redundant backup disabled | — | azure-database-enable-geo-redundant | MEDIUM |
| 29 | `azurerm_windows_web_app` | HTTPS only not enforced | CKV_AZURE_14 | azure-appservice-enforce-https | HIGH |
| 30 | `azurerm_windows_web_app` | Minimum TLS 1.0 | CKV_AZURE_16 | azure-appservice-require-client-cert | HIGH |
| 31 | `azurerm_windows_web_app` | FTP state AllAllowed | CKV_AZURE_78 | azure-appservice-ftp-state | HIGH |
| 32 | `azurerm_windows_web_app` | HTTP/2 not enabled | CKV_AZURE_15 | — | LOW |
| 33 | `azurerm_windows_web_app` | Authentication not configured | CKV_AZURE_13 | azure-appservice-authentication-enabled | MEDIUM |
| 34 | `azurerm_windows_web_app` | Client certificates not required | CKV_AZURE_17 | — | LOW |
| 35 | `azurerm_windows_web_app` | Logging not configured | CKV_AZURE_65 | azure-appservice-enable-http-logging | MEDIUM |
| 36 | `azurerm_log_analytics_workspace` | Retention below 90 days | CKV_AZURE_132 | azure-monitor-activity-retention-set | MEDIUM |
| 37 | `azurerm_log_analytics_workspace` | No CMK configured | CKV2_AZURE_26 | — | LOW |
| 38 | (absent) | No activity log alerts defined | CKV_AZURE_37 | azure-monitor-activity-log-alert-exists | MEDIUM |
| 39 | (absent) | No diagnostic setting on Key Vault | CKV_AZURE_131 | — | MEDIUM |

**Total expected: 39 findings** across CRITICAL(3), HIGH(14), MEDIUM(16), LOW(6)

---

## Suppression / baseline testing

To test that your pipeline correctly suppresses known-acceptable findings:

```python
# checkov suppression inline (add to resource block)
#checkov:skip=CKV_AZURE_132:Retention intentionally low in lab environment
```

```yaml
# tfsec .tfsec/ignore.yml
ignore:
  - code: azure-storage-enforce-https
    reason: "Lab environment only – finding intentional"
    expiry: "2026-12-31"
```
