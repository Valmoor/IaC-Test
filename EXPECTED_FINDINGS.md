# Option 4 – Policy-as-Code Expected Results

## How to evaluate

### Trigger a compliance scan after deploy
```bash
# Trigger immediate evaluation (don't wait 24hr)
az policy state trigger-scan --resource-group policy-fixtures-rg

# List all non-compliant resources
az policy state list \
  --resource-group policy-fixtures-rg \
  --filter "complianceState eq 'NonCompliant'" \
  --query "[].{Policy:policyDefinitionName, Resource:resourceId}" \
  -o table

# Check a specific policy assignment
az policy state list \
  --policy-assignment deny-rdp-any-assignment \
  --query "[].{Resource:resourceId, State:complianceState}" \
  -o table
```

### Switch custom policy from Audit → Deny mode
Edit the `policy_rule` effect in `main.tf` from `"Deny"` to `"Audit"` first to
observe violations before enforcing. Then switch to `"Deny"` to validate ARM-layer
enforcement blocks the `pfix-rdp-open-nsg` rule creation.

---

## Expected Compliance States

### Cluster 1 – Storage
| Resource | Policy | Expected State |
|---|---|---|
| `noncompliant_storage` | Secure transfer required | NonCompliant |
| `noncompliant_storage` | Public access disallowed | NonCompliant |
| `noncompliant_storage` | Network access restricted | NonCompliant |
| `compliant_storage` | Secure transfer required | Compliant |
| `compliant_storage` | Public access disallowed | Compliant |
| `compliant_storage` | Network access restricted | Compliant |

### Cluster 2 – Key Vault
| Resource | Policy | Expected State |
|---|---|---|
| `noncompliant_kv` | Purge protection enabled | NonCompliant |
| `noncompliant_kv` | Firewall enabled | NonCompliant |
| `noncompliant_secret` | Expiration date set | NonCompliant |
| `compliant_kv` | Purge protection enabled | Compliant |
| `compliant_kv` | Firewall enabled | Compliant |
| `compliant_secret` | Expiration date set | Compliant |

### Cluster 3 – Virtual Machines
| Resource | Policy | Expected State |
|---|---|---|
| `noncompliant_vm` | System updates installed | NonCompliant |
| `noncompliant_vm` | Azure Monitor Agent installed | NonCompliant |
| `noncompliant_vm` | Endpoint protection installed | NonCompliant |
| `compliant_vm` | System updates installed | Compliant |
| `compliant_vm` | Azure Monitor Agent installed | Compliant |

### Cluster 4 – SQL Server
| Resource | Policy | Expected State |
|---|---|---|
| `noncompliant_sql` | Auditing enabled | NonCompliant |
| `noncompliant_sql` | Azure Defender enabled | NonCompliant |
| `noncompliant_sql` | Minimum TLS 1.2 | NonCompliant |
| `compliant_sql` | Auditing enabled | Compliant |
| `compliant_sql` | Minimum TLS 1.2 | Compliant |

### Cluster 5 – App Service
| Resource | Policy | Expected State |
|---|---|---|
| `noncompliant_app` | Latest TLS version | NonCompliant |
| `noncompliant_app` | FTPS only | NonCompliant |
| `noncompliant_app` | Authentication enabled | NonCompliant |
| `noncompliant_app` | HTTPS only | NonCompliant |
| `compliant_app` | Latest TLS version | Compliant |
| `compliant_app` | FTPS only | Compliant |
| `compliant_app` | Authentication enabled | Compliant |
| `compliant_app` | HTTPS only | Compliant |

### Cluster 6 – Custom Deny Policy
| Resource | Expected Behaviour |
|---|---|
| `pfix-rdp-open-nsg` rule | **Denied at ARM layer** in Deny mode; NonCompliant in Audit mode |
| `pfix-rdp-restricted-nsg` rule | Allowed – source is RFC1918 range, not Internet/* |
