# Security Scanner Test Lab

Terraform-based lab for validating security scanning tools against Azure
infrastructure. Four distinct options, each targeting a different layer of
the scanning stack.

```
scanner-test-lab/
├── 1-iac-misconfigs/          # IaC static analysis (Checkov, tfsec, Terrascan, Snyk IaC)
│   ├── main.tf
│   └── EXPECTED_FINDINGS.md
├── 2-community-resources/     # Community vulnerable images & projects (no Terraform needed)
│   └── RESOURCES.md
├── 3-benchmark-gaps/          # CIS Azure Foundations Benchmark v2.0 gap fixtures
│   ├── main.tf
│   └── EXPECTED_FINDINGS.md
└── 4-policy-fixtures/         # Azure Policy / Defender for Cloud test fixtures
    ├── main.tf
    └── EXPECTED_FINDINGS.md
```

---

## Option 1 – IaC Static Analysis Targets (`1-iac-misconfigs/`)

**What:** A single Terraform file with 39 documented misconfigurations across
Storage, Key Vault, NSG, VM, SQL Server, App Service, and Log Analytics.
Nothing gets deployed — scanners run against the `.tf` source only.

**Tools:** Checkov, tfsec, Terrascan, Snyk IaC, KICS

**Use when:** Validating your CI/CD pipeline's IaC scanning gate, testing
suppression/baseline rules, or comparing scanner coverage across tools.

```bash
cd 1-iac-misconfigs
checkov -f main.tf --framework terraform
tfsec .
terrascan scan -i terraform -d .
```

See `EXPECTED_FINDINGS.md` for the full 39-finding ground truth with
Checkov IDs, tfsec IDs, and severity ratings.

---

## Option 2 – Community Vulnerable VMs (`2-community-resources/`)

**What:** A curated reference guide to purpose-built vulnerable environments
maintained by the security community.

**Highlights:**
- **Metasploitable3** — Windows Server with real CVEs for vuln scanner validation
- **XMGoat / AzureGoat** — Azure-native misconfigured Terraform labs for CSPM tools
- **TerraGoat** — Bridgecrew's official Checkov test corpus
- **DVWA / WebGoat** — Web app scanner targets (OWASP Top 10)

No files to deploy here — read `RESOURCES.md` for deploy instructions per project.

---

## Option 3 – CIS Benchmark Gaps (`3-benchmark-gaps/`)

**What:** Terraform that deploys real Azure resources failing 32 specific CIS
Azure Foundations Benchmark v2.0 controls. One control (5.2.1) is intentionally
compliant to verify your scanner reports PASS alongside failures.

**Tools:** Microsoft Defender for Cloud, Prisma Cloud, Wiz, Orca, Azure Policy
with the CIS initiative assigned.

**Use when:** Validating your CSPM tool's benchmark coverage, testing
Defender for Cloud regulatory compliance reporting, or building a compliance
score baseline.

```bash
cd 3-benchmark-gaps
terraform init && terraform apply

# Trigger immediate policy evaluation
az policy state trigger-scan --resource-group cis-benchmark-gaps-rg

# View non-compliant controls
az policy state list \
  --resource-group cis-benchmark-gaps-rg \
  --filter "complianceState eq 'NonCompliant'" \
  -o table
```

See `EXPECTED_FINDINGS.md` for the full control mapping.

---

## Option 4 – Policy-as-Code Fixtures (`4-policy-fixtures/`)

**What:** Paired compliant/non-compliant resources for 5 resource types,
plus a custom Deny policy definition that blocks NSGs with RDP open to Any.
Every fixture has a compliant counterpart so your scanner must correctly
report both PASS and FAIL.

**Tools:** Azure Policy, Defender for Cloud, Terraform Sentinel, OPA/Conftest

**Use when:** Testing custom policy definitions before production rollout,
validating that built-in policy assignments fire on the right resources,
or verifying ARM-layer Deny enforcement.

```bash
cd 4-policy-fixtures

# Deploy in Audit mode first (edit policy effect to "Audit" before apply)
terraform init && terraform apply

# Trigger scan
az policy state trigger-scan --resource-group policy-fixtures-rg

# Once validated, switch to Deny mode and re-apply to test enforcement
```

See `EXPECTED_FINDINGS.md` for the full compliant/non-compliant matrix.

---

## Prerequisites

```bash
# Terraform >= 1.6
terraform version

# Azure CLI, logged in
az login
az account set --subscription "<your-isolated-lab-subscription-id>"

# Recommended: dedicated subscription with no prod connectivity
```

---

## Cost & Cleanup

Options 3 and 4 deploy real resources that incur cost. Estimated spend:

| Option | Resources | Approx. cost |
|---|---|---|
| 1 | None (static scan only) | $0 |
| 3 | 2x VM B2s, SQL, App Service, Storage, PostgreSQL | ~$8–12/day |
| 4 | 2x VM B2s, SQL x2, App Service x2, Storage x2 | ~$10–15/day |

**Always destroy when not actively testing:**
```bash
terraform destroy -auto-approve
```

Tag all resources with `Purpose = scanner-lab` and set a budget alert on the
subscription to catch runaway resources.
