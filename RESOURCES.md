# Option 2 – Community Vulnerable VM Images & Lab Resources

These are purpose-built, community-maintained projects designed for exactly
this use case. They are better tested and more regularly updated than anything
custom-built.

---

## Windows-Specific Targets

### Metasploitable3 (Windows Server 2008)
- **Repo:** https://github.com/rapid7/metasploitable3
- **What it is:** Rapid7's intentionally vulnerable Windows Server VM. Ships with
  known CVEs, weak services, and misconfigured applications out of the box.
- **Deploy with Vagrant:**
  ```bash
  git clone https://github.com/rapid7/metasploitable3
  cd metasploitable3
  vagrant up win2k8
  ```
- **Good for testing:** Vulnerability scanners (Nessus, Qualys, Rapid7 InsightVM),
  authenticated scan profiles, patch management tooling.

### DVWA (Damn Vulnerable Web Application)
- **Repo:** https://github.com/digininja/DVWA
- **Docker:**
  ```bash
  docker run --rm -it -p 80:80 vulnerables/web-dvwa
  ```
- **Good for testing:** Web app scanners (Burp Suite, OWASP ZAP, Acunetix).
  Covers SQLi, XSS, CSRF, file inclusion, command injection with adjustable
  difficulty levels.

### WebGoat
- **Repo:** https://github.com/WebGoat/WebGoat
- **Docker:**
  ```bash
  docker run -p 8080:8080 -p 9090:9090 webgoat/webgoat
  ```
- **Good for testing:** OWASP Top 10 scanner coverage validation.

---

## Azure-Specific Vulnerable Labs

### XMGoat (Orca Security)
- **Repo:** https://github.com/XMCyber/XMGoat
- **What it is:** Terraform-deployable intentionally misconfigured Azure
  environment. Covers privilege escalation paths, lateral movement, and
  cloud misconfigs.
- **Deploy:**
  ```bash
  git clone https://github.com/XMCyber/XMGoat
  cd XMGoat
  terraform init && terraform apply
  ```
- **Good for testing:** CSPM tools (Defender for Cloud, Wiz, Orca, Prisma Cloud),
  Azure-specific attack path analysis.

### AzureGoat (INE / AppSecco)
- **Repo:** https://github.com/ine-labs/AzureGoat
- **What it is:** Intentionally vulnerable Azure infrastructure covering OWASP
  Top 10 for cloud. Includes web app, serverless, and IaaS misconfiguration paths.
- **Deploy:**
  ```bash
  git clone https://github.com/ine-labs/AzureGoat
  cd AzureGoat
  terraform init && terraform apply
  ```
- **Good for testing:** Cloud-native attack paths, SSRF to IMDS, overprivileged
  managed identities, insecure storage.

### SadCloud (nccgroup)
- **Repo:** https://github.com/nccgroup/sadcloud
- **What it is:** Terraform modules for spinning up intentionally misconfigured
  AWS/Azure infrastructure. Modular — enable only the misconfiguration categories
  you want.
- **Good for testing:** Individual scanner rules in isolation.

---

## Scanner-Specific Test Suites

### Checkov – TerraGoat
- **Repo:** https://github.com/bridgecrewio/terragoat
- **What it is:** Bridgecrew's official intentionally vulnerable Terraform codebase,
  maintained alongside Checkov. Every misconfiguration maps to a specific Checkov
  check ID.
- **Run:**
  ```bash
  git clone https://github.com/bridgecrewio/terragoat
  checkov -d terragoat/terraform/azure --framework terraform
  ```

### tfsec – Test Fixtures
- **Repo:** https://github.com/aquasecurity/tfsec/tree/master/internal/testdata
- Built-in test fixtures used by the tfsec project itself. Useful for
  understanding exactly what syntax triggers each rule.

### Prowler (Azure)
- **Repo:** https://github.com/prowler-cloud/prowler
- Multi-cloud security scanner. Run against your lab subscription:
  ```bash
  pip install prowler
  prowler azure --subscription-id <your-sub-id>
  ```

---

## Quick Comparison

| Tool | Cloud | Infra Type | Best For |
|---|---|---|---|
| Metasploitable3 | On-prem/any | Windows VM | Vuln scanner, patch mgmt |
| DVWA | Any | Web app (Docker) | Web app scanner |
| WebGoat | Any | Web app (Docker) | OWASP Top 10 |
| XMGoat | Azure | IaaS + IAM | CSPM, attack paths |
| AzureGoat | Azure | Full stack | Cloud-native scanner |
| TerraGoat | Azure/AWS/GCP | IaC only | Checkov/tfsec rule validation |
| SadCloud | AWS/Azure | IaC only | Modular misconfiguration testing |

---

## Notes

- Always deploy these in a **dedicated isolated subscription** with no
  production connectivity, no peering, and billing alerts set.
- Tag resources clearly (`Purpose = vuln-lab`) to avoid confusion.
- Most of these projects include a destroy script or `terraform destroy` path —
  run it when done to avoid unnecessary spend and exposure.
