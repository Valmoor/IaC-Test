###############################################################################
# OPTION 4 – Azure Policy / Defender for Cloud Policy-as-Code Test Fixtures
#
# Purpose: Validate that your Azure Policy assignments, custom policy
# definitions, and Defender for Cloud recommendations fire correctly.
#
# Each resource is crafted to trigger a specific built-in policy definition.
# A COMPLIANT counterpart is included for each cluster so your scanner
# correctly reports both PASS and FAIL states.
#
# Deploy strategy:
#   1. terraform apply (creates non-compliant + compliant resources)
#   2. Assign the relevant Policy Initiative or individual definitions
#   3. az policy state trigger-scan --resource-group policy-fixtures-rg
#   4. Compare results against EXPECTED_FINDINGS.md
###############################################################################

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.90"
    }
  }
}

provider "azurerm" { features {} }

data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "policy" {
  name     = "policy-fixtures-rg"
  location = "eastus2"
  tags = {
    Purpose = "policy-scanner-test"
    Owner   = "security-team"
  }
}

###############################################################################
# POLICY FIXTURE CLUSTER 1 – Storage Account policies
#
# Built-in policies targeted:
#   [a] "Storage accounts should restrict network access"
#       Definition ID: 34c877ad-507e-4c82-993e-3452a6e0ad3c
#   [b] "Secure transfer to storage accounts should be enabled"
#       Definition ID: 404c3081-a854-4457-ae30-26a93ef643f9
#   [c] "Storage accounts should use customer-managed key for encryption"
#       Definition ID: 6fac406b-40ca-413b-bf8e-0bf964659c25
#   [d] "Storage account public access should be disallowed"
#       Definition ID: 4fa4b6c0-31ca-4c0d-b10d-24b96f62a751
###############################################################################

# NON-COMPLIANT – triggers [a], [b], [d]
resource "azurerm_storage_account" "noncompliant_storage" {
  name                     = "policyfixnoncmpl001"
  resource_group_name      = azurerm_resource_group.policy.name
  location                 = azurerm_resource_group.policy.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # Triggers [b] – secure transfer not required
  enable_https_traffic_only = false
  # Triggers [d] – public access allowed
  allow_nested_items_to_be_public = true
  # Triggers [a] – no network_rules = default Allow
  min_tls_version = "TLS1_1"

  tags = { PolicyFixture = "noncompliant" }
}

# COMPLIANT – should produce PASS for [a], [b], [d]
resource "azurerm_storage_account" "compliant_storage" {
  name                     = "policyfixcmpl001"
  resource_group_name      = azurerm_resource_group.policy.name
  location                 = azurerm_resource_group.policy.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  enable_https_traffic_only       = true
  allow_nested_items_to_be_public = false
  min_tls_version                 = "TLS1_2"

  network_rules {
    default_action             = "Deny"
    bypass                     = ["AzureServices", "Logging", "Metrics"]
    ip_rules                   = []
    virtual_network_subnet_ids = []
  }

  tags = { PolicyFixture = "compliant" }
}

###############################################################################
# POLICY FIXTURE CLUSTER 2 – Key Vault policies
#
# Built-in policies targeted:
#   [a] "Azure Key Vault should have firewall enabled"
#       Definition ID: 55615ac9-af46-4a59-874e-391cc3dfb490
#   [b] "Key vaults should have purge protection enabled"
#       Definition ID: 0b60c0b2-2dc2-4e1c-b5c9-abbed971de53
#   [c] "Key vaults should have soft delete enabled"
#       Definition ID: 1e66c121-a66a-4b1f-9b83-0fd99bf0fc2d
#   [d] "Keys should have an expiration date set"
#       Definition ID: 152b15f7-8e1f-4c1f-ab71-8c010ba5dbc0
###############################################################################

# NON-COMPLIANT – triggers [a], [b], [c]
resource "azurerm_key_vault" "noncompliant_kv" {
  name                       = "pfix-noncmpl-kv"
  location                   = azurerm_resource_group.policy.location
  resource_group_name        = azurerm_resource_group.policy.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  purge_protection_enabled   = false  # Triggers [b]
  soft_delete_retention_days = 7      # Triggers [c] (< 90 days)
  # No network_acls block            # Triggers [a]

  access_policy {
    tenant_id          = data.azurerm_client_config.current.tenant_id
    object_id          = data.azurerm_client_config.current.object_id
    secret_permissions = ["Get", "List", "Set", "Delete"]
  }

  tags = { PolicyFixture = "noncompliant" }
}

# NON-COMPLIANT secret – no expiry date, triggers [d]
resource "azurerm_key_vault_secret" "noncompliant_secret" {
  name         = "no-expiry-secret"
  value        = "fixture-placeholder-value"
  key_vault_id = azurerm_key_vault.noncompliant_kv.id
  # expiration_date omitted intentionally
  tags         = { PolicyFixture = "noncompliant" }
}

# COMPLIANT Key Vault – should produce PASS for [a], [b], [c]
resource "azurerm_key_vault" "compliant_kv" {
  name                       = "pfix-cmpl-kv"
  location                   = azurerm_resource_group.policy.location
  resource_group_name        = azurerm_resource_group.policy.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  purge_protection_enabled   = true
  soft_delete_retention_days = 90

  network_acls {
    bypass         = ["AzureServices"]
    default_action = "Deny"
  }

  access_policy {
    tenant_id          = data.azurerm_client_config.current.tenant_id
    object_id          = data.azurerm_client_config.current.object_id
    secret_permissions = ["Get", "List", "Set", "Delete"]
  }

  tags = { PolicyFixture = "compliant" }
}

# COMPLIANT secret – has expiry date, should produce PASS for [d]
resource "azurerm_key_vault_secret" "compliant_secret" {
  name            = "with-expiry-secret"
  value           = "fixture-placeholder-value"
  key_vault_id    = azurerm_key_vault.compliant_kv.id
  expiration_date = "2027-01-01T00:00:00Z"
  tags            = { PolicyFixture = "compliant" }
}

###############################################################################
# POLICY FIXTURE CLUSTER 3 – Virtual Machine policies
#
# Built-in policies targeted:
#   [a] "Virtual machines should encrypt temp disks, caches, and data flows"
#       Definition ID: 0961003e-5a0a-4549-abde-af6a37f2724d
#   [b] "Audit VMs that do not use managed disks"
#       Definition ID: 06a78e20-9358-41c9-923c-fb736d382a4d
#   [c] "System updates should be installed on your machines"
#       Definition ID: 86b3d65f-7626-441e-b690-81a8b71cff60
#   [d] "Endpoint protection solution should be installed on VMs"
#       Definition ID: 1f7c564c-0a90-4d44-b7e1-9d456cbc8e50
#   [e] "Log Analytics agent should be installed on VMs"
#       Definition ID: a70ca396-0a34-413a-88e1-b956c1e683be
#   [f] "Virtual machines should have the Azure Monitor Agent installed"
#       Definition ID: c02729e5-e5e7-4458-97fa-2b5ad0661f28
###############################################################################

resource "azurerm_virtual_network" "policy" {
  name                = "policy-vnet"
  address_space       = ["10.20.0.0/16"]
  location            = azurerm_resource_group.policy.location
  resource_group_name = azurerm_resource_group.policy.name
}

resource "azurerm_subnet" "policy" {
  name                 = "default"
  resource_group_name  = azurerm_resource_group.policy.name
  virtual_network_name = azurerm_virtual_network.policy.name
  address_prefixes     = ["10.20.1.0/24"]
}

resource "azurerm_network_interface" "noncompliant_vm" {
  name                = "pfix-noncmpl-nic"
  location            = azurerm_resource_group.policy.location
  resource_group_name = azurerm_resource_group.policy.name
  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.policy.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_network_interface" "compliant_vm" {
  name                = "pfix-cmpl-nic"
  location            = azurerm_resource_group.policy.location
  resource_group_name = azurerm_resource_group.policy.name
  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.policy.id
    private_ip_address_allocation = "Dynamic"
  }
}

# NON-COMPLIANT VM – triggers [c] (manual patching), [d] (no AMA), [e], [f]
resource "azurerm_windows_virtual_machine" "noncompliant_vm" {
  name                = "pfix-noncmpl-vm"
  resource_group_name = azurerm_resource_group.policy.name
  location            = azurerm_resource_group.policy.location
  size                = "Standard_B2s"
  admin_username      = "labadmin"
  admin_password      = "LabOnly-NotReal-99!"

  network_interface_ids = [azurerm_network_interface.noncompliant_vm.id]

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2025-datacenter-azure-edition"
    version   = "latest"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  # Triggers [c] – manual patch mode, no automatic updates
  enable_automatic_updates = false
  patch_mode               = "Manual"

  # No identity block           – triggers [d],[e],[f] indirectly
  # No boot_diagnostics block   – triggers CKV2_AZURE_12

  tags = { PolicyFixture = "noncompliant" }
}

# COMPLIANT VM – should produce PASS for [c]; AMA extension added for [f]
resource "azurerm_windows_virtual_machine" "compliant_vm" {
  name                = "pfix-cmpl-vm"
  resource_group_name = azurerm_resource_group.policy.name
  location            = azurerm_resource_group.policy.location
  size                = "Standard_B2s"
  admin_username      = "labadmin"
  admin_password      = "LabOnly-NotReal-99!"

  network_interface_ids = [azurerm_network_interface.compliant_vm.id]

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2025-datacenter-azure-edition"
    version   = "latest"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
  }

  enable_automatic_updates = true
  patch_mode               = "AutomaticByPlatform"
  hotpatching_enabled      = true
  provision_vm_agent       = true

  identity { type = "SystemAssigned" }
  boot_diagnostics {}

  tags = { PolicyFixture = "compliant" }
}

# Azure Monitor Agent on compliant VM only – triggers [f] FAIL on noncompliant_vm
resource "azurerm_virtual_machine_extension" "ama_compliant" {
  name                       = "AzureMonitorWindowsAgent"
  virtual_machine_id         = azurerm_windows_virtual_machine.compliant_vm.id
  publisher                  = "Microsoft.Azure.Monitor"
  type                       = "AzureMonitorWindowsAgent"
  type_handler_version       = "1.22"
  auto_upgrade_minor_version = true
  automatic_upgrade_enabled  = true
  tags                       = { PolicyFixture = "compliant" }
}

###############################################################################
# POLICY FIXTURE CLUSTER 4 – SQL Server policies
#
# Built-in policies targeted:
#   [a] "Auditing on SQL server should be enabled"
#       Definition ID: a6fb4358-5bf4-4ad7-ba82-2cd2f41ce5e9
#   [b] "Azure Defender for SQL should be enabled for unprotected SQL Servers"
#       Definition ID: abfb4388-5bf4-4ad7-ba82-2cd2f41ce5e9
#   [c] "SQL servers should use customer-managed keys to encrypt data at rest"
#       Definition ID: 0d134df8-db83-46fb-ad72-fe0c9428c8dd
#   [d] "SQL Server should use a virtual network service endpoint"
#       Definition ID: ae5d2f14-d830-42b6-9899-df6cfe9c71a3
###############################################################################

# NON-COMPLIANT SQL Server – triggers [a], [b]
resource "azurerm_mssql_server" "noncompliant_sql" {
  name                         = "pfix-noncmpl-sql"
  resource_group_name          = azurerm_resource_group.policy.name
  location                     = azurerm_resource_group.policy.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "LabOnly-NotReal-99!"
  public_network_access_enabled = true
  minimum_tls_version           = "1.0"
  # No auditing policy  – triggers [a]
  # No Defender plan    – triggers [b]
  tags = { PolicyFixture = "noncompliant" }
}

# COMPLIANT SQL Server – has auditing and TLS 1.2
resource "azurerm_mssql_server" "compliant_sql" {
  name                          = "pfix-cmpl-sql"
  resource_group_name           = azurerm_resource_group.policy.name
  location                      = azurerm_resource_group.policy.location
  version                       = "12.0"
  administrator_login           = "sqladmin"
  administrator_login_password  = "LabOnly-NotReal-99!"
  public_network_access_enabled = false
  minimum_tls_version           = "1.2"
  tags                          = { PolicyFixture = "compliant" }
}

resource "azurerm_log_analytics_workspace" "policy" {
  name                = "policy-law"
  location            = azurerm_resource_group.policy.location
  resource_group_name = azurerm_resource_group.policy.name
  sku                 = "PerGB2018"
  retention_in_days   = 365
}

# COMPLIANT – auditing on compliant SQL server; absent on noncompliant triggers [a]
resource "azurerm_mssql_server_extended_auditing_policy" "compliant_sql" {
  server_id                               = azurerm_mssql_server.compliant_sql.id
  log_monitoring_enabled                  = true
  retention_in_days                       = 90
}

###############################################################################
# POLICY FIXTURE CLUSTER 5 – App Service policies
#
# Built-in policies targeted:
#   [a] "App Service apps should use the latest TLS version"
#       Definition ID: f0e6e85b-9b9f-4a4b-b67b-f730d42f1b0b
#   [b] "App Service apps should require FTPS only"
#       Definition ID: 399b2637-a50f-4f95-96f8-3a145476eb15
#   [c] "App Service apps should have authentication enabled"
#       Definition ID: 95bccee9-a7f8-4bec-9ee9-62c3473701fc
#   [d] "App Service apps should only be accessible over HTTPS"
#       Definition ID: a4af4a39-4135-47fb-b175-47fbdf85311d
###############################################################################

resource "azurerm_service_plan" "policy" {
  name                = "policy-asp"
  resource_group_name = azurerm_resource_group.policy.name
  location            = azurerm_resource_group.policy.location
  os_type             = "Windows"
  sku_name            = "B1"
}

# NON-COMPLIANT app – triggers [a], [b], [c], [d]
resource "azurerm_windows_web_app" "noncompliant_app" {
  name                = "pfix-noncmpl-app"
  resource_group_name = azurerm_resource_group.policy.name
  location            = azurerm_resource_group.policy.location
  service_plan_id     = azurerm_service_plan.policy.id
  https_only          = false  # triggers [d]

  site_config {
    minimum_tls_version = "1.0"       # triggers [a]
    ftps_state          = "AllAllowed" # triggers [b]
  }
  auth_settings { enabled = false }   # triggers [c]
  tags = { PolicyFixture = "noncompliant" }
}

# COMPLIANT app – should produce PASS for [a], [b], [c], [d]
resource "azurerm_windows_web_app" "compliant_app" {
  name                = "pfix-cmpl-app"
  resource_group_name = azurerm_resource_group.policy.name
  location            = azurerm_resource_group.policy.location
  service_plan_id     = azurerm_service_plan.policy.id
  https_only          = true

  site_config {
    minimum_tls_version = "1.2"
    ftps_state          = "Disabled"
    http2_enabled       = true
  }
  auth_settings { enabled = true }
  identity { type = "SystemAssigned" }
  tags = { PolicyFixture = "compliant" }
}

###############################################################################
# POLICY FIXTURE CLUSTER 6 – Custom deny policy
#
# Creates a custom policy definition that DENIES creation of NSGs with
# port 3389 open to Any, then creates one NSG that violates it.
# Use this to validate your custom policy enforcement pipeline.
###############################################################################

resource "azurerm_policy_definition" "deny_rdp_any" {
  name         = "deny-rdp-open-to-any"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Deny NSG rules that allow RDP from Any source"
  description  = "Denies creation of NSG security rules that allow TCP 3389 from source *"

  metadata = jsonencode({
    category = "Network"
    version  = "1.0.0"
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type"
          equals = "Microsoft.Network/networkSecurityGroups/securityRules"
        },
        {
          field  = "Microsoft.Network/networkSecurityGroups/securityRules/access"
          equals = "Allow"
        },
        {
          field  = "Microsoft.Network/networkSecurityGroups/securityRules/direction"
          equals = "Inbound"
        },
        {
          anyOf = [
            {
              field  = "Microsoft.Network/networkSecurityGroups/securityRules/destinationPortRange"
              equals = "3389"
            },
            {
              field    = "Microsoft.Network/networkSecurityGroups/securityRules/destinationPortRanges[*]"
              contains = "3389"
            }
          ]
        },
        {
          anyOf = [
            {
              field  = "Microsoft.Network/networkSecurityGroups/securityRules/sourceAddressPrefix"
              equals = "*"
            },
            {
              field  = "Microsoft.Network/networkSecurityGroups/securityRules/sourceAddressPrefix"
              equals = "Internet"
            },
            {
              field  = "Microsoft.Network/networkSecurityGroups/securityRules/sourceAddressPrefix"
              equals = "0.0.0.0/0"
            }
          ]
        }
      ]
    }
    then = {
      effect = "Deny"
    }
  })
}

# Policy assignment – assign to resource group scope
resource "azurerm_resource_group_policy_assignment" "deny_rdp_any" {
  name                 = "deny-rdp-any-assignment"
  resource_group_id    = azurerm_resource_group.policy.id
  policy_definition_id = azurerm_policy_definition.deny_rdp_any.id
  description          = "Test fixture: enforces that no NSG allows RDP from Any"
  display_name         = "Deny open RDP – policy fixture"
}

# This NSG should be DENIED by the policy above (use in audit mode first)
resource "azurerm_network_security_group" "policy_violation" {
  name                = "pfix-rdp-open-nsg"
  location            = azurerm_resource_group.policy.location
  resource_group_name = azurerm_resource_group.policy.name
  tags                = { PolicyFixture = "should-be-denied" }
}

resource "azurerm_network_security_group_rule" "rdp_open" {
  name                        = "rdp-from-any"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "3389"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.policy.name
  network_security_group_name = azurerm_network_security_group.policy_violation.name
  # With policy in Deny mode this rule creation will be blocked at the ARM layer
}

# COMPLIANT NSG – RDP restricted to specific CIDR; should pass the deny policy
resource "azurerm_network_security_group" "policy_compliant" {
  name                = "pfix-rdp-restricted-nsg"
  location            = azurerm_resource_group.policy.location
  resource_group_name = azurerm_resource_group.policy.name
  tags                = { PolicyFixture = "compliant" }
}

resource "azurerm_network_security_group_rule" "rdp_restricted" {
  name                        = "rdp-from-vpn"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "3389"
  source_address_prefix       = "10.0.0.0/8"  # VPN range only
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.policy.name
  network_security_group_name = azurerm_network_security_group.policy_compliant.name
}
