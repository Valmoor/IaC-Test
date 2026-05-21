###############################################################################
# OPTION 1 – IaC Misconfiguration Targets
# Tools: Checkov, tfsec, Terrascan, Snyk IaC, KICS
#
# Each resource block is annotated with the CWE/rule IDs the major scanners
# are expected to flag. No runtime attack surface is created.
###############################################################################

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.90"
    }
  }
  # FINDING: CKV_TF_1 (Checkov) – no backend configured, state stored locally
  # tfsec: No remote backend; state may contain sensitive values
}

provider "azurerm" {
  features {}
}

###############################################################################
# Resource Group
###############################################################################
resource "azurerm_resource_group" "lab" {
  name     = "scanner-lab-rg"
  location = "eastus2"
  # FINDING: CKV_AZURE_RG_1 – no lock on resource group
}

###############################################################################
# FINDING CLUSTER: Storage Account
# CKV_AZURE_3   – Storage account with blob public access allowed
# CKV_AZURE_33  – Storage account not using HTTPS
# CKV_AZURE_36  – Storage network default action not set to Deny
# CKV_AZURE_44  – Storage minimum TLS version not 1.2
# CKV_AZURE_59  – Ensure that Storage accounts disallow public access
# CKV_AZURE_190 – Ensure that Azure Storage has immutability policy
# tfsec: azure-storage-no-public-access, azure-storage-use-secure-tls-policy
###############################################################################
resource "azurerm_storage_account" "findings" {
  name                     = "scanlabstorage001"
  resource_group_name      = azurerm_resource_group.lab.name
  location                 = azurerm_resource_group.lab.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # FINDING: CKV_AZURE_33 – HTTPS not enforced
  enable_https_traffic_only = false

  # FINDING: CKV_AZURE_3 / CKV_AZURE_59 – public blob access allowed
  allow_nested_items_to_be_public = true

  # FINDING: CKV_AZURE_44 – minimum TLS version below 1.2
  min_tls_version = "TLS1_0"

  # FINDING: CKV_AZURE_36 – no network_rules block means default allow
  # network_rules omitted intentionally
}

resource "azurerm_storage_container" "findings" {
  name                  = "data"
  storage_account_name  = azurerm_storage_account.findings.name
  # FINDING: CKV_AZURE_34 – container access level is not private
  container_access_type = "blob"
}

###############################################################################
# FINDING CLUSTER: Key Vault
# CKV_AZURE_42  – Key Vault should have purge protection enabled
# CKV_AZURE_109 – Key Vault should have network ACLs configured
# CKV_AZURE_110 – Key Vault should have soft delete enabled (< 90 days)
# CKV2_AZURE_38 – Key Vault diagnostic logging not enabled
###############################################################################
resource "azurerm_key_vault" "findings" {
  name                = "scanlab-kv-001"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  tenant_id           = "00000000-0000-0000-0000-000000000000"
  sku_name            = "standard"

  # FINDING: CKV_AZURE_42 – purge protection disabled
  purge_protection_enabled = false

  # FINDING: CKV_AZURE_110 – retention too short
  soft_delete_retention_days = 7

  # FINDING: CKV_AZURE_109 – no network_acls means public internet access
  # network_acls block omitted intentionally
}

# FINDING: CKV_AZURE_112 – Key Vault secret has no expiration date
resource "azurerm_key_vault_secret" "findings" {
  name         = "app-secret"
  value        = "placeholder-not-a-real-secret"
  key_vault_id = azurerm_key_vault.findings.id
  # expiration_date omitted intentionally
}

###############################################################################
# FINDING CLUSTER: Virtual Network & NSG
# CKV_AZURE_10  – SSH/RDP unrestricted inbound
# CKV_AZURE_77  – NSG rule allows inbound from internet on all ports
# CKV_AZURE_160 – NSG should not allow inbound from * on port 3389
# CKV_AZURE_161 – NSG should not allow inbound from * on port 22
# tfsec: azure-network-no-public-ingress, azure-network-ssh-blocked-from-internet
#        azure-network-rdp-blocked-from-internet
###############################################################################
resource "azurerm_virtual_network" "findings" {
  name                = "scanlab-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  # FINDING: CKV2_AZURE_37 – DDoS protection plan not enabled
}

resource "azurerm_subnet" "findings" {
  name                 = "default"
  resource_group_name  = azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.findings.name
  address_prefixes     = ["10.0.1.0/24"]
  # FINDING: CKV_AZURE_228 – subnet has no NSG association via service_endpoints
}

resource "azurerm_network_security_group" "findings" {
  name                = "scanlab-nsg"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name

  # FINDING: CKV_AZURE_10 / CKV_AZURE_160 – RDP open to internet
  security_rule {
    name                       = "rdp-open"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  # FINDING: CKV_AZURE_10 / CKV_AZURE_161 – SSH open to internet
  security_rule {
    name                       = "ssh-open"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  # FINDING: CKV_AZURE_77 – all inbound allowed
  security_rule {
    name                       = "all-inbound"
    priority                   = 120
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

###############################################################################
# FINDING CLUSTER: Virtual Machine
# CKV_AZURE_1   – OS disk not encrypted with CMK
# CKV_AZURE_50  – VM agent not provisioned
# CKV_AZURE_93  – Managed identity not enabled
# CKV_AZURE_149 – Automatic updates disabled
# CKV_AZURE_178 – VM has public IP attached directly
# CKV2_AZURE_12 – Boot diagnostics not enabled
###############################################################################
resource "azurerm_windows_virtual_machine" "findings" {
  name                = "scanlab-vm"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  size                = "Standard_B2s"

  # FINDING: CKV_AZURE_149 – automatic updates disabled
  enable_automatic_updates = false
  patch_mode               = "Manual"

  # FINDING: CKV_AZURE_50 – VM agent not provisioned (disables all extensions)
  provision_vm_agent = false

  # These must be set but are not real credentials
  admin_username = "labadmin"
  admin_password = "LabOnly-NotReal-99!"

  network_interface_ids = [azurerm_network_interface.findings.id]

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2025-datacenter-azure-edition"
    version   = "latest"
  }

  os_disk {
    caching              = "ReadWrite"
    # FINDING: CKV_AZURE_1 – Standard_LRS with no disk encryption set
    storage_account_type = "Standard_LRS"
    # disk_encryption_set_id omitted intentionally
  }

  # FINDING: CKV_AZURE_93 – identity block omitted = no managed identity
  # identity { type = "SystemAssigned" }  <-- omitted

  # FINDING: CKV2_AZURE_12 – boot_diagnostics block omitted
  # boot_diagnostics {}  <-- omitted
}

resource "azurerm_public_ip" "findings" {
  name                = "scanlab-pip"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  allocation_method   = "Static"
  sku                 = "Standard"
  # FINDING: CKV_AZURE_47 – no idle timeout / DDoS protection
}

resource "azurerm_network_interface" "findings" {
  name                = "scanlab-nic"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location

  # FINDING: CKV_AZURE_118 – IP forwarding enabled
  enable_ip_forwarding = true

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.findings.id
    private_ip_address_allocation = "Dynamic"
    # FINDING: CKV_AZURE_178 – public IP directly on NIC
    public_ip_address_id = azurerm_public_ip.findings.id
  }
}

###############################################################################
# FINDING CLUSTER: SQL Server / Database
# CKV_AZURE_23  – SQL Server auditing not enabled
# CKV_AZURE_24  – SQL Server TDE not enabled
# CKV_AZURE_25  – SQL Server firewall allows 0.0.0.0-255.255.255.255
# CKV_AZURE_26  – SQL Server threat detection not enabled
# CKV_AZURE_27  – SQL Server alert email not configured
# CKV_AZURE_28  – SQL Server vulnerability assessment not enabled
###############################################################################
resource "azurerm_mssql_server" "findings" {
  name                         = "scanlab-sql-001"
  resource_group_name          = azurerm_resource_group.lab.name
  location                     = azurerm_resource_group.lab.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "LabOnly-NotReal-99!"

  # FINDING: CKV_AZURE_113 – public network access enabled
  public_network_access_enabled = true

  # FINDING: Minimum TLS version not set to 1.2
  minimum_tls_version = "1.0"

  # azuread_administrator block omitted
  # FINDING: CKV_AZURE_166 – Azure AD admin not set on SQL server
}

# FINDING: CKV_AZURE_25 – firewall allows all Azure + internet IPs
resource "azurerm_mssql_firewall_rule" "allow_all" {
  name             = "AllowAll"
  server_id        = azurerm_mssql_server.findings.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255"
}

resource "azurerm_mssql_database" "findings" {
  name      = "appdb"
  server_id = azurerm_mssql_server.findings.id
  sku_name  = "S1"

  # FINDING: CKV_AZURE_224 – ledger not enabled
  # FINDING: Geo-redundant backup disabled
  geo_backup_enabled = false

  # transparent_data_encryption_enabled defaults to true in provider >= 3.x
  # but leaving audit/threat detection off is the main finding surface here
}

###############################################################################
# FINDING CLUSTER: App Service
# CKV_AZURE_13  – App Service authentication not enabled
# CKV_AZURE_14  – HTTPS only not enabled
# CKV_AZURE_15  – Web app using HTTP 2.0
# CKV_AZURE_16  – TLS version too low
# CKV_AZURE_17  – Web app client certificates not enabled
# CKV_AZURE_63  – App Service not behind WAF
# CKV_AZURE_65  – App Service logging not enabled
# CKV_AZURE_78  – FTP disabled setting missing
###############################################################################
resource "azurerm_service_plan" "findings" {
  name                = "scanlab-asp"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  os_type             = "Windows"
  sku_name            = "B1"
}

resource "azurerm_windows_web_app" "findings" {
  name                = "scanlab-webapp-001"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  service_plan_id     = azurerm_service_plan.findings.id

  # FINDING: CKV_AZURE_14 – HTTPS only not enforced
  https_only = false

  site_config {
    # FINDING: CKV_AZURE_16 – TLS version below 1.2
    minimum_tls_version = "1.0"

    # FINDING: CKV_AZURE_78 – FTP state not disabled
    ftps_state = "AllAllowed"

    # FINDING: CKV_AZURE_15 – HTTP/2 not enabled
    http2_enabled = false
  }

  # FINDING: CKV_AZURE_13 – auth_settings block omitted
  # auth_settings { enabled = true }  <-- omitted

  # FINDING: CKV_AZURE_17 – client cert not required
  client_certificate_enabled = false

  # FINDING: CKV_AZURE_65 – logs block omitted
  # logs {}  <-- omitted
}

###############################################################################
# FINDING CLUSTER: Monitor / Logging
# CKV_AZURE_37  – No activity log alert for policy assignment changes
# CKV_AZURE_131 – No diagnostic setting on Key Vault
# CKV2_AZURE_26 – Log Analytics workspace not protected with CMK
###############################################################################
resource "azurerm_log_analytics_workspace" "findings" {
  name                = "scanlab-law"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  sku                 = "PerGB2018"
  # FINDING: CKV_AZURE_132 – retention below 90 days
  retention_in_days   = 30
  # FINDING: CKV2_AZURE_26 – no CMK (reservation_capacity_in_gb_per_day / cmk block absent)
}

# FINDING: CKV_AZURE_37 – no azurerm_monitor_activity_log_alert resources defined
# FINDING: CKV_AZURE_131 – no azurerm_monitor_diagnostic_setting on key vault
