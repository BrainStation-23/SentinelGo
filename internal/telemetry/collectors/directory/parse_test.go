package directory

import "testing"

func TestParseDsregcmd_EntraJoined(t *testing.T) {
	const sample = `
+----------------------------------------------------------------------+
| Device State                                                         |
+----------------------------------------------------------------------+

             AzureAdJoined : YES
          EnterpriseJoined : NO
              DomainJoined : YES
                   Version : 2.1

+----------------------------------------------------------------------+
| Device Details                                                       |
+----------------------------------------------------------------------+

                  DeviceId : 12345678-90ab-cdef-1234-567890abcdef
                Thumbprint : ABCDEF0123456789

+----------------------------------------------------------------------+
| Tenant Details                                                       |
+----------------------------------------------------------------------+

                TenantName : Contoso
                  TenantId : 87654321-dcba-4321-dcba-fedcba987654
`
	entraJoined, tenantID, deviceID := parseDsregcmd(sample)
	if !entraJoined {
		t.Error("entraJoined = false, want true")
	}
	if tenantID != "87654321-dcba-4321-dcba-fedcba987654" {
		t.Errorf("tenantID = %q, want tenant guid", tenantID)
	}
	if deviceID != "12345678-90ab-cdef-1234-567890abcdef" {
		t.Errorf("deviceID = %q, want device guid", deviceID)
	}
}

func TestParseDsregcmd_NotJoined(t *testing.T) {
	const sample = `
             AzureAdJoined : NO
          EnterpriseJoined : NO
              DomainJoined : NO
`
	entraJoined, tenantID, deviceID := parseDsregcmd(sample)
	if entraJoined {
		t.Error("entraJoined = true, want false")
	}
	if tenantID != "" || deviceID != "" {
		t.Errorf("expected empty tenant/device ids, got %q/%q", tenantID, deviceID)
	}
}

func TestParseDsregcmd_Empty(t *testing.T) {
	entraJoined, tenantID, deviceID := parseDsregcmd("")
	if entraJoined || tenantID != "" || deviceID != "" {
		t.Errorf("parseDsregcmd(\"\") = (%v, %q, %q), want (false, \"\", \"\")", entraJoined, tenantID, deviceID)
	}
}

func TestParseRealmList_Joined(t *testing.T) {
	const sample = `example.com
  type: kerberos
  realm-name: EXAMPLE.COM
  domain-name: example.com
  configured: kerberos-member
  server-software: active-directory
  client-software: sssd
`
	joined, domain := parseRealmList(sample)
	if !joined {
		t.Error("joined = false, want true")
	}
	if domain != "example.com" {
		t.Errorf("domain = %q, want example.com", domain)
	}
}

func TestParseRealmList_NotJoined(t *testing.T) {
	joined, domain := parseRealmList("")
	if joined || domain != "" {
		t.Errorf("parseRealmList(\"\") = (%v, %q), want (false, \"\")", joined, domain)
	}
	joined, domain = parseRealmList("   \n\t\n")
	if joined || domain != "" {
		t.Errorf("parseRealmList(whitespace) = (%v, %q), want (false, \"\")", joined, domain)
	}
}

func TestParseSSSDConfig(t *testing.T) {
	const sample = `[sssd]
config_file_version = 2
services = nss, pam
domains = example.com

[domain/example.com]
id_provider = ad
`
	joined, domain := parseSSSDConfig(sample)
	if !joined {
		t.Error("joined = false, want true")
	}
	if domain != "example.com" {
		t.Errorf("domain = %q, want example.com", domain)
	}
}

func TestParseSSSDConfig_MultipleDomains(t *testing.T) {
	joined, domain := parseSSSDConfig("domains = first.example.com, second.example.com")
	if !joined || domain != "first.example.com" {
		t.Errorf("got (%v, %q), want (true, first.example.com)", joined, domain)
	}
}

func TestParseSSSDConfig_NoDomains(t *testing.T) {
	joined, domain := parseSSSDConfig("[sssd]\nservices = nss, pam\n")
	if joined || domain != "" {
		t.Errorf("got (%v, %q), want (false, \"\")", joined, domain)
	}
}

func TestParseDsconfigad_Joined(t *testing.T) {
	const sample = `Active Directory Forest        = example.com
Active Directory Domain        = example.com
Computer Account                = MACBOOK$
`
	joined, domain := parseDsconfigad(sample)
	if !joined {
		t.Error("joined = false, want true")
	}
	if domain != "example.com" {
		t.Errorf("domain = %q, want example.com", domain)
	}
}

func TestParseDsconfigad_NotJoined(t *testing.T) {
	joined, domain := parseDsconfigad("")
	if joined || domain != "" {
		t.Errorf("parseDsconfigad(\"\") = (%v, %q), want (false, \"\")", joined, domain)
	}
}
