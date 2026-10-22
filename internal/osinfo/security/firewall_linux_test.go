//go:build linux

package security

import (
	"os"
	"path/filepath"
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

func writeFakeFile(t *testing.T, root, path, content string) {
	t.Helper()
	full := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

var (
	sshPort = shared.ListeningPort{Protocol: "tcp", Port: 22}
	smbPort = shared.ListeningPort{Protocol: "tcp", Port: 445}
)

func TestLinuxFirewallCheck_UFW(t *testing.T) {
	root := stubLinuxSecurityRoot(t)
	writeFakeFile(t, root, "/etc/ufw/applications.d/openssh-server", "[OpenSSH]\nports=22/tcp\n")
	stubLinuxSecurityCommands(t, map[string]linuxCmdResult{
		"ufw status verbose": cmdOK("Status: active\nDefault: deny (incoming), allow (outgoing)\n\nTo                         Action      From\n--                         ------      ----\nOpenSSH                    ALLOW IN    Anywhere\n"),
	})
	check := linuxFirewallCheck([]shared.FirewallProfile{{Name: "ufw", Enabled: true}})
	if got, _ := check(sshPort); got != firewallAllowed {
		t.Errorf("ssh = %q, want allowed", got)
	}
	if got, _ := check(smbPort); got != firewallBlocked {
		t.Errorf("smb = %q, want blocked", got)
	}
}

func TestLinuxFirewallCheck_Firewalld(t *testing.T) {
	root := stubLinuxSecurityRoot(t)
	writeFakeFile(t, root, "/usr/lib/firewalld/services/ssh.xml", `<service><port protocol="tcp" port="22"/></service>`)
	// The admin copy overrides the packaged one.
	writeFakeFile(t, root, "/usr/lib/firewalld/services/samba.xml", `<service><port protocol="tcp" port="445"/></service>`)
	writeFakeFile(t, root, "/etc/firewalld/services/samba.xml", `<service><port protocol="tcp" port="139"/></service>`)
	stubLinuxSecurityCommands(t, map[string]linuxCmdResult{
		"firewall-cmd --list-all-zones": cmdOK("public (default, active)\n  target: default\n  services: ssh samba\n"),
	})
	check := linuxFirewallCheck([]shared.FirewallProfile{{Name: "firewalld", Enabled: true}})
	if got, _ := check(sshPort); got != firewallAllowed {
		t.Errorf("ssh = %q, want allowed", got)
	}
	if got, _ := check(smbPort); got != firewallBlocked {
		t.Errorf("smb = %q, want blocked (the admin samba.xml opens 139 only)", got)
	}
}

func TestLinuxFirewallCheck_NoManager(t *testing.T) {
	stubLinuxSecurityRoot(t)
	tests := []struct {
		name     string
		profiles []shared.FirewallProfile
		cmds     map[string]linuxCmdResult
		want     string
	}{
		{"nothing installed", nil, nil, firewallDisabled},
		{"ufw inactive, empty iptables", []shared.FirewallProfile{{Name: "ufw"}},
			map[string]linuxCmdResult{"iptables -L -n": cmdOK("Chain INPUT (policy ACCEPT)\n")}, firewallDisabled},
		{"raw nftables drop rules", nil,
			map[string]linuxCmdResult{"nft list ruleset": cmdOK("table inet filter {\n chain input { type filter hook input priority 0; policy drop; }\n}\n")}, firewallUnknown},
		{"iptables manages filtering", []shared.FirewallProfile{{Name: "iptables", Enabled: true}}, nil, firewallUnknown},
		{"ufw active but unreadable", []shared.FirewallProfile{{Name: "ufw", Enabled: true}}, nil, firewallUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubLinuxSecurityCommands(t, tt.cmds)
			if got, _ := linuxFirewallCheck(tt.profiles)(smbPort); got != tt.want {
				t.Errorf("verdict = %q, want %q", got, tt.want)
			}
		})
	}
}
