//go:build darwin

package security

import (
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

func TestDarwinFirewallCheck(t *testing.T) {
	on := []shared.FirewallProfile{{Name: "Application Firewall", Enabled: true}}
	tests := []struct {
		name      string
		profiles  []shared.FirewallProfile
		responses map[string]string
		want      string
	}{
		{"state unknown", nil, nil, firewallUnknown},
		{"firewall off", []shared.FirewallProfile{{Name: "Application Firewall"}}, nil, firewallDisabled},
		{"block all", on, map[string]string{socketfilterfw + " --getblockall": "Firewall has block all state set to enabled."}, firewallBlocked},
		{"per-app rules", on, map[string]string{
			socketfilterfw + " --getblockall":    "Firewall has block all state set to disabled.",
			socketfilterfw + " --getglobalstate": "Firewall is enabled. (State = 1)",
		}, firewallUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubDarwinSecurityCommands(t, tt.responses)
			if got, _ := darwinFirewallCheck(tt.profiles)(shared.ListeningPort{Protocol: "tcp", Port: 445}); got != tt.want {
				t.Errorf("verdict = %q, want %q", got, tt.want)
			}
		})
	}
}
