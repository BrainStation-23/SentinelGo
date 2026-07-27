package svcparse

import "testing"

func TestExtractServiceName(t *testing.T) {
	tests := []struct {
		name       string
		executable string
		args       string
		wantName   string
		wantOK     bool
	}{
		// sc.exe
		{"sc start", "sc.exe", "start MyService", "MyService", true},
		{"sc stop with full windows path", `C:\Windows\System32\sc.exe`, "stop MyService", "MyService", true},
		{"sc query case-insensitive exe", "SC.EXE", "query MyService", "MyService", true},
		{"sc unknown subcommand", "sc.exe", "pause MyService", "", false},
		{"sc empty args", "sc.exe", "", "", false},
		{"sc extra whitespace", "sc.exe", "  start   MyService  ", "MyService", true},

		// net start/stop
		{"net.exe start", "net.exe", "start Spooler", "Spooler", true},
		{"net stop (no .exe)", "net", "stop Spooler", "Spooler", true},
		{"net missing service name", "net.exe", "start", "", false},

		// iisreset
		{"iisreset empty args always w3svc", "iisreset.exe", "", "w3svc", true},
		{"iisreset args irrelevant", "iisreset.exe", "/noforce", "w3svc", true},

		// appcmd
		{"appcmd start apppool", "appcmd.exe", "start apppool /apppool.name:MyPool", "MyPool", true},
		{"appcmd stop apppool case-insensitive flag", "appcmd.exe", "stop apppool /APPPOOL.NAME:MyPool", "MyPool", true},
		{"appcmd not an apppool command", "appcmd.exe", "start site /site.name:Default", "", false},

		// systemctl
		{"systemctl start", "systemctl", "start nginx", "nginx", true},
		{"systemctl restart with suffix", "systemctl", "restart nginx.service", "nginx.service", true},
		{"systemctl wrong case rejected", "Systemctl", "start nginx", "", false},
		{"systemctl unknown subcommand", "systemctl", "enable nginx", "", false},

		// service <name> start|stop
		{"service start", "service", "nginx start", "nginx", true},
		{"service stop", "service", "nginx stop", "nginx", true},
		{"service wrong order rejected", "service", "start nginx", "", false},

		// launchctl
		{"launchctl start", "launchctl", "start com.example.foo", "com.example.foo", true},
		{"launchctl kickstart", "launchctl", "kickstart system/com.example.foo", "system/com.example.foo", true},
		{"launchctl kickstart skips -k flag", "launchctl", "kickstart -k gui/501/com.example.foo", "gui/501/com.example.foo", true},

		// brew services
		{"brew services start", "brew", "services start postgresql", "postgresql", true},
		{"brew services stop", "brew", "services stop postgresql", "postgresql", true},
		{"brew not a services subcommand", "brew", "install postgresql", "", false},

		// unrecognized tool
		{"unrecognized executable", "notepad.exe", `C:\file.txt`, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotOK := ExtractServiceName(tt.executable, tt.args)
			if gotOK != tt.wantOK || gotName != tt.wantName {
				t.Errorf("ExtractServiceName(%q, %q) = (%q, %v), want (%q, %v)",
					tt.executable, tt.args, gotName, gotOK, tt.wantName, tt.wantOK)
			}
		})
	}
}
