//go:build linux

package task

// White-box tests for Linux-specific executor logic.
// Package task (not task_test) to access unexported containsPrivilegedCommands.

import "testing"

func TestContainsPrivilegedCommands(t *testing.T) {
	tests := []struct {
		name   string
		script string
		want   bool
	}{
		{name: "empty script", script: "", want: false},
		{name: "plain echo", script: "echo hello", want: false},
		{name: "python print", script: "print('hello')", want: false},
		{name: "systemctl", script: "systemctl restart nginx", want: true},
		{name: "service command", script: "service apache2 stop", want: true},
		{name: "modprobe", script: "modprobe kvm", want: true},
		{name: "insmod", script: "insmod /lib/modules/module.ko", want: true},
		{name: "rmmod", script: "rmmod usb_storage", want: true},
		{name: "mount command", script: "mount /dev/sdb1 /mnt", want: true},
		{name: "umount command", script: "umount /mnt/data", want: true},
		{name: "chown", script: "chown root:root /etc/passwd", want: true},
		{name: "chmod 777", script: "chmod 777 /tmp/file", want: true},
		{name: "chmod 755", script: "chmod 755 /usr/local/bin/app", want: true},
		{name: "write to /etc/", script: "echo 'data' > /etc/hosts.conf", want: true},
		{name: "write to /sys/", script: "echo 1 > /sys/kernel/something", want: true},
		{name: "read from /proc/", script: "cat /proc/cpuinfo", want: true},
		{name: "iptables", script: "iptables -A INPUT -p tcp --dport 80 -j ACCEPT", want: true},
		{name: "sysctl", script: "sysctl -w net.ipv4.ip_forward=1", want: true},
		{name: "multiline with privilege", script: "#!/bin/bash\necho start\nsystemctl reload nginx\necho done", want: true},
		{name: "multiline without privilege", script: "#!/bin/bash\necho hello\nls -la\ncat README.md", want: false},
		{name: "commented-out privilege", script: "# systemctl restart service\necho safe", want: true}, // comments not stripped; this is intentional
		{name: "chmod 644 not privileged pattern", script: "chmod 644 file.txt", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsPrivilegedCommands(tt.script)
			if got != tt.want {
				t.Errorf("containsPrivilegedCommands(%q) = %v, want %v", tt.script, got, tt.want)
			}
		})
	}
}
