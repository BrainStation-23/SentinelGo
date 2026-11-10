package filedlp

import (
	"golang.org/x/sys/windows"

	"sentinelgo/internal/dlp/policy"
)

// externalMounts lists drive letters on removable buses (USB hard disks
// included) and mapped network drives. UNC paths are network paths
// whatever this says.
func externalMounts() []Destination {
	var out []Destination
	for _, v := range listVolumes() {
		out = append(out, v.Destination)
	}
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return out
	}
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		root := string(rune('A'+i)) + `:\`
		p, err := windows.UTF16PtrFromString(root)
		if err != nil || windows.GetDriveType(p) != windows.DRIVE_REMOTE {
			continue
		}
		out = append(out, Destination{Channel: policy.ChannelFileNetworkShare, Type: TypeNetworkShare, Mount: root, Source: root})
	}
	return out
}
