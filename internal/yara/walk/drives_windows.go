package walk

import "golang.org/x/sys/windows"

// fixedDrives lists the fixed local drives (`C:\`, `D:\`), which a full
// scan walks. Removable, network, optical and RAM drives are left out.
func fixedDrives() []string {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return []string{`C:\`}
	}
	var out []string
	for i := range 26 {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		root := string(rune('A'+i)) + `:\`
		p, err := windows.UTF16PtrFromString(root)
		if err != nil {
			continue
		}
		if windows.GetDriveType(p) == windows.DRIVE_FIXED {
			out = append(out, root)
		}
	}
	return out
}
