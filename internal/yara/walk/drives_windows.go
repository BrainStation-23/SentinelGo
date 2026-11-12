package walk

import "golang.org/x/sys/windows"

// fixedDrives lists the fixed local drives (`C:\`, `D:\`), which a full
// scan walks. Removable, network, optical and RAM drives are left out.
func fixedDrives() []string {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return []string{`C:\`}
	}
	const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	var out []string
	for i, bit := 0, uint32(1); i < len(letters); i, bit = i+1, bit<<1 {
		if mask&bit == 0 {
			continue
		}
		root := letters[i:i+1] + `:\`
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
