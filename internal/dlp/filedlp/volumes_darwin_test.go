package filedlp

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/sys/unix"

	"sentinelgo/internal/dlp/policy"
)

func statfs(mnt, from, fstype string, flags uint32) unix.Statfs_t {
	var st unix.Statfs_t
	copy(st.Mntonname[:], mnt)
	copy(st.Mntfromname[:], from)
	copy(st.Fstypename[:], fstype)
	st.Flags = flags
	return st
}

func TestMacVolumes(t *testing.T) {
	prevFS, prevDU, prevIO := getfsstat, runDiskutil, runIoreg
	t.Cleanup(func() { getfsstat, runDiskutil, runIoreg = prevFS, prevDU, prevIO })
	mounts := []unix.Statfs_t{
		statfs("/", "/dev/disk3s1s1", "apfs", unix.MNT_RDONLY),
		statfs("/Volumes/KINGSTON", "/dev/disk4s1", "msdos", 0),
		statfs("/Volumes/Backup", "/dev/disk5s1", "apfs", 0),
		statfs("/Volumes/Finance", "//ann@files.corp.example/Finance", "smbfs", 0),
		statfs("/Volumes/Broken", "/dev/disk6s1", "msdos", 0),
	}
	getfsstat = func() []unix.Statfs_t { return mounts }
	diskutilCalls := 0
	runDiskutil = func(_ context.Context, args ...string) ([]byte, error) {
		diskutilCalls++
		switch args[len(args)-1] {
		case "/dev/disk4s1":
			return []byte(diskutilUSB), nil
		case "/dev/disk5s1":
			return []byte(`<plist><dict><key>BusProtocol</key><string>PCI-Express</string><key>Internal</key><true/></dict></plist>`), nil
		}
		return nil, errors.New("no such disk")
	}
	runIoreg = func(context.Context) ([]byte, error) { return []byte(ioregUSB), nil }

	vols := macVolumes()
	if len(vols) != 2 {
		t.Fatalf("volumes %+v", vols)
	}
	usb, share := vols[0], vols[1]
	if usb.Channel != policy.ChannelFileRemovable || usb.Mount != "/Volumes/KINGSTON" || usb.VolumeLabel != "KINGSTON" ||
		usb.USB == nil || usb.USB.VendorID != "0951" || usb.Source != "/dev/disk4s1" {
		t.Errorf("usb %+v %+v", usb, usb.USB)
	}
	if share.Channel != policy.ChannelFileNetworkShare || share.ShareHost != "files.corp.example" {
		t.Errorf("share %+v", share)
	}
	// Classified once per mount; a failed classification is tried again.
	calls := diskutilCalls
	macVolumes()
	if diskutilCalls != calls+1 { // only the broken disk again
		t.Errorf("diskutil runs: %d then %d", calls, diskutilCalls)
	}
	// Unmounted: forgotten, classified again when it comes back.
	getfsstat = func() []unix.Statfs_t { return nil }
	macVolumes()
	getfsstat = func() []unix.Statfs_t { return mounts }
	calls = diskutilCalls
	macVolumes()
	if diskutilCalls != calls+3 {
		t.Errorf("not classified again after unmount: %d then %d", calls, diskutilCalls)
	}
}

func TestDarwinDevices_RemountCommands(t *testing.T) {
	prev := runDiskutil
	t.Cleanup(func() { runDiskutil = prev })
	var got [][]string
	fail := ""
	runDiskutil = func(_ context.Context, args ...string) ([]byte, error) {
		got = append(got, args)
		if args[0] == fail {
			return nil, errors.New("busy")
		}
		return nil, nil
	}
	if err := setReadOnlyDevice(devVolume{Destination: Destination{Source: "/dev/disk4s1"}}, true); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0][0] != "unmount" || got[1][1] != "readOnly" {
		t.Errorf("commands %v", got)
	}
	got = nil
	fail = "unmount"
	if err := remountDevice("/dev/disk4s1", false); err == nil || len(got) != 1 {
		t.Errorf("a busy unmount must stop there: %v %v", err, got)
	}
	fail = "mount"
	if err := remountDevice("/dev/disk4s1", false); err == nil {
		t.Error("a failed mount is an error")
	}
}
