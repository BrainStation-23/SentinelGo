package walk

import "golang.org/x/sys/windows"

// LowerSelf puts the calling process in background processing mode: lowest
// CPU, IO and memory priority. Windows only allows it on the current
// process, so scan workers call it at startup (#412).
func LowerSelf() error {
	return windows.SetPriorityClass(windows.CurrentProcess(), windows.PROCESS_MODE_BACKGROUND_BEGIN)
}
