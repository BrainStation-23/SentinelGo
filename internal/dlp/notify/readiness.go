package notify

// Notification readiness (#323): whether a notification shown in this user's
// session can actually appear. The desktop tools exit 0 either way, so the
// session helper reads the user's settings instead. Values are contract v1,
// shared with the console (Compliance-OS#623):
//
//	supported            nothing we can detect blocks it
//	disabled:global      the user turned off all notifications
//	disabled:app         the user turned off SentinelGo's notifications
//	disabled:policy      blocked by Group Policy or MDM
//	dnd                  Do Not Disturb, Focus, quiet hours or a full-screen app
//	unavailable:<reason> no notification server, or the tool is missing
//	unknown              the setting couldn't be read
//
// The parsers below have no OS suffix, so they are tested on every platform;
// readiness_<os>.go only reads the raw settings.

import (
	"encoding/json"
	"strings"
)

// Readiness states.
const (
	ReadySupported      = "supported"
	ReadyDisabledGlobal = "disabled:global"
	ReadyDisabledApp    = "disabled:app"
	ReadyDisabledPolicy = "disabled:policy"
	ReadyDND            = "dnd"
	ReadyUnknown        = "unknown"
)

// Unavailable is the state for a missing notification server or tool.
func Unavailable(reason string) string { return "unavailable:" + reason }

// Shows reports whether a notification in this state reaches the user: it
// is shown now, or kept in the notification center (Do Not Disturb). An
// unknown state is given the benefit of the doubt, as before readiness.
func Shows(state string) bool {
	return state == ReadySupported || state == ReadyDND || state == ReadyUnknown || state == ""
}

// ── Windows ──────────────────────────────────────────────────────────────────

// winSettings are the raw values readiness_windows.go reads (nil: absent).
type winSettings struct {
	PolicyNoToast *uint32 // HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications NoToastApplicationNotification
	ToastEnabled  *uint32 // HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications ToastEnabled
	AppEnabled    *uint32 // HKCU\…\Notifications\Settings\<AUMID> Enabled
	QUNS          uint32  // SHQueryUserNotificationState; 0 when it failed
}

// QUERY_USER_NOTIFICATION_STATE values.
const (
	qunsNotPresent       = 1
	qunsBusy             = 2 // a full-screen app
	qunsRunningD3DFull   = 3
	qunsPresentationMode = 4
	qunsQuietTime        = 6 // the first hour after a new user's first sign-in
	qunsApp              = 7 // a Windows Store app is running full screen
)

func winReadiness(s winSettings) (state, detail string) {
	switch {
	case s.PolicyNoToast != nil && *s.PolicyNoToast == 1:
		return ReadyDisabledPolicy, "NoToastApplicationNotification"
	case s.ToastEnabled != nil && *s.ToastEnabled == 0:
		return ReadyDisabledGlobal, "ToastEnabled=0"
	case s.AppEnabled != nil && *s.AppEnabled == 0:
		return ReadyDisabledApp, "SentinelOps.SentinelGo Enabled=0"
	}
	switch s.QUNS {
	case qunsBusy, qunsRunningD3DFull, qunsPresentationMode, qunsQuietTime, qunsApp:
		return ReadyDND, quns(s.QUNS)
	case qunsNotPresent:
		return Unavailable("no_desktop"), quns(s.QUNS)
	}
	return ReadySupported, ""
}

func quns(v uint32) string {
	switch v {
	case qunsBusy:
		return "full-screen app"
	case qunsRunningD3DFull:
		return "full-screen game"
	case qunsPresentationMode:
		return "presentation mode"
	case qunsQuietTime:
		return "quiet time"
	case qunsApp:
		return "full-screen app"
	case qunsNotPresent:
		return "no desktop (locked or switching users)"
	}
	return ""
}

// ── macOS ────────────────────────────────────────────────────────────────────

// ncAllowNotifications is the "Allow notifications" bit of an app's flags
// in com.apple.ncprefs (macOS 11 and later).
const ncAllowNotifications = 1 << 25

// ncprefs is com.apple.ncprefs.plist converted to JSON by plutil.
type ncprefs struct {
	Apps []struct {
		BundleID string `json:"bundle-id"`
		Flags    int64  `json:"flags"`
	} `json:"apps"`
}

// darwinReadiness decides from the user's notification preferences (JSON of
// ~/Library/Preferences/com.apple.ncprefs.plist) and, when an MDM profile
// sets them, the managed notification settings for bundleID.
// managedEnabled is nil without a managed setting for the app.
func darwinReadiness(ncJSON []byte, bundleID string, managedEnabled *bool) (state, detail string) {
	if managedEnabled != nil && !*managedEnabled {
		return ReadyDisabledPolicy, "MDM notification settings"
	}
	if len(ncJSON) == 0 {
		return ReadyUnknown, "com.apple.ncprefs unreadable"
	}
	var p ncprefs
	if json.Unmarshal(ncJSON, &p) != nil {
		return ReadyUnknown, "com.apple.ncprefs unreadable"
	}
	for _, a := range p.Apps {
		if a.BundleID != bundleID {
			continue
		}
		if a.Flags&ncAllowNotifications == 0 {
			return ReadyDisabledApp, bundleID
		}
		// Focus/Do Not Disturb needs Full Disk Access to read; not reported.
		return ReadySupported, ""
	}
	// The app never posted a notification yet: macOS asks or allows on the
	// first one, depending on the app.
	return ReadyUnknown, bundleID + " not yet registered"
}

// managedNotificationEnabled reads a managed com.apple.notificationsettings
// (as JSON from plutil) for bundleID: nil when it has no entry.
func managedNotificationEnabled(js []byte, bundleID string) *bool {
	var m struct {
		NotificationSettings []struct {
			BundleIdentifier     string `json:"BundleIdentifier"`
			NotificationsEnabled *bool  `json:"NotificationsEnabled"`
		} `json:"NotificationSettings"`
	}
	if json.Unmarshal(js, &m) != nil {
		return nil
	}
	for _, s := range m.NotificationSettings {
		if s.BundleIdentifier == bundleID {
			return s.NotificationsEnabled
		}
	}
	return nil
}

// ── Linux ────────────────────────────────────────────────────────────────────

// linuxSettings are the raw answers readiness_linux.go collects.
type linuxSettings struct {
	ToolFound   bool
	ServerOwned *bool  // org.freedesktop.Notifications has an owner; nil: couldn't ask
	ShowBanners string // gsettings output, "" when not GNOME or unreadable
	Inhibited   *bool  // the server's Inhibited property (KDE); nil: unknown
}

func linuxReadiness(s linuxSettings) (state, detail string) {
	switch {
	case !s.ToolFound:
		return Unavailable("no_tool"), "notify-send not installed"
	case s.ServerOwned != nil && !*s.ServerOwned:
		return Unavailable("no_server"), "no notification server on the session bus"
	case strings.TrimSpace(s.ShowBanners) == "false":
		return ReadyDND, "GNOME Do Not Disturb"
	case s.Inhibited != nil && *s.Inhibited:
		return ReadyDND, "notifications inhibited"
	case s.ServerOwned == nil:
		return ReadyUnknown, "session bus not reachable"
	}
	return ReadySupported, ""
}

// parseBusctlBool reads "b true" / "b false" (busctl) or "(true,)" (gdbus).
func parseBusctlBool(out string) *bool {
	var v bool
	switch strings.TrimSpace(out) {
	case "b true", "(true,)", "(<true>,)":
		v = true
	case "b false", "(false,)", "(<false>,)":
		v = false
	default:
		return nil
	}
	return &v
}
