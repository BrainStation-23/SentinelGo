package users

import "sentinelgo/internal/osinfo/shared"

func Get() []shared.UserWithGroup {
	return getLocalUsers()
}

// Identity returns the local admin group's members, the signed-in users,
// the last signed-in user and the device's directory join (#223).
func Identity() shared.UserIdentity {
	return getIdentity()
}
