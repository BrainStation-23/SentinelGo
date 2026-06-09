package users

import "sentinelgo/internal/osinfo/shared"

func Get() []shared.UserWithGroup {
	return getLocalUsers()
}
