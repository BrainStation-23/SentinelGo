package walk

// macOS has no O_NOATIME; volumes are mounted with lazy access times.
const noatime = 0
