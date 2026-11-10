package filedlp

// ExternalMounts lists the removable volumes and network shares mounted now
// (Type TypeRemovable or TypeNetworkShare, Mount their mount point or drive
// root). Threat hunting scans (#413) skip them unless the bundle includes
// them; it is the same classification file DLP uses.
func ExternalMounts() []Destination { return externalMounts() }
