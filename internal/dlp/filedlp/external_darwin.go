package filedlp

func externalMounts() []Destination {
	vols := listVolumes()
	out := make([]Destination, 0, len(vols))
	for _, v := range vols {
		out = append(out, v.Destination)
	}
	return out
}
