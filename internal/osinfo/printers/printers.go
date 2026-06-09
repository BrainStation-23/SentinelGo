package printers

import (
	"sentinelgo/internal/osinfo/shared"
)

func Get() []shared.Printer {
	return getPrinters()
}

func newPrinter(description, printingType string, hDPI, vDPI int) shared.Printer {
	return shared.Printer{
		Description:  description,
		LocationType: "Local",
		PrintingType: printingType,
		PrintingResolution: shared.PrintingResolution{
			HorizontalDPI: hDPI,
			VerticalDPI:   vDPI,
		},
		MarkingType: "Unknown",
	}
}
