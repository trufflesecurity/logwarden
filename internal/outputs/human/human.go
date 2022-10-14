package human

import (
	"context"
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/trufflesecurity/gcp-auditor/internal/result"
)

var (
	yellowPrinter = color.New(color.FgYellow)
	greenPrinter  = color.New(color.FgHiGreen)
	whitePrinter  = color.New(color.FgWhite)
	redPrinter    = color.New(color.FgRed)
)

type Human struct {
}

func (o Human) Send(ctx context.Context, res result.Result) error {
	printer := greenPrinter

	greenPrinter.Printf("Rule: %s\n", yellowPrinter.Sprint(res.Rule))
	printer.Printf("Message: %s\n", whitePrinter.Sprint(res.Message))
	printer.Printf("Type: %s\n", whitePrinter.Sprint(res.Type))
	for k, v := range res.Details {
		if k == "granted" && v == true {
			printer.Printf("Granted: %s\n", redPrinter.Sprint("true"))
			continue
		}

		printer.Printf("%s: %v\n", strings.Title(k), whitePrinter.Sprint(v))
	}
	fmt.Println("")

	return nil
}
