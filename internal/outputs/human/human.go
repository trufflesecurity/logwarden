package human

import (
	"context"
	"fmt"

	"github.com/fatih/color"
	"github.com/trufflesecurity/logwarden/internal/result"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

var (
	yellowPrinter = color.New(color.FgYellow)
	greenPrinter  = color.New(color.FgHiGreen)
	whitePrinter  = color.New(color.FgWhite)
	redPrinter    = color.New(color.FgRed)
)

type Human struct{}

func (o Human) Send(ctx context.Context, res result.Result) error {
	printer := greenPrinter

	_, _ = greenPrinter.Printf("Rule: %s\n", yellowPrinter.Sprint(res.Rule))
	_, _ = printer.Printf("Message: %s\n", whitePrinter.Sprint(res.Message))
	_, _ = printer.Printf("Type: %s\n", whitePrinter.Sprint(res.Type))
	for k, v := range res.Details {
		if k == "granted" && v == true {
			_, _ = printer.Printf("Granted: %s\n", redPrinter.Sprint("true"))
			continue
		}

		_, _ = printer.Printf("%s: %v\n", cases.Title(language.English).String(k), whitePrinter.Sprint(v))
	}
	fmt.Println("")

	return nil
}
