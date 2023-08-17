package json

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/trufflesecurity/logwarden/internal/result"
)

type JSON struct{}

func (o JSON) Send(ctx context.Context, res result.Result) error {
	out, err := json.Marshal(res)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(out))

	return nil
}
