package outputs

import (
	"context"

	"github.com/trufflesecurity/logwarden/internal/result"
)

type Output interface {
	Send(ctx context.Context, res result.Result) error
}
