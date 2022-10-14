package outputs

import (
	"context"

	"github.com/trufflesecurity/gcp-auditor/internal/result"
)

type Output interface {
	Send(ctx context.Context, res result.Result) error
}
