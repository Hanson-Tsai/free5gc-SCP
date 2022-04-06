package context

import (
	"fmt"

	"github.com/free5gc/openapi/models"
)

var scpCtx *SCPContext

func init() {
	scpCtx = new(SCPContext)
	scpCtx.Name = "scp"
	scpCtx.UriScheme = models.UriScheme_HTTPS
}

type SCPContext struct {
	NfId            string
	Name            string
	UriScheme       models.UriScheme
	BindingIPv4     string
	RegisterIPv4    string
	SBIPort         int
	NrfUri          string
}

// Create new SCP context
func SCP_Self() *SCPContext {
	return scpCtx
}

func (c *SCPContext) GetIPv4Uri() string {
	return fmt.Sprintf("%s://%s:%d", c.UriScheme, c.RegisterIPv4, c.SBIPort)
}

