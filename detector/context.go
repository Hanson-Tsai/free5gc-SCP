package detector

import (
	"github.com/free5gc/openapi/models"
)

var CurrentAuthProcedure AuthProcedureInfo

// Define every thing you want in this struct,
// so that you can use them in different message handler
type AuthProcedureInfo struct {
	AuthSubsData models.AuthenticationSubscription // HandleQueryAuthSubsData->Response
	AuthInfo     models.AuthenticationInfo         // HandleUeAuthPostRequest->Request
	AV           models.AuthenticationVector
	autn         string
	rand         string
	HXresStar    string
	kseaf        string
}
