package consumer

import (
	"context"
	"net/http"

	"github.com/antihax/optional"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/Nausf_UEAuthentication"
	Nudm_UEAU "github.com/free5gc/openapi/Nudm_UEAuthentication"
	"github.com/free5gc/openapi/Nudr_DataRepository"
	"github.com/free5gc/openapi/models"
)

func SendUeAuthPostRequest(uri string,
	authInfo *models.AuthenticationInfo) (*models.UeAuthenticationCtx, http.Header, *models.ProblemDetails, error) {
	configuration := Nausf_UEAuthentication.NewConfiguration()
	configuration.SetBasePath(uri)

	client := Nausf_UEAuthentication.NewAPIClient(configuration)

	ueAuthenticationCtx, httpResponse, err := client.DefaultApi.UeAuthenticationsPost(context.Background(), *authInfo)
	if err == nil {
		return &ueAuthenticationCtx, httpResponse.Header, nil, nil
	} else if httpResponse != nil {
		if httpResponse.Status != err.Error() {
			return nil, nil, nil, err
		}
		problem := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		return nil, nil, &problem, nil
	} else {
		return nil, nil, nil, openapi.ReportError("server no response")
	}
}

func SendAuth5gAkaConfirmRequest(uri string, authCtxId string, confirmationData *models.ConfirmationData) (
	*models.ConfirmationDataResponse, *models.ProblemDetails, error) {
	configuration := Nausf_UEAuthentication.NewConfiguration()
	configuration.SetBasePath(uri)

	client := Nausf_UEAuthentication.NewAPIClient(configuration)

	confirmData := &Nausf_UEAuthentication.UeAuthenticationsAuthCtxId5gAkaConfirmationPutParamOpts{
		ConfirmationData: optional.NewInterface(*confirmationData),
	}

	confirmResult, httpResponse, err := client.DefaultApi.UeAuthenticationsAuthCtxId5gAkaConfirmationPut(
		context.Background(), authCtxId, confirmData)
	if err == nil {
		return &confirmResult, nil, nil
	} else if httpResponse != nil {
		if httpResponse.Status != err.Error() {
			return nil, nil, err
		}
		switch httpResponse.StatusCode {
		case 400, 500:
			problem := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
			return nil, &problem, nil
		}
		return nil, nil, nil
	} else {
		return nil, nil, openapi.ReportError("server no response")
	}
}

func SendEapAuthConfirmRequest(uri string, authCtxId string, eapSessionData *models.EapSession) (
	*models.EapSession, *models.ProblemDetails, error) {
	configuration := Nausf_UEAuthentication.NewConfiguration()
	configuration.SetBasePath(uri)

	client := Nausf_UEAuthentication.NewAPIClient(configuration)

	eapSessionReq := &Nausf_UEAuthentication.EapAuthMethodParamOpts{
		EapSession: optional.NewInterface(*eapSessionData),
	}

	eapSession, httpResponse, err := client.DefaultApi.EapAuthMethod(context.Background(), authCtxId, eapSessionReq)
	if err == nil {
		return &eapSession, nil, nil
	} else if httpResponse != nil {
		if httpResponse.Status != err.Error() {
			return nil, nil, err
		}
		switch httpResponse.StatusCode {
		case 400, 500:
			problem := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
			return nil, &problem, nil
		}
		return nil, nil, nil
	} else {
		return nil, nil, openapi.ReportError("server no response")
	}
}

func SendGenerateAuthDataRequest(uri string, supiOrSuci string, authInfoReq *models.AuthenticationInfoRequest) (*models.AuthenticationInfoResult, *models.ProblemDetails, error) {
	configuration := Nudm_UEAU.NewConfiguration()
	configuration.SetBasePath(uri)

	client := Nudm_UEAU.NewAPIClient(configuration)

	authInfoResult, httpResponse, err := client.GenerateAuthDataApi.GenerateAuthData(context.Background(), supiOrSuci, *authInfoReq)
	if err == nil {
		return &authInfoResult, nil, nil
	} else if httpResponse != nil {
		if httpResponse.Status != err.Error() {
			return nil, nil, err
		}
		problem := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		return nil, &problem, nil
	} else {
		return nil, nil, openapi.ReportError("server no response")
	}
}

func SendAuthSubsDataGet(uri string, supi string) (*models.AuthenticationSubscription, *models.ProblemDetails, error) {
	configuration := Nudr_DataRepository.NewConfiguration()
	configuration.SetBasePath(uri)

	client := Nudr_DataRepository.NewAPIClient(configuration)

	authSubs, httpResponse, err := client.AuthenticationDataDocumentApi.QueryAuthSubsData(context.Background(), supi, nil)
	if err == nil {
		return &authSubs, nil, nil
	} else if httpResponse != nil {
		if httpResponse.Status != err.Error() {
			return nil, nil, err
		}
		problem := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		return nil, &problem, nil
	} else {
		return nil, nil, openapi.ReportError("server no response")
	}
}
