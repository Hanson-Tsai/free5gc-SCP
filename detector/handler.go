package detector

import (
	"encoding/hex"
	"net/http"

	"github.com/free5gc/http_wrapper"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/scp/consumer"
	"github.com/free5gc/scp/logger"
)

const (
	ERR_MANDATORY_ABSENT = "Mandatory type is absent"
	ERR_MISS_CONDITION   = "Miss condition"
	ERR_VALUE_INCORRECT  = "Unexpected value is received"
)

func HandleUeAuthPostRequest(request *http_wrapper.Request) *http_wrapper.Response {
	// 1st
	logger.DetectorLog.Infof("HandleUeAuthPostRequest")
	//logger.DetectorLog.Infof("Destination URI: %+v", request.Header["3gpp-Sbi-Taget-Apiroot"][0])
	logger.DetectorLog.Infof("[AMF]UeAuthPost Request: %+v", request)

	updateAuthenticationInfo := request.Body.(models.AuthenticationInfo)
	CurrentAuthProcedure.AuthInfo = updateAuthenticationInfo
	// NOTE: The request from AMF is guaranteed to be correct

	// TODO: Send request to target NF by setting correct uri
	targetNfUri := request.Header["3gpp-Sbi-Taget-Apiroot"][0] //To AUSF

	response, respHeader, problemDetails, err := consumer.SendUeAuthPostRequest(targetNfUri, &updateAuthenticationInfo)
	logger.DetectorLog.Infof("[AUSF]UeAuthPost Response: %+v", response)

	// TODO: Check IEs in response body is correct
	if response.Var5gAuthData.(map[string]interface{})["hxresStar"] == "" {
		logger.DetectorLog.Errorln("UeAuthenticationCtx.Av5gAKa.HxresStar: ", ERR_MANDATORY_ABSENT)
		response.Var5gAuthData.(map[string]interface{})["hxresStar"] = CurrentAuthProcedure.HXresStar
	} else if response.Var5gAuthData.(map[string]interface{})["hxresStar"] != CurrentAuthProcedure.HXresStar {
		logger.DetectorLog.Errorln("UeAuthenticationCtx.Av5gAKa.HxresStar: ", ERR_VALUE_INCORRECT)
		response.Var5gAuthData.(map[string]interface{})["hxresStar"] = CurrentAuthProcedure.HXresStar
	}
	if response.Var5gAuthData.(map[string]interface{})["autn"] == "" {
		logger.DetectorLog.Errorln("UeAuthenticationCtx.Av5gAKa.autn: ", ERR_MANDATORY_ABSENT)
		response.Var5gAuthData.(map[string]interface{})["autn"] = CurrentAuthProcedure.autn
	} else if response.Var5gAuthData.(map[string]interface{})["autn"] != CurrentAuthProcedure.autn {
		logger.DetectorLog.Errorln("UeAuthenticationCtx.Av5gAKa.autn: ", ERR_VALUE_INCORRECT)
		response.Var5gAuthData.(map[string]interface{})["autn"] = CurrentAuthProcedure.autn
	}
	if response.Var5gAuthData.(map[string]interface{})["rand"] == "" {
		logger.DetectorLog.Errorln("UeAuthenticationCtx.Av5gAKa.rand: ", ERR_MANDATORY_ABSENT)
		response.Var5gAuthData.(map[string]interface{})["rand"] = CurrentAuthProcedure.rand
	} else if response.Var5gAuthData.(map[string]interface{})["rand"] != CurrentAuthProcedure.rand {
		logger.DetectorLog.Errorln("UeAuthenticationCtx.Av5gAKa.rand: ", ERR_VALUE_INCORRECT)
		response.Var5gAuthData.(map[string]interface{})["rand"] = CurrentAuthProcedure.autn
	}

	if response != nil {
		return http_wrapper.NewResponse(http.StatusCreated, respHeader, response)
	} else if problemDetails != nil {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	logger.DetectorLog.Errorln(err)
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,

		Cause: "UNSPECIFIED",
	}
	return http_wrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func HandleGenerateAuthDataRequest(request *http_wrapper.Request) *http_wrapper.Response {
	// 2nd
	logger.DetectorLog.Infoln("Handle GenerateAuthDataRequest")
	//logger.DetectorLog.Infof("Destination URI: %+v", request.Header["3gpp-Sbi-Taget-Apiroot"][0])
	logger.DetectorLog.Infof("[AUSF]GenerateAuthData Request: %+v", request)

	authInfoRequest := request.Body.(models.AuthenticationInfoRequest)
	supiOrSuci := request.Params["supiOrSuci"]

	// TODO: Check IEs in request body is correct
	if authInfoRequest.ServingNetworkName == "" {
		logger.DetectorLog.Errorln("AuthenticationInfoRequest.ServingNetworkName: ", ERR_MANDATORY_ABSENT)
		authInfoRequest.ServingNetworkName = CurrentAuthProcedure.AuthInfo.ServingNetworkName
	} else if authInfoRequest.ServingNetworkName != CurrentAuthProcedure.AuthInfo.ServingNetworkName {
		logger.DetectorLog.Errorln("AuthenticationInfoRequest.ServingNetworkName: ", ERR_VALUE_INCORRECT)
		authInfoRequest.ServingNetworkName = CurrentAuthProcedure.AuthInfo.ServingNetworkName
	}
	if supiOrSuci == "" {
		logger.DetectorLog.Errorln("AuthenticationInfoRequest.supiOrSuci: ", ERR_MANDATORY_ABSENT)
		supiOrSuci = CurrentAuthProcedure.AuthInfo.SupiOrSuci
	} else if supiOrSuci != CurrentAuthProcedure.AuthInfo.SupiOrSuci {
		logger.DetectorLog.Errorln("AuthenticationInfoRequest.supiOrSuci: ", ERR_VALUE_INCORRECT)
		supiOrSuci = CurrentAuthProcedure.AuthInfo.SupiOrSuci
	}

	// TODO: Send request to target NF by setting correct uri
	targetNfUri := request.Header["3gpp-Sbi-Taget-Apiroot"][0] //To UDM

	response, problemDetails, err := consumer.SendGenerateAuthDataRequest(targetNfUri, supiOrSuci, &authInfoRequest)
	logger.DetectorLog.Infof("[UDM]GenerateAuthData Response: %+v", response)
	logger.DetectorLog.Infof("[UDM][AV]: %+v", response.AuthenticationVector)
	xres, sqnXorAk, ck, ik, autn := retrieveBasicDeriveFactor(&CurrentAuthProcedure.AuthSubsData, response.AuthenticationVector.Rand)
	_, _, _, _, _ = xres, sqnXorAk, ck, ik, autn

	key := append(ck, ik...)
	hexRand, _ := hex.DecodeString(response.AuthenticationVector.Rand)
	xresStar := retrieveXresStar(key, "6B", []byte(authInfoRequest.ServingNetworkName), hexRand, xres)
	kausf := retrieve5GAkaKausf(key, "6A", []byte(authInfoRequest.ServingNetworkName), sqnXorAk)
	sha := append(hexRand, xresStar...)
	hxres := retrieveHxresStar(sha)

	CurrentAuthProcedure.HXresStar = hex.EncodeToString(hxres)
	CurrentAuthProcedure.kseaf = hex.EncodeToString(retrieveKseaf(kausf, "6C", []byte(authInfoRequest.ServingNetworkName)))
	CurrentAuthProcedure.autn = hex.EncodeToString(autn)
	CurrentAuthProcedure.rand = response.AuthenticationVector.Rand

	logger.DetectorLog.Infof("[UDM][AV][Xres][O]: %s", hex.EncodeToString(xres))
	logger.DetectorLog.Infof("[UDM][AV][Autn][O]: %s", hex.EncodeToString(autn))
	logger.DetectorLog.Infof("[UDM][AV][XresStar][O]: %s", hex.EncodeToString(xresStar))
	logger.DetectorLog.Infof("[UDM][AV][Kausf][O]: %s", hex.EncodeToString(kausf))
	logger.DetectorLog.Infof("[UDM][AV][Xres][X]: %+v", response.AuthenticationVector.Xres)
	logger.DetectorLog.Infof("[UDM][AV][Autn][X]: %+v", response.AuthenticationVector.Autn)
	logger.DetectorLog.Infof("[UDM][AV][XresStar][X]: %+v", response.AuthenticationVector.XresStar)
	logger.DetectorLog.Infof("[UDM][AV][Kausf][X]: %+v", response.AuthenticationVector.Kausf)
	logger.DetectorLog.Infof("[UDM][HXresStar][O]: %+v", CurrentAuthProcedure.HXresStar)

	// TODO: Check IEs in response body is correct
	if response.AuthType == "5G_AKA" {
		if response.AuthenticationVector.Autn == "" {
			response.AuthenticationVector.Autn = CurrentAuthProcedure.autn
			logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthenticationVector.Autn: ", ERR_MANDATORY_ABSENT)
		} else if response.AuthenticationVector.Autn != CurrentAuthProcedure.autn {
			response.AuthenticationVector.Autn = CurrentAuthProcedure.autn
			logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthenticationVector.Autn: ", ERR_VALUE_INCORRECT)
		}
		if response.AuthenticationVector.XresStar == "" {
			response.AuthenticationVector.XresStar = hex.EncodeToString(xresStar)
			logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthenticationVector.XresStar: ", ERR_MANDATORY_ABSENT)
		} else if response.AuthenticationVector.XresStar != hex.EncodeToString(xresStar) {
			response.AuthenticationVector.XresStar = hex.EncodeToString(xresStar)
			logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthenticationVector.XresStar: ", ERR_VALUE_INCORRECT)
		}
		if response.AuthenticationVector.Kausf == "" {
			response.AuthenticationVector.Kausf = hex.EncodeToString(kausf)
			logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthenticationVector.Kausf: ", ERR_MANDATORY_ABSENT)
		} else if response.AuthenticationVector.Kausf != hex.EncodeToString(kausf) {
			response.AuthenticationVector.Kausf = hex.EncodeToString(kausf)
			logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthenticationVector.Kausf: ", ERR_VALUE_INCORRECT)
		}
	}

	if response != nil {
		return http_wrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	logger.DetectorLog.Errorln(err)
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	return http_wrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func HandleQueryAuthSubsData(request *http_wrapper.Request) *http_wrapper.Response {
	// 3rd
	logger.DetectorLog.Infof("Handle QueryAuthSubsData")
	//logger.DetectorLog.Infof("Destination URI: %+v", request.Header["3gpp-Sbi-Taget-Apiroot"][0])
	logger.DetectorLog.Infof("[UDM]QueryAuthSubs Request: %+v", request)

	ueId := request.Params["ueId"]
	correctSupi, _ := extractSupi(CurrentAuthProcedure.AuthInfo.SupiOrSuci)

	if ueId == "" {
		logger.DetectorLog.Errorln("SubscriptionDataSubscriptions.ueId: ", ERR_MANDATORY_ABSENT)
		ueId = correctSupi
	} else if ueId != correctSupi {
		logger.DetectorLog.Errorln("SubscriptionDataSubscriptions.ueId: ", ERR_VALUE_INCORRECT)
		ueId = correctSupi
	}

	// TODO: Send request to correct NF by setting correct uri
	targetNfUri := request.Header["3gpp-Sbi-Taget-Apiroot"][0] //To UDR

	response, problemDetails, err := consumer.SendAuthSubsDataGet(targetNfUri, ueId)
	logger.DetectorLog.Infof("[UDR]QueryAuthSubs Response: %+v", response)

	// NOTE: The response from UDR is guaranteed to be correct
	CurrentAuthProcedure.AuthSubsData = *response

	if response != nil {
		return http_wrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	logger.DetectorLog.Errorln(err)
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	return http_wrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func HandleAuth5gAkaComfirmRequest(request *http_wrapper.Request) *http_wrapper.Response {
	// 4th
	logger.DetectorLog.Infof("Auth5gAkaComfirmRequest")
	//logger.DetectorLog.Infof("Destination URI: %+v", request.Header["3gpp-Sbi-Taget-Apiroot"][0])
	logger.DetectorLog.Infof("[AMF]5gAkaComfirm Request: %+v", request)

	updateConfirmationData := request.Body.(models.ConfirmationData)
	ConfirmationDataResponseID := request.Params["authCtxId"]

	// NOTE: The request from AMF is guaranteed to be correct

	// TODO: Send request to target NF by setting correct uri
	targetNfUri := request.Header["3gpp-Sbi-Taget-Apiroot"][0] //To AUSF

	response, problemDetails, err := consumer.SendAuth5gAkaConfirmRequest(targetNfUri, ConfirmationDataResponseID, &updateConfirmationData)
	logger.DetectorLog.Infof("[AUSF]5gAkaComfirm Response: %+v", response)

	// TODO: Check IEs in response body is correct
	if response.AuthResult == "AUTHENTICATION_SUCCESS" {
		if response.Kseaf == "" {
			response.Kseaf = CurrentAuthProcedure.kseaf
			logger.DetectorLog.Errorln("ConfirmationDataResponse.Kseaf: ", ERR_MISS_CONDITION)
		} else if response.Kseaf != CurrentAuthProcedure.kseaf {
			response.Kseaf = CurrentAuthProcedure.kseaf
			logger.DetectorLog.Errorln("ConfirmationDataResponse.Kseaf: ", ERR_VALUE_INCORRECT)
		}
		correctSupi, _ := extractSupi(CurrentAuthProcedure.AuthInfo.SupiOrSuci)
		if response.Supi == "" {
			response.Supi = correctSupi
			logger.DetectorLog.Errorln("ConfirmationDataResponse.Supi: ", ERR_MISS_CONDITION)
		} else if response.Supi != correctSupi {
			response.Supi = correctSupi
			logger.DetectorLog.Errorln("ConfirmationDataResponse.Supi: ", ERR_VALUE_INCORRECT)
		}
	} else {
		if response.Kseaf != "" {
			response.Kseaf = ""
			logger.DetectorLog.Errorln("ConfirmationDataResponse.Kseaf: ", ERR_MISS_CONDITION)
		}
		if response.Supi != "" {
			response.Supi = ""
			logger.DetectorLog.Errorln("ConfirmationDataResponse.Supi: ", ERR_MISS_CONDITION)
		}
	}

	if response != nil {
		return http_wrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}
	logger.DetectorLog.Errorln(err)
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	return http_wrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}
