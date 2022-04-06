package util

import (
	"net/http"
	"time"

	"github.com/free5gc/path_util"
)

const TimeFormat = time.RFC3339

// Path of HTTP2 key and log file
var (
	SCP_LOG_PATH                                 = path_util.Free5gcPath("free5gc/scpsslkey.log")
	SCP_PEM_PATH                                 = path_util.Free5gcPath("free5gc/support/TLS/scp.pem")
	SCP_KEY_PATH                                 = path_util.Free5gcPath("free5gc/support/TLS/scp.key")
	SCP_CONFIG_PATH                              = path_util.Free5gcPath("free5gc/config/scpcfg.yaml")
	ERROR_REQUEST_PARAMETERS                     = "ERROR_REQUEST_PARAMETERS"
	USER_UNKNOWN                                 = "USER_UNKNOWN"
	CONTEXT_NOT_FOUND                            = "CONTEXT_NOT_FOUND"
	ERROR_INITIAL_PARAMETERS                     = "ERROR_INITIAL_PARAMETERS"
	POLICY_CONTEXT_DENIED                        = "POLICY_CONTEXT_DENIED"
	ERROR_TRIGGER_EVENT                          = "ERROR_TRIGGER_EVENT"
	ERROR_TRAFFIC_MAPPING_INFO_REJECTED          = "ERROR_TRAFFIC_MAPPING_INFO_REJECTED"
	BDT_POLICY_NOT_FOUND                         = "BDT_POLICY_NOT_FOUND"
	REQUESTED_SERVICE_NOT_AUTHORIZED             = "REQUESTED_SERVICE_NOT_AUTHORIZED"
	REQUESTED_SERVICE_TEMPORARILY_NOT_AUTHORIZED = "REQUESTED_SERVICE_TEMPORARILY_NOT_AUTHORIZED" // NWDAF
	UNAUTHORIZED_SPONSORED_DATA_CONNECTIVITY     = "UNAUTHORIZED_SPONSORED_DATA_CONNECTIVITY"
	PDU_SESSION_NOT_AVAILABLE                    = "PDU_SESSION_NOT_AVAILABLE"
	APPLICATION_SESSION_CONTEXT_NOT_FOUND        = "APPLICATION_SESSION_CONTEXT_NOT_FOUND"
	PcpErrHttpStatusMap                          = map[string]int32{
		ERROR_REQUEST_PARAMETERS:                     http.StatusBadRequest,
		USER_UNKNOWN:                                 http.StatusBadRequest,
		ERROR_INITIAL_PARAMETERS:                     http.StatusBadRequest,
		ERROR_TRIGGER_EVENT:                          http.StatusBadRequest,
		POLICY_CONTEXT_DENIED:                        http.StatusForbidden,
		ERROR_TRAFFIC_MAPPING_INFO_REJECTED:          http.StatusForbidden,
		REQUESTED_SERVICE_NOT_AUTHORIZED:             http.StatusForbidden,
		REQUESTED_SERVICE_TEMPORARILY_NOT_AUTHORIZED: http.StatusForbidden,
		UNAUTHORIZED_SPONSORED_DATA_CONNECTIVITY:     http.StatusForbidden,
		CONTEXT_NOT_FOUND:                            http.StatusNotFound,
		BDT_POLICY_NOT_FOUND:                         http.StatusNotFound,
		APPLICATION_SESSION_CONTEXT_NOT_FOUND:        http.StatusNotFound,
		PDU_SESSION_NOT_AVAILABLE:                    http.StatusInternalServerError,
	}
)
