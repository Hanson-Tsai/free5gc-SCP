package logger

import (
	"os"
	"time"

	formatter "github.com/antonfisher/nested-logrus-formatter"
	"github.com/sirupsen/logrus"

	"github.com/free5gc/logger_conf"
	"github.com/free5gc/logger_util"
)

var (
	log                    *logrus.Logger
	AppLog                 *logrus.Entry
	InitLog                *logrus.Entry
	CfgLog                 *logrus.Entry
	Consumerlog            *logrus.Entry
	DetectorLog            *logrus.Entry
	UtilLog                *logrus.Entry
	CtxLog                 *logrus.Entry
	GinLog                 *logrus.Entry
)

func init() {
	log = logrus.New()
	log.SetReportCaller(false)

	log.Formatter = &formatter.Formatter{
		TimestampFormat: time.RFC3339,
		TrimMessages:    true,
		NoFieldsSpace:   true,
		HideKeys:        true,
		FieldsOrder:     []string{"component", "category"},
	}

	free5gcLogHook, err := logger_util.NewFileHook(logger_conf.Free5gcLogFile, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o666)
	if err == nil {
		log.Hooks.Add(free5gcLogHook)
	}

	selfLogHook, err := logger_util.NewFileHook(logger_conf.NfLogDir+"scp.log", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o666)
	if err == nil {
		log.Hooks.Add(selfLogHook)
	}

	AppLog = log.WithFields(logrus.Fields{"component": "SCP", "category": "App"})
	InitLog = log.WithFields(logrus.Fields{"component": "SCP", "category": "Init"})
	CfgLog = log.WithFields(logrus.Fields{"component": "SCP", "category": "CFG"})
	UtilLog = log.WithFields(logrus.Fields{"component": "SCP", "category": "Util"})
	Consumerlog = log.WithFields(logrus.Fields{"component": "SCP", "category": "Consumer"})
	DetectorLog = log.WithFields(logrus.Fields{"component": "SCP", "category": "Detector"})
	CtxLog = log.WithFields(logrus.Fields{"component": "SCP", "category": "Context"})
	GinLog = log.WithFields(logrus.Fields{"component": "SCP", "category": "GIN"})
}

func SetLogLevel(level logrus.Level) {
	log.SetLevel(level)
}

func SetReportCaller(set bool) {
	log.SetReportCaller(set)
}
