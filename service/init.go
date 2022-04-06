package service

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"

	"github.com/gin-contrib/cors"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"

	"github.com/free5gc/http2_util"
	"github.com/free5gc/logger_util"
	/*openApiLogger "github.com/free5gc/openapi/logger"*/
	"github.com/free5gc/path_util"
	pathUtilLogger "github.com/free5gc/path_util/logger"
	"github.com/free5gc/scp/consumer"
	"github.com/free5gc/scp/context"
	"github.com/free5gc/scp/factory"
	"github.com/free5gc/scp/logger"
	"github.com/free5gc/scp/proxy/ausfueauth"
	"github.com/free5gc/scp/proxy/datarepository"
	"github.com/free5gc/scp/proxy/udmueauth"
	"github.com/free5gc/scp/util"
)

type SCP struct{}

type (
	// Config information.
	Config struct {
		scpcfg string
	}
)

var config Config

var scpCLi = []cli.Flag{
	cli.StringFlag{
		Name:  "config, c",
		Usage: "config `file`",
	},
}

var initLog *logrus.Entry

func init() {
	initLog = logger.InitLog
}

func (*SCP) GetCliCmd() (flags []cli.Flag) {
	return scpCLi
}

func (scp *SCP) Initialize(c *cli.Context) error {
	config = Config{
		scpcfg: c.String("config"),
	}
	if config.scpcfg != "" {
		if err := factory.InitConfigFactory(config.scpcfg); err != nil {
			return err
		}
	} else {
		DefaultScpConfigPath := path_util.Free5gcPath("free5gc/config/scpcfg.yaml")
		if err := factory.InitConfigFactory(DefaultScpConfigPath); err != nil {
			return err
		}
	}

	scp.setLogLevel()

	if err := factory.CheckConfigVersion(); err != nil {
		return err
	}

	return nil
}

func (scp *SCP) setLogLevel() {
	if factory.ScpConfig.Logger == nil {
		initLog.Warnln("SCP config without log level setting!!!")
		return
	}

	if factory.ScpConfig.Logger.SCP != nil {
		if factory.ScpConfig.Logger.SCP.DebugLevel != "" {
			if level, err := logrus.ParseLevel(factory.ScpConfig.Logger.SCP.DebugLevel); err != nil {
				initLog.Warnf("SCP Log level [%s] is invalid, set to [info] level",
					factory.ScpConfig.Logger.SCP.DebugLevel)
				logger.SetLogLevel(logrus.InfoLevel)
			} else {
				initLog.Infof("SCP Log level is set to [%s] level", level)
				logger.SetLogLevel(level)
			}
		} else {
			initLog.Infoln("SCP Log level is default set to [info] level")
			logger.SetLogLevel(logrus.InfoLevel)
		}
		logger.SetReportCaller(factory.ScpConfig.Logger.SCP.ReportCaller)
	}

	if factory.ScpConfig.Logger.PathUtil != nil {
		if factory.ScpConfig.Logger.PathUtil.DebugLevel != "" {
			if level, err := logrus.ParseLevel(factory.ScpConfig.Logger.PathUtil.DebugLevel); err != nil {
				pathUtilLogger.PathLog.Warnf("PathUtil Log level [%s] is invalid, set to [info] level",
					factory.ScpConfig.Logger.PathUtil.DebugLevel)
				pathUtilLogger.SetLogLevel(logrus.InfoLevel)
			} else {
				pathUtilLogger.SetLogLevel(level)
			}
		} else {
			pathUtilLogger.PathLog.Warnln("PathUtil Log level not set. Default set to [info] level")
			pathUtilLogger.SetLogLevel(logrus.InfoLevel)
		}
		pathUtilLogger.SetReportCaller(factory.ScpConfig.Logger.PathUtil.ReportCaller)
	}

	/*
	if factory.ScpConfig.Logger.OpenApi != nil {
		if factory.ScpConfig.Logger.OpenApi.DebugLevel != "" {
			if level, err := logrus.ParseLevel(factory.ScpConfig.Logger.OpenApi.DebugLevel); err != nil {
				openApiLogger.OpenApiLog.Warnf("OpenAPI Log level [%s] is invalid, set to [info] level",
					factory.ScpConfig.Logger.OpenApi.DebugLevel)
				openApiLogger.SetLogLevel(logrus.InfoLevel)
			} else {
				openApiLogger.SetLogLevel(level)
			}
		} else {
			openApiLogger.OpenApiLog.Warnln("OpenAPI Log level not set. Default set to [info] level")
			openApiLogger.SetLogLevel(logrus.InfoLevel)
		}
		openApiLogger.SetReportCaller(factory.ScpConfig.Logger.OpenApi.ReportCaller)
	}
	*/
}

func (scp *SCP) FilterCli(c *cli.Context) (args []string) {
	for _, flag := range scp.GetCliCmd() {
		name := flag.GetName()
		value := fmt.Sprint(c.Generic(name))
		if value == "" {
			continue
		}

		args = append(args, "--"+name, value)
	}
	return args
}

func (scp *SCP) Start() {
	initLog.Infoln("Server started")
	router := logger_util.NewGinWithLogrus(logger.GinLog)

	ausfueauth.AddService(router)
	udmueauth.AddService(router)
	datarepository.AddService(router)

	router.Use(cors.New(cors.Config{
		AllowMethods: []string{"GET", "POST", "OPTIONS", "PUT", "PATCH", "DELETE"},
		AllowHeaders: []string{
			"Origin", "Content-Length", "Content-Type", "User-Agent",
			"Referrer", "Host", "Token", "X-Requested-With",
		},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		AllowAllOrigins:  true,
		MaxAge:           86400,
	}))

	self := context.SCP_Self()
	util.InitscpContext(self)

	addr := fmt.Sprintf("%s:%d", self.BindingIPv4, self.SBIPort)

	profile, err := consumer.BuildNFInstance(self)
	if err != nil {
		initLog.Error("Build SCP Profile Error")
	}
	_, self.NfId, err = consumer.SendRegisterNFInstance(self.NrfUri, self.NfId, profile)
	if err != nil {
		initLog.Errorf("SCP register to NRF Error[%s]", err.Error())
	}

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signalChannel
		scp.Terminate()
		os.Exit(0)
	}()

	server, err := http2_util.NewServer(addr, util.SCP_LOG_PATH, router)
	if server == nil {
		initLog.Errorf("Initialize HTTP server failed: %+v", err)
		return
	}

	if err != nil {
		initLog.Warnf("Initialize HTTP server: +%v", err)
	}

	serverScheme := factory.ScpConfig.Configuration.Sbi.Scheme
	if serverScheme == "http" {
		err = server.ListenAndServe()
	} else if serverScheme == "https" {
		err = server.ListenAndServeTLS(util.SCP_PEM_PATH, util.SCP_KEY_PATH)
	}

	if err != nil {
		initLog.Fatalf("HTTP server setup failed: %+v", err)
	}
}

func (scp *SCP) Exec(c *cli.Context) error {
	initLog.Traceln("args:", c.String("scpcfg"))
	args := scp.FilterCli(c)
	initLog.Traceln("filter: ", args)
	command := exec.Command("./scp", args...)

	stdout, err := command.StdoutPipe()
	if err != nil {
		initLog.Fatalln(err)
	}
	wg := sync.WaitGroup{}
	wg.Add(4)
	go func() {
		in := bufio.NewScanner(stdout)
		for in.Scan() {
			fmt.Println(in.Text())
		}
		wg.Done()
	}()

	stderr, err := command.StderrPipe()
	if err != nil {
		initLog.Fatalln(err)
	}
	go func() {
		in := bufio.NewScanner(stderr)
		fmt.Println("SCP log start")
		for in.Scan() {
			fmt.Println(in.Text())
		}
		wg.Done()
	}()

	go func() {
		fmt.Println("SCP start")
		if err = command.Start(); err != nil {
			fmt.Printf("command.Start() error: %v", err)
		}
		fmt.Println("SCP end")
		wg.Done()
	}()

	wg.Wait()

	return err
}

func (scp *SCP) Terminate() {
	logger.InitLog.Infof("Terminating SCP...")
	// deregister with NRF
	problemDetails, err := consumer.SendDeregisterNFInstance()
	if problemDetails != nil {
		logger.InitLog.Errorf("Deregister NF instance Failed Problem[%+v]", problemDetails)
	} else if err != nil {
		logger.InitLog.Errorf("Deregister NF instance Error[%+v]", err)
	} else {
		logger.InitLog.Infof("Deregister from NRF successfully")
	}
	logger.InitLog.Infof("SCP terminated")
}
