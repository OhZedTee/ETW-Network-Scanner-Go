package main

import (
	"flag"
	"io"
	"os"

	hook "github.com/OhZedTee/ETW-Network-Scanner-Go/internal/pkg/logger"
	"github.com/OhZedTee/ETW-Network-Scanner-Go/internal/pkg/parser"
	"github.com/OhZedTee/ETW-Network-Scanner-Go/internal/pkg/session"
	log "github.com/sirupsen/logrus"
)

func main() {

	logLevel := flag.String("loglevel", "info", "Set the log level (debug, info, warn, error, fatal, panic)")
	flag.Parse()

	level, logParseErr := log.ParseLevel(*logLevel)
	if logParseErr != nil {
		log.WithError(logParseErr).Fatalf("Invalid log level: %v", logParseErr)
	}
	log.SetLevel(level)

	// Create session end channel
	sessionEndChan := make(chan bool)

	// Create session object and init
	var sessionObj session.Session
	if err := sessionObj.Init("config/providers.yml"); err != nil {
		log.WithError(err).Fatal("unable to initialize session; shutting down")
	}

	// Create rule set object and init
	var parserObj parser.Parser
	if err := parserObj.Init("config/rules.yml"); err != nil {
		log.WithError(err).Fatal("unable to initialize parser; shutting down")
	}

	hook := setupLogging(sessionObj)
	defer hook.TeardownLogging()

	go func() {
		defer close(sessionEndChan)

		// Start session
		if err := sessionObj.Run(120); err != nil {
			log.WithError(err).Fatal("fatal session error; shutting down")
		}

		sessionEndChan <- true
	}()

	go func() {
		// Start parser
		if err := parserObj.Run(); err != nil {
			log.WithError(err).Fatal("fatal parser error; shutting down")
		}
	}()

	<-sessionEndChan
	log.Warn("Session ended, exitting...")
}

func setupLogging(sessionObj session.Session) *hook.ProviderHook {
	customHook := hook.NewProviderHook()

	for _, provider := range sessionObj.Providers {
		file, err := os.OpenFile("logs/"+provider.LogFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_SYNC, 0666)
		if err == nil {
			customHook.ProviderWriters[provider.Id] = file
			customHook.Files = append(customHook.Files, file)
		} else {
			// error opening file for whatever reason, use stdout for the provider
			log.Info("Failed to log to file, using default stdout")
			customHook.ProviderWriters[provider.Id] = os.Stdout
		}
		// defer file.Close()
	}

	log.AddHook(customHook)
	log.SetOutput(io.Discard)

	return customHook
}
