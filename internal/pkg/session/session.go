package session

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/0xrawsec/golang-etw/etw"
	"github.com/OhZedTee/ETW-Network-Scanner-Go/internal/pkg/config"
	log "github.com/sirupsen/logrus"
)

type Session struct {
	Providers []Provider
	Session   *etw.RealTimeSession
	Consumer  *etw.Consumer
}

func (s *Session) Init(providerConfigFilePath string) error {
	// Load providers from config
	providersConfig, providerParseErr := config.NewProvidersFromYaml(providerConfigFilePath)
	if providerParseErr != nil {
		return fmt.Errorf("unable to parse provider config, cannot continue")
	}

	//Populating the Session struct with the providers, events, and fields specified in the config file
	for _, provider := range providersConfig.Providers {
		s.Providers = append(s.Providers, Provider{
			Id:              provider.Name,
			TrackableEvents: config.SliceToBoolMap(provider.Events),
			TrackableFields: config.SliceToStringMap(provider.Fields),
			LogFile:         provider.LogFile,
		})
	}

	return nil
}

// Starts ETW session and consumer
func (s *Session) Run(captureTime time.Duration) error {
	s.Session = etw.NewRealTimeSession("ETW-Go")
	defer s.Session.Stop()

	minSingleProviderSuccess := false

	//Enabling the providers inside the Provider Struct
	for _, provider := range s.Providers {
		if resolveProviderErr := s.Session.EnableProvider(etw.ResolveProvider(provider.Id)); resolveProviderErr != nil {
			log.WithError(resolveProviderErr).Errorf("Cannot resolve provider... continuing")
			continue
		}
		minSingleProviderSuccess = true
	}

	if !minSingleProviderSuccess {
		return fmt.Errorf("unable to resolve a single provider, cannot continue")
	}

	s.Consumer = etw.NewRealTimeConsumer(context.Background())
	defer s.Consumer.Stop()

	s.Consumer.FromSessions(s.Session)

	go func() {
		for event := range s.Consumer.Events {
			// Only log events from valid map
			idx := -1
			for k, v := range s.Providers {
				if v.Id == event.System.Provider.Guid || v.Id == event.System.Provider.Name {
					idx = k
				}
			}

			if idx == -1 {
				//provider not found?? This statement should never happen, if it does, something seriously wrong has happened that deems investigation
				log.Warnf("Event from unknown provider. Name: %s GUID: %s", event.System.Provider.Name, event.System.Provider.Guid)
				continue
			}

			lookupEventTypes := s.Providers[idx].TrackableEvents

			// Deep copy of Trackable fields as we are modifying fields
			lookupFields := make(map[string]interface{})
			AddProviderToLog(lookupFields, s.Providers[idx])
			for k, v := range s.Providers[idx].TrackableFields {
				lookupFields[k] = v
			}

			if lookupEventTypes[event.System.EventID] {

				if _, ok := s.Providers[idx].TrackableFields["*"]; ok {
					// If * is present, capture all fields
					ExtractLogFields(reflect.ValueOf(event), lookupFields, true)

				} else {
					//We only want to log specific fields defined in provider fields #lookupFields
					ExtractLogFields(reflect.ValueOf(event), lookupFields, false)
				}

				ExtractIPFields(lookupFields)
				log.WithFields(lookupFields).Infof("Event ID: %d", event.System.EventID)
			}
		}
	}()

	if startConsumerErr := s.Consumer.Start(); startConsumerErr != nil {
		return fmt.Errorf("unable to start consumer, cannot continue: %w", startConsumerErr)
	}

	time.Sleep(captureTime * time.Second)

	if s.Consumer.Err() != nil {
		log.WithError(s.Consumer.Err()).Warn("the consumer ran into an error while capturing from session")
	}

	return nil
}
