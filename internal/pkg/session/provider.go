package session

import (
	"net"
	"reflect"

	log "github.com/sirupsen/logrus"
)

type Provider struct {
	Id              string
	TrackableEvents map[uint16]bool
	TrackableFields log.Fields
	LogFile         string
}

func (p *Provider) Set(id string, eventIds []uint16, fields map[string]interface{}) {
	p.Id = id

	// Initialize the map if it's not already done
	if p.TrackableEvents == nil {
		p.TrackableEvents = make(map[uint16]bool)
	}

	for _, eventId := range eventIds {
		p.addTrackableEvents(eventId)
	}

	p.TrackableFields = fields
}

func (p *Provider) addTrackableEvents(eventId uint16) {
	p.TrackableEvents[eventId] = true
}

func ExtractLogFields(value reflect.Value, lookupFields log.Fields, logEverything bool) {
	value = reflect.Indirect(value)

	// Ensure the value is valid and not nil
	if !value.IsValid() {
		return
	}

	if log.GetLevel() == log.DebugLevel {
		// fmt.Printf("Type of value: %s\n", value.Type().String())
		log.Debugf("Type of value: %s\n", value.Type().String())
	}

	// Handle nested structs and maps
	switch value.Kind() {
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			fieldValue := value.Field(i)

			//Only proceed if the field is exported and can be interfaced
			if fieldValue.CanInterface() {
				field := value.Type().Field(i)
				ExtractLogFields(fieldValue, lookupFields, logEverything)

				if !logEverything {
					if _, found := lookupFields[field.Name]; found {
						lookupFields[field.Name] = fieldValue.Interface()
					}
				} else { //log everything
					lookupFields[field.Name] = fieldValue.Interface()
				}
			}
		}
	case reflect.Map:
		for _, key := range value.MapKeys() {
			strKey, ok := key.Interface().(string)
			if !ok {
				continue
			}

			if !logEverything {
				if _, found := lookupFields[strKey]; found {
					lookupFields[strKey] = value.MapIndex(key).Interface()
				}
			} else { //log everything
				lookupFields[strKey] = value.MapIndex(key).Interface()
			}
		}
	default:
		// This is an unsupported primitive, since we dont have field name information here,
		// handling of primitives is done at the struct field level in the 'case reflect.Struct'
		// given first call to function uses etw.Event struct

	}
}

func ExtractIPFields(lookupFields log.Fields) {
	// Future work: This function does not work for nested structs, for that, more work would need
	// to be done reflect on the struct in a similar function to ExtractLogFields
	for key, v := range lookupFields {
		// Check if v is a string before type assertion
		strValue, ok := v.(string)
		if !ok {
			// v is not a string, so skip it
			continue
		}

		host, port, splitHostPortErr := net.SplitHostPort(strValue)
		if splitHostPortErr != nil {
			continue //Not a valid IP:port format
		}

		ip := net.ParseIP(host)
		if ip == nil {
			continue // Not a valid IP address
		}

		// Update the map
		lookupFields[key+"_IP"] = host
		lookupFields[key+"_PORT"] = port
		delete(lookupFields, key) // remove the original field entry
	}
}

func AddProviderToLog(l log.Fields, p Provider) {
	l["provider"] = p.Id
}
