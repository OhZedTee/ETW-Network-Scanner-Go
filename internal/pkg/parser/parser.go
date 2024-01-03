package parser

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	alert "github.com/OhZedTee/ETW-Network-Scanner-Go/internal/pkg/alerting"
	"github.com/OhZedTee/ETW-Network-Scanner-Go/internal/pkg/config"
	log "github.com/sirupsen/logrus"
)

type Parser struct {
	RuleConfig *config.RuleSet
}

type LogEntry struct {
	Time    time.Time
	EventID int
	Fields  map[string]interface{}
}

type LogEntries struct {
	Entries []LogEntry
}

func (p *Parser) Init(ruleSetConfigFilePath string) error {
	// Load rules from config
	rulesConfig, rulesParseErr := config.NewRuleSetFromFile(ruleSetConfigFilePath)
	if rulesParseErr != nil {
		return fmt.Errorf("unable to parse rules config, cannot continue")
	}

	//Populating the Parser struct with the rules
	p.RuleConfig = rulesConfig
	return nil
}

func (p *Parser) Run() error {
	// Run rules every 30 sec, no reason to run on first pass, session doesn't have enough data captured yet
	ruleRunningTicker := time.NewTicker(30 * time.Second)

	//Infinite program loop (session package will still cause program to end, but we want rules to run throughout running program)
	for {
		select {
		case <-ruleRunningTicker.C:
			if err := p.RunRules(); err != nil {
				log.WithError(err).Errorf("problem running rules")
			}
		}
	}
}

func (p *Parser) RunRules() error {
	for name, rule := range p.RuleConfig.Rules {
		if rule.Enabled {
			hits := 0
			alertMessage := ""
			switch name {
			case "scan_detection":
				// var zeroTime time.Time                                             // Default time struct is zero time
				startTime := time.Now().Add(-1 * time.Minute)
				endTime := time.Now()
				logEntries := processRuleFiles(rule.FileNames, startTime, endTime) //providing zeroTime will process all logs

				var adversary string
				hits, adversary = rule_ScanDetection(logEntries)
				alertMessage = fmt.Sprintf("Host is currently being scanned by %s", adversary)
			case "rdp_brute_force":
				startTime := time.Now().Add(-1 * time.Minute) // 1 minute ago
				endTime := time.Now()

				logEntries := processRuleFiles(rule.FileNames, startTime, endTime)

				var adversary string
				hits, adversary = rule_RDPBruteForce(logEntries)
				alertMessage = fmt.Sprintf("Host is currently being RDP Brute Forced by %s", adversary)
			case "rdp_session_hijack":
				startTime := time.Now().Add(-30 * time.Minute) // 30 minutes ago
				endTime := time.Now()

				var adversary string
				logEntries := processRuleFiles(rule.FileNames, startTime, endTime)
				hits, adversary = rule_RDPSessionHijack(logEntries)
				alertMessage = fmt.Sprintf("Host is currently being RDP Session Hijacked by %s", adversary)
			default:
				log.Warnf("Rule: %s does not have a matching detection algorithm, skipping...", name)
			}

			if hits >= rule.AlertThreshold {
				alertingErr := alert.ShowAlert(alertMessage)
				if alertingErr != nil {
					log.WithError(alertingErr).Warn("unable to alert")
				}
			}
		}
	}
	return nil
}

func rule_ScanDetection(le LogEntries) (int, string) {
	// create a map of remoteIP, for each map, number of unique ports
	// instead a map[remoteIP][]string key.count()
	// ignore time, return max key.count() <-- alertThreshold.
	var uniquePort = make(map[string][]string)

	for _, entry := range le.Entries {
		port, portOk := entry.Fields["LocalSockAddr_PORT"].(string)
		ip, ipOk := entry.Fields["RemoteSockAddr_IP"].(string)

		if portOk && ipOk {
			// check if the port is not already in the slice for this IP
			if !contains(uniquePort[ip], port) {
				uniquePort[ip] = append(uniquePort[ip], port)
			}
		}
	}

	max := 0
	sourceMaxIp := ""
	for ip, ports := range uniquePort {
		if len(ports) > max {
			max = len(ports)
			sourceMaxIp = ip
		}
	}

	return max, sourceMaxIp
}

type RDPInfo struct {
	ActivityId []string
	Count      int
}

func rule_RDPBruteForce(le LogEntries) (int, string) {
	// when someone tries to connect, we just need 2 events, 131, 103
	// create a map map[IP]struct{ []activityID, count} (number of connections attempted)
	// number of connections is calculated by:
	// 131 -> add IP to the map with activityID, count = 0, if the IP is already in the map,
	// 103 -> 103 event, with the same activity ID and reason code 14

	var terminatedRDP = make(map[string]RDPInfo)
	for _, entry := range le.Entries {
		if entry.EventID == 131 {
			// Check if the IP is already in the map
			ip, ipOk := entry.Fields["ClientIP_IP"].(string)
			activityId, aIdOk := entry.Fields["ActivityID"].(string)

			if !aIdOk {
				continue
			}

			// If IP already in the map, just append the new activityID, if not, create a new entry
			if ipOk {
				rdpInfo, exists := terminatedRDP[ip]

				if !exists {
					rdpInfo = RDPInfo{}
					rdpInfo.ActivityId = append(rdpInfo.ActivityId, activityId)
					rdpInfo.Count = 0
				} else {
					rdpInfo.ActivityId = append(rdpInfo.ActivityId, activityId)
				}

				terminatedRDP[ip] = rdpInfo
			}
		} else if entry.EventID == 103 {
			// Check if reason code is 14.
			reasonCode, reasonCodeOk := entry.Fields["ReasonCode"].(string)
			activityId, aIdOk := entry.Fields["ActivityID"].(string)

			// No reason code or activity id, we cannot update count safely
			if !reasonCodeOk || !aIdOk {
				continue
			}

			if reasonCode == "14" {
				// Check if the activityId exists for a map
				for ip, info := range terminatedRDP {
					if contains(info.ActivityId, activityId) {
						// Update the entry directly in the terminatedRDP map
						updatedInfo := info
						updatedInfo.Count++
						terminatedRDP[ip] = updatedInfo

					}
				}
			}

		}
	}

	max := 0
	sourceMaxIp := ""
	for ip, rdpInfo := range terminatedRDP {
		if rdpInfo.Count > max {
			max = rdpInfo.Count
			sourceMaxIp = ip
		}
	}

	return max, sourceMaxIp
}

// Future work, add RDP Session Hijack rule
func rule_RDPSessionHijack(le LogEntries) (int, string) { return 0, "" }

func (le *LogEntries) Insert(entry LogEntry) { le.Entries = append(le.Entries, entry) }

func (le *LogEntries) Sort() {
	// SliceStable will keep equal elements in their original order
	sort.SliceStable(le.Entries, func(i, j int) bool {
		return le.Entries[i].Time.Before(le.Entries[j].Time)
	})
}

func (le *LogEntries) processLogLine(line string) (LogEntry, error) {
	re := regexp.MustCompile(`(\w+)="(.*?)"|\w+=\S+`)
	matches := re.FindAllStringSubmatch(line, -1)

	entry := LogEntry{
		Fields: make(map[string]interface{}),
	}

	for _, match := range matches {
		key := match[1]
		value := match[2]

		if key == "" && len(match) > 0 {
			// Handle non-quoted key-value pairs
			pair := strings.SplitN(match[0], "=", 2)
			if len(pair) == 2 {
				key, value = pair[0], pair[1]
			}
		}

		switch key {
		case "time":
			// Assuming time follows RFC3339 format
			parsedTime, parseTimeErr := time.Parse(time.RFC3339, value)
			if parseTimeErr != nil {
				return LogEntry{}, fmt.Errorf("could not parse time, skipping log line: %w", parseTimeErr)
			}
			entry.Time = parsedTime
		case "msg":
			// Assuming msg contains "Event ID: <id>"
			parts := strings.SplitN(value, " ", 3)
			if len(parts) == 3 {
				id, convertToIntErr := strconv.Atoi(parts[2])
				if convertToIntErr != nil {
					return LogEntry{}, fmt.Errorf("could not parse event id, skipping log line: %w", convertToIntErr)
				}
				entry.EventID = id
			}
		default:
			// Assuming fields that are not applicable have a value of NA
			if value != "NA" {
				//Add other fields to the map
				entry.Fields[key] = value
			}

		}
	}

	return entry, nil

}

func (le *LogEntries) processLogFile(fileName string, startTime, endTime time.Time) error {
	file, openFileErr := os.Open("logs/" + fileName)
	if openFileErr != nil {
		return openFileErr
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		entry, processLineErr := le.processLogLine(line)
		if processLineErr != nil {
			log.WithError(processLineErr).Warnf("could not process line: (%s) from logfile: %s", line, fileName)
			continue
		}

		// Check if the entry is within the specified time interval (between or equal)
		if (startTime.IsZero() && endTime.IsZero()) ||
			((entry.Time.After(startTime) || entry.Time.Equal(startTime)) &&
				(entry.Time.Before(endTime) || entry.Time.Equal(endTime))) {
			le.Insert(entry)
		}
	}

	// Sort log entries and return any error collected by the scanner
	le.Sort()
	return scanner.Err()
}

func processRuleFiles(fileNames []string, startTime, endTime time.Time) LogEntries {
	var logEntries LogEntries
	for _, fileName := range fileNames {
		processLogFileErr := logEntries.processLogFile(fileName, startTime, endTime)
		if processLogFileErr != nil {
			log.WithError(processLogFileErr).Warnf("error processing file: %s", fileName)
		}
	}

	return logEntries
}

func contains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}

	return false
}
