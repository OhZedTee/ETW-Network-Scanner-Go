package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Rule struct {
	Enabled        bool     `yaml:"enabled"`
	AlertThreshold int      `yaml:"alert_threshold"`
	FileNames      []string `yaml:"files"`
}

type RuleSet struct {
	Rules map[string]Rule `yaml:"rules"`
}

func NewRuleSetFromFile(filePath string) (*RuleSet, error) {
	file, readFileErr := os.ReadFile(filePath)
	if readFileErr != nil {
		return nil, fmt.Errorf("error reading YAML file '%s': %w", filePath, readFileErr)
	}

	rules := &RuleSet{}
	unMarshallErr := yaml.Unmarshal(file, rules)
	if unMarshallErr != nil {
		return nil, fmt.Errorf("error unmarshalling YAML data: %w", unMarshallErr)
	}
	return rules, nil
}
