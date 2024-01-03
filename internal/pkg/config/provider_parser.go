package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Provider struct {
	Name    string   `yaml:"name"`
	Events  []uint16 `yaml:"events"`
	Fields  []string `yaml:"fields"`
	LogFile string   `yaml:"logFile"`
}

type Providers struct {
	Providers map[string]Provider `yaml:"providers"`
}

func NewProvidersFromYaml(filePath string) (*Providers, error) {
	file, readFileErr := os.ReadFile(filePath)
	if readFileErr != nil {
		return nil, fmt.Errorf("error reading YAML file '%s': %w", filePath, readFileErr)
	}

	providers := &Providers{}
	unMarshallErr := yaml.Unmarshal(file, providers)
	if unMarshallErr != nil {
		return nil, fmt.Errorf("error unmarshalling YAML data: %w", unMarshallErr)
	}
	return providers, nil
}

func SliceToBoolMap(slice []uint16) map[uint16]bool {
	resultMap := make(map[uint16]bool)
	for _, v := range slice {
		resultMap[v] = true
	}
	return resultMap
}

func SliceToStringMap(slice []string) map[string]interface{} {
	resultMap := make(map[string]interface{})
	for _, v := range slice {
		resultMap[v] = "NA"
	}

	return resultMap
}
