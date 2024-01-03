package hook

import (
	"io"
	"os"
	"sync"

	log "github.com/sirupsen/logrus"
)

type ProviderHook struct {
	ProviderWriters map[string]io.Writer
	StdOutWriter    io.Writer
	Files           []*os.File // keeping track of open files
	mu              sync.Mutex
}

func NewProviderHook() *ProviderHook {
	return &ProviderHook{
		ProviderWriters: make(map[string]io.Writer),
		StdOutWriter:    os.Stdout,
	}
}

func (h *ProviderHook) Levels() []log.Level {
	return log.AllLevels
}

func (h *ProviderHook) Fire(entry *log.Entry) error {
	// Lock the hook to ensure multiple goroutines don't try to log messages at the same time to the same file
	h.mu.Lock()
	defer h.mu.Unlock()

	// Assuming provider entry is added as a field in the log entry
	// If any log is not info, write to StdOut, otherwise check if its a specific provider
	var target io.Writer
	if entry.Level != log.InfoLevel {
		target = h.StdOutWriter
	} else {
		provider, ok := entry.Data["provider"].(string)
		if !ok {
			//abscence of a provider, write to stdout too
			target = h.StdOutWriter
		} else {
			target, ok = h.ProviderWriters[provider]
			if !ok {
				// Provider writer not found, write to StdOut
				target = h.StdOutWriter
			}
		}
	}

	line, err := entry.String()
	if err != nil {
		return err
	}

	_, err = target.Write([]byte(line))
	return err
}

func (h *ProviderHook) TeardownLogging() {
	for _, file := range h.Files {
		err := file.Close()
		if err != nil {
			log.Errorf("failed to close file: %v", err)
		}
	}
}
