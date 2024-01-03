package alert

import (
	"fmt"
	"os/exec"

	log "github.com/sirupsen/logrus"
)

// Shows the alert to the host
// Future work: Send alert to domain administrator
func ShowAlert(message string) error {
	log.Warn(message)

	return exec.Command("powershell", "-Command", fmt.Sprintf("New-BurntToastNotification -Text '%s'", message)).Run()
}
