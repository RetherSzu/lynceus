package casefile

import (
	"path/filepath"
	"time"
)

// LogEntry est une ligne du journal des opérations du cas (case.log).
type LogEntry struct {
	Command     string      `json:"command"`
	Args        []string    `json:"args"`
	StartedAt   time.Time   `json:"started_at"`
	FinishedAt  time.Time   `json:"finished_at"`
	ToolVersion string      `json:"tool_version"`
	ExitCode    int         `json:"exit_code"`
	Summary     interface{} `json:"summary,omitempty"`
}

// Log ajoute une entrée au journal, sans jamais réécrire les précédentes.
func (c *Case) Log(e LogEntry) error {
	e.StartedAt, e.FinishedAt = e.StartedAt.UTC(), e.FinishedAt.UTC()
	return appendLine(filepath.Join(c.BaseDir, "case.log"), e)
}
