package cmd

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var debug bool

type PlainFormatter struct{}

func (f *PlainFormatter) Format(entry *log.Entry) ([]byte, error) {
	return []byte(fmt.Sprintf("%s\n", entry.Message)), nil
}

func toggleDebug(cmd *cobra.Command, args []string) {
	if debug {
		log.Info("Debug logs enabled")
		log.SetLevel(log.DebugLevel)
		log.SetFormatter(&log.TextFormatter{})
	} else {
		plainFormatter := new(PlainFormatter)
		log.SetFormatter(plainFormatter)
	}
}

func init() {
	// Set a custom formatter for logrus
	log.SetFormatter(&log.TextFormatter{
		DisableColors:    false, // Enable colors
		ForceColors:      true,  // Force colors even if not writing to a terminal
		TimestampFormat:  "2006-01-02 15:04:05",
		FullTimestamp:    true,
		QuoteEmptyFields: true,
	})

	// Set custom colors for log levels
	log.AddHook(&levelColorsHook{})
}

type levelColorsHook struct{}

func (hook *levelColorsHook) Levels() []log.Level {
	return []log.Level{log.WarnLevel, log.ErrorLevel, log.FatalLevel, log.PanicLevel}
}

func (hook *levelColorsHook) Fire(entry *log.Entry) error {
	switch entry.Level {
	case log.WarnLevel:
		entry.Message = fmt.Sprintf("\x1b[33m%s\x1b[0m", entry.Message) // Yellow for warnings
	case log.ErrorLevel, log.FatalLevel, log.PanicLevel:
		entry.Message = fmt.Sprintf("\x1b[31m%s\x1b[0m", entry.Message) // Red for errors, fatal, and panic
	}
	return nil
}
