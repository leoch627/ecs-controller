package notify

import (
	"strings"
	"time"
)

// Brand prefixes every notification heading and email subject.
const Brand = "ECS 控制台"

const timeLayout = "2006-01-02 15:04:05"

// Line is one "label: value" row of a notification body.
type Line struct {
	Label string
	Value string
}

// L builds a Line.
func L(label, value string) Line { return Line{Label: label, Value: value} }

// Heading is the first line of every notification and the email subject.
func Heading(title string) string { return "【" + Brand + "】" + title }

// InstanceLines are the rows that open every notification about one instance,
// always in the same order. The ID row is dropped when the instance has no
// name of its own and is already shown by its ID.
func InstanceLines(name, instanceID, region string) []Line {
	lines := []Line{L("实例", name)}
	if strings.TrimSpace(instanceID) != strings.TrimSpace(name) {
		lines = append(lines, L("实例 ID", instanceID))
	}
	return append(lines, L("区域", region))
}

// Text renders the event in the one format every channel uses:
//
//	【ECS 控制台】<title>
//	<label>: <value>   (rows with an empty value are skipped)
//	时间: <time>
//
//	<body>              (only when set)
func (e Event) Text() string {
	var b strings.Builder
	b.WriteString(Heading(e.Title))
	for _, line := range e.Lines {
		value := strings.TrimSpace(line.Value)
		if value == "" {
			continue
		}
		b.WriteString("\n" + line.Label + ": " + value)
	}
	b.WriteString("\n时间: " + e.at().Format(timeLayout))
	if body := strings.TrimSpace(e.Body); body != "" {
		b.WriteString("\n\n" + body)
	}
	return b.String()
}

func (e Event) at() time.Time {
	if e.Time.IsZero() {
		return time.Now()
	}
	return e.Time
}
