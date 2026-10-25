package web

import "time"

func timeText(unix int64) string {
	return time.Unix(unix, 0).UTC().Format("2006-01-02 15:04 UTC")
}

// TimeText writes a Unix time for the pages.
func TimeText(unix int64) string { return timeText(unix) }
