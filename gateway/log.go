package gateway

import "log/slog"

func reportError(action string, err error) { slog.Error(action, "error", err) }
