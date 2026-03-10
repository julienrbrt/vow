package server

import (
	"fmt"
	"net/http"
)

type homeStats struct {
	TotalAccounts    int64
	ActiveAccounts   int64
	TotalRecords     int64
	TotalBlobs       int64
	TotalInviteCodes int64
}

type homeData struct {
	Hostname      string
	Did           string
	ContactEmail  string
	Version       string
	RequireInvite bool
	Stats         homeStats
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("raw") == "1" {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprint(w, `

 ___      ___  ________  ___       __
|\  \    /  /||\   __  \|\  \     |\  \
\ \  \  /  / /\ \  \|\  \ \  \    \ \  \
 \ \  \/  / /  \ \  \\\  \ \  \  __\ \  \
  \ \    / /    \ \  \\\  \ \  \|\__\_\  \
   \ \__/ /      \ \_______\ \____________\
    \|__|/        \|_______|\|____________|


This is an AT Protocol Personal Data Server (aka, an atproto PDS)

Code: https://pkg.rbrt.fr/vow
Version: `+s.config.Version+"\n")
		return
	}

	ctx := r.Context()

	var stats homeStats

	var totalAccounts int64
	s.db.Raw(ctx, "SELECT COUNT(*) FROM repos", nil).Scan(&totalAccounts)
	stats.TotalAccounts = totalAccounts

	var activeAccounts int64
	s.db.Raw(ctx, "SELECT COUNT(*) FROM repos WHERE deactivated = 0", nil).Scan(&activeAccounts)
	stats.ActiveAccounts = activeAccounts

	var totalRecords int64
	s.db.Raw(ctx, "SELECT COUNT(*) FROM records", nil).Scan(&totalRecords)
	stats.TotalRecords = totalRecords

	var totalBlobs int64
	s.db.Raw(ctx, "SELECT COUNT(*) FROM blobs", nil).Scan(&totalBlobs)
	stats.TotalBlobs = totalBlobs

	var totalInviteCodes int64
	s.db.Raw(ctx, "SELECT COUNT(*) FROM invite_codes WHERE disabled = 0 AND remaining_use_count > 0", nil).Scan(&totalInviteCodes)
	stats.TotalInviteCodes = totalInviteCodes

	_ = s.renderTemplate(w, "home.html", homeData{
		Hostname:      s.config.Hostname,
		Did:           s.config.Did,
		ContactEmail:  s.config.ContactEmail,
		Version:       s.config.Version,
		RequireInvite: s.config.RequireInvite,
		Stats:         stats,
	})
}
