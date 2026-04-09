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
	if err := s.db.Raw(ctx, `
		SELECT
			(SELECT COUNT(*) FROM repos) AS total_accounts,
			(SELECT COUNT(*) FROM repos WHERE deactivated = 0) AS active_accounts,
			(SELECT COUNT(*) FROM records) AS total_records,
			(SELECT COUNT(*) FROM blobs) AS total_blobs,
			(SELECT COUNT(*) FROM invite_codes WHERE disabled = 0 AND remaining_use_count > 0) AS total_invite_codes
	`, nil).Scan(&stats).Error; err != nil {
		s.logger.Error("error fetching home stats", "error", err)
	}

	if err := s.renderTemplate(w, "home.html", homeData{
		Hostname:      s.config.Hostname,
		Did:           s.config.Did,
		ContactEmail:  s.config.ContactEmail,
		Version:       s.config.Version,
		RequireInvite: s.config.RequireInvite,
		Stats:         stats,
	}); err != nil {
		s.logger.Error("failed to render template", "error", err)
	}
}
