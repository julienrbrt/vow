package server

import "net/http"

type ComAtprotoServerDescribeServerResponseLinks struct {
	PrivacyPolicy  *string `json:"privacyPolicy,omitempty"`
	TermsOfService *string `json:"termsOfService,omitempty"`
}

type ComAtprotoServerDescribeServerResponseContact struct {
	Email string `json:"email"`
}

type ComAtprotoServerDescribeServerResponse struct {
	InviteCodeRequired        bool                                          `json:"inviteCodeRequired"`
	PhoneVerificationRequired bool                                          `json:"phoneVerificationRequired"`
	AvailableUserDomains      []string                                      `json:"availableUserDomains"`
	Links                     ComAtprotoServerDescribeServerResponseLinks   `json:"links"`
	Contact                   ComAtprotoServerDescribeServerResponseContact `json:"contact"`
	Did                       string                                        `json:"did"`
}

func (s *Server) handleDescribeServer(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, 200, ComAtprotoServerDescribeServerResponse{
		InviteCodeRequired:        s.config.RequireInvite,
		PhoneVerificationRequired: false,
		AvailableUserDomains:      []string{"." + s.config.Hostname}, // TODO: more
		Links: ComAtprotoServerDescribeServerResponseLinks{
			PrivacyPolicy:  nil,
			TermsOfService: nil,
		},
		Contact: ComAtprotoServerDescribeServerResponseContact{
			Email: s.config.ContactEmail,
		},
		Did: s.config.Did,
	})
}
