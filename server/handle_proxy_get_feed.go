package server

import (
	"context"
	"net/http"

	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/api/bsky"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/bluesky-social/indigo/xrpc"
	"pkg.rbrt.fr/vow/internal/helpers"
)

func (s *Server) handleProxyBskyFeedGetFeed(w http.ResponseWriter, r *http.Request) {
	feedUri, err := syntax.ParseATURI(r.URL.Query().Get("feed"))
	if err != nil {
		helpers.InputError(w, new("invalid feed uri"))
		return
	}

	appViewEndpoint, _, err := s.getAtprotoProxyEndpointFromRequest(r)
	if err != nil {
		s.logger.Error("could not get atproto proxy", "error", err)
		helpers.ServerError(w, nil)
		return
	}

	appViewClient := xrpc.Client{
		Host: appViewEndpoint,
	}
	feedRecord, err := atproto.RepoGetRecord(r.Context(), &appViewClient, "", feedUri.Collection().String(), feedUri.Authority().String(), feedUri.RecordKey().String())
	if err != nil {
		s.logger.Error("could not get feed record", "error", err)
		helpers.ServerError(w, nil)
		return
	}
	feedGeneratorDid := feedRecord.Value.Val.(*bsky.FeedGenerator).Did

	// Inject proxy token overrides into the request context so handleProxy can read them.
	ctx := context.WithValue(r.Context(), contextKeyProxyTokenLxm, "app.bsky.feed.getFeedSkeleton")
	ctx = context.WithValue(ctx, contextKeyProxyTokenAud, feedGeneratorDid)

	s.handleProxy(w, r.WithContext(ctx))
}
