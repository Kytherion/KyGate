package pipeline

// Stage 8, Route, in shadow mode (OP-4): the router decides what
// cheaper model it would use, the request still goes to the model it names,
// and the event records the decision and, after the answer, what it would
// have saved (architecture §3.5).

import (
	"fmt"

	"github.com/Kytherion/KyGate/internal/ingress"
	"github.com/Kytherion/KyGate/internal/router"
)

// routeShadow runs the router in shadow mode and records its decision.
func (g *Gateway) routeShadow(sc *serveCtx, target router.Target, conversation string) {
	if g.Router == nil || sc.downgraded || !sc.pol.RoutingShadow() || (sc.req.Endpoint != ingress.Chat && sc.req.Endpoint != ingress.Messages) {
		return
	}
	d := g.Router.Decide(router.FeaturesOf(sc.req, target.Hosting == "local", sc.pol.Route.Tiers), conversation)
	sc.route = d
	ev := sc.ev
	ev.RouteReason = d.Reason
	if d.Moves() {
		ev.RouteModel = d.Model
		sc.w.Header().Set("X-KyGate-Route", fmt.Sprintf("shadow; would use %s (%s tier)", d.Model, d.Tier))
	} else {
		sc.w.Header().Set("X-KyGate-Route", "shadow; stays")
	}
}

// routeSaving prices the real usage at the model the router would have used.
func (g *Gateway) routeSaving(sc *serveCtx, cost float64, hosting string, usage router.Usage) {
	if !sc.route.Moves() || cost <= 0 {
		return
	}
	would, priced := g.Catalog.Cost(sc.route.Model, hosting, usage)
	if priced && would < cost {
		sc.ev.RouteSavingUSD = cost - would
	}
}
