package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/division-sh/swarm/internal/events"
	"github.com/division-sh/swarm/internal/providertriggers"
	runtimebus "github.com/division-sh/swarm/internal/runtime/bus"
	runtimecorrelation "github.com/division-sh/swarm/internal/runtime/correlation"
	runtimecredentials "github.com/division-sh/swarm/internal/runtime/credentials"
	runtimeinbound "github.com/division-sh/swarm/internal/runtime/inboundpublication"
	runtimeingress "github.com/division-sh/swarm/internal/runtime/ingress"
	"github.com/division-sh/swarm/internal/runtime/semanticview"
)

const inboundWebhookMaxBodyBytes = 1 << 20

type InboundPersistence = runtimeinbound.Runner

type InboundTarget struct {
	BundleHash          string
	ServiceID           string
	PackageKey          string
	FlowID              string
	RunID               string
	Generation          int64
	PublicationSequence int64
	InstanceID          string
	FlowInstance        string
	EntityID            string
	EntitySlug          string
	Alias               string
	Provider            string
	SigningSecret       string
	AdmissionPlan       providertriggers.InboundAdmissionPlan
}

func (t InboundTarget) EffectiveEntityID() string {
	return firstNonEmpty(t.EntityID)
}

func (t InboundTarget) EffectiveEntitySlug() string {
	return firstNonEmpty(t.EntitySlug)
}

func (t *InboundTarget) NormalizeEntity() {
	if t == nil {
		return
	}
	entityID := t.EffectiveEntityID()
	entitySlug := t.EffectiveEntitySlug()
	t.EntityID = entityID
	t.EntitySlug = entitySlug
}

type InboundGateway struct {
	bus                     *runtimebus.EventBus
	store                   InboundPersistence
	logger                  *RuntimeLogger
	shutdownAdmissionClosed func() bool
	beginAdmission          func(context.Context) (context.Context, func(), bool)
	runtimeIngress          *runtimeingress.Controller
	credentials             runtimecredentials.Store
}

func (g *InboundGateway) SetAdmissionGuard(begin func(context.Context) (context.Context, func(), bool)) {
	if g != nil {
		g.beginAdmission = begin
	}
}

func NewInboundGateway(bus *runtimebus.EventBus, logger *RuntimeLogger, shutdownAdmissionClosed func() bool, stores ...InboundPersistence) *InboundGateway {
	var store InboundPersistence
	if len(stores) > 0 {
		store = stores[0]
	}
	g := &InboundGateway{
		bus:                     bus,
		store:                   store,
		logger:                  logger,
		shutdownAdmissionClosed: shutdownAdmissionClosed,
	}
	return g
}

func (g *InboundGateway) SetCredentialStore(store runtimecredentials.Store) {
	if g != nil {
		g.credentials = store
	}
}

func (g *InboundGateway) SetRuntimeIngress(controller *runtimeingress.Controller) {
	if g == nil {
		return
	}
	g.runtimeIngress = controller
}

func (g *InboundGateway) HandleResolvedWebhook(w http.ResponseWriter, r *http.Request, target InboundTarget, source semanticview.Source) {
	if g == nil {
		http.Error(w, "runtime ingress unavailable", http.StatusServiceUnavailable)
		return
	}
	g.handleResolvedWebhook(w, r, target, source)
}

func (g *InboundGateway) handleResolvedWebhook(w http.ResponseWriter, r *http.Request, target InboundTarget, source semanticview.Source) {
	if g.beginAdmission != nil {
		admissionCtx, release, admitted := g.beginAdmission(r.Context())
		if !admitted {
			http.Error(w, "runtime shutting down", http.StatusServiceUnavailable)
			return
		}
		defer release()
		r = r.WithContext(admissionCtx)
	} else if g.shutdownAdmissionClosed != nil && g.shutdownAdmissionClosed() {
		http.Error(w, "runtime shutting down", http.StatusServiceUnavailable)
		return
	}
	if g.runtimeIngress != nil {
		if err := g.runtimeIngress.AdmitQueueableIngress(r.Context(), "inbound.webhook"); err != nil {
			http.Error(w, "runtime ingress unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	provider := providertriggers.NormalizeProviderName(target.Provider)
	if provider == "" {
		_, provider, _ = parseWebhookPath(r.URL.Path)
	}
	if provider == "" {
		http.Error(w, "provider is required", http.StatusBadRequest)
		return
	}
	if !target.AdmissionPlan.Valid() {
		http.Error(w, fmt.Sprintf("ingress target %q provider %q has no compiled admission plan; request rejected before provider admission", target.Alias, provider), http.StatusServiceUnavailable)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, inboundWebhookMaxBodyBytes+1))
	if err != nil {
		http.Error(w, "read body failed", http.StatusBadRequest)
		return
	}
	if len(body) > inboundWebhookMaxBodyBytes {
		http.Error(w, "webhook body too large", http.StatusRequestEntityTooLarge)
		return
	}
	requestURL := inboundRequestURL(r)
	queryValues, queryParseError := inboundQueryValues(r)
	formValues, formParsed, formParseError := inboundFormValues(r.Header.Get("Content-Type"), body)

	signingValue := ""
	if target.AdmissionPlan.RequiresSecret() {
		if target.SigningSecret == "" {
			http.Error(w, fmt.Sprintf("ingress alias %q provider %q requires a signing secret for %s request authentication", target.Alias, provider, target.AdmissionPlan.RequestAuthentication()), http.StatusServiceUnavailable)
			return
		}
		if g.credentials == nil {
			http.Error(w, fmt.Sprintf("signing secret %s is UNBOUND; run `swarm secrets set %s`", target.SigningSecret, target.SigningSecret), http.StatusServiceUnavailable)
			return
		}
		resolved, ok, err := g.credentials.Get(r.Context(), target.SigningSecret)
		if err != nil {
			http.Error(w, "read signing secret failed", http.StatusServiceUnavailable)
			return
		}
		if !ok || strings.TrimSpace(resolved) == "" {
			http.Error(w, fmt.Sprintf("signing secret %s is UNBOUND; run `swarm secrets set %s`", target.SigningSecret, target.SigningSecret), http.StatusServiceUnavailable)
			return
		}
		signingValue = resolved
	}
	target.NormalizeEntity()
	var payload any
	if err := json.Unmarshal(body, &payload); err != nil {
		payload = map[string]any{"raw": string(body)}
	}
	entityID := target.EffectiveEntityID()
	entitySlug := target.EffectiveEntitySlug()
	now := time.Now().UTC()
	delivery, err := target.AdmissionPlan.Accept(providertriggers.Request{
		Provider: provider,
		Target: providertriggers.Target{
			EntityID:      target.EntityID,
			EntitySlug:    target.EntitySlug,
			WebhookSecret: signingValue,
		},
		Method:          r.Method,
		URL:             requestURL,
		Body:            body,
		Headers:         r.Header,
		Payload:         payload,
		ContentType:     r.Header.Get("Content-Type"),
		Query:           queryValues,
		QueryParseError: queryParseError,
		Form:            formValues,
		FormParsed:      formParsed,
		FormParseError:  formParseError,
		Received:        now,
		UserAgent:       r.UserAgent(),
	})
	if err != nil {
		status := http.StatusBadRequest
		if providerErr, ok := err.(providertriggers.Error); ok {
			status = providerErr.Status
		}
		http.Error(w, err.Error(), status)
		return
	}
	if delivery.Response != nil {
		status := delivery.Response.Status
		if status == 0 {
			status = http.StatusOK
		}
		contentType := strings.TrimSpace(delivery.Response.ContentType)
		if contentType == "" {
			contentType = "text/plain; charset=utf-8"
		}
		w.Header().Set("content-type", contentType)
		w.WriteHeader(status)
		_, _ = w.Write(delivery.Response.Body)
		return
	}
	if source != nil && !standingInputPinAdmitted(source, target.FlowID, string(delivery.EventName)) {
		http.Error(w, fmt.Sprintf("ingress target %q provider %q resolved event %q, but flow %q in bundle %s has no exact external input pin; add that pin", target.Alias, provider, delivery.EventName, target.FlowID, target.BundleHash), http.StatusUnprocessableEntity)
		return
	}
	providerEventID := delivery.ProviderEventID
	requestCtx := r.Context()
	if strings.TrimSpace(target.RunID) != "" {
		requestCtx = runtimecorrelation.WithRunID(requestCtx, target.RunID)
	}

	if g.store == nil || g.bus == nil {
		http.Error(w, "inbound publication owner unavailable", http.StatusServiceUnavailable)
		return
	}

	pubType, pubPayload := delivery.EventName, delivery.Payload
	envelopeBytes := mustJSON(pubPayload)
	projection, err := target.AdmissionPlan.SemanticDeliveryProjection(delivery)
	if err != nil {
		http.Error(w, "derive inbound semantic projection failed", http.StatusInternalServerError)
		return
	}
	projection["target"] = map[string]any{
		"entity_id":         entityID,
		"stable_service_id": strings.TrimSpace(target.ServiceID),
		"package_key":       strings.TrimSpace(target.PackageKey),
		"flow_id":           strings.TrimSpace(target.FlowID),
		"instance_id":       strings.TrimSpace(target.InstanceID),
	}
	fingerprint, err := runtimeinbound.SemanticFingerprint(projection)
	if err != nil {
		http.Error(w, "derive inbound semantic fingerprint failed", http.StatusInternalServerError)
		return
	}
	publicationID, markerEventID, publicationEventID := runtimeinbound.DeterministicIDs(provider, entityID, providerEventID)
	ackMode := runtimeinbound.AcknowledgementAfterPublish
	if delivery.AcknowledgeBeforeDispatch {
		ackMode = runtimeinbound.AcknowledgementDurableBeforeDispatch
	}
	request := runtimeinbound.Request{
		PublicationID:               publicationID,
		Provider:                    provider,
		EntityID:                    entityID,
		ProviderEventID:             providerEventID,
		SemanticFingerprint:         fingerprint,
		SemanticProjectionVersion:   runtimeinbound.SemanticProjectionVersion,
		StableServiceID:             target.ServiceID,
		PackageKey:                  target.PackageKey,
		FlowID:                      target.FlowID,
		InstanceID:                  target.InstanceID,
		TargetAlias:                 target.Alias,
		TargetFlowInstance:          target.FlowInstance,
		ExpectedPublicationSequence: target.PublicationSequence,
		ResolvedRunID:               target.RunID,
		MarkerEventID:               markerEventID,
		PublicationEventID:          publicationEventID,
		AcknowledgementMode:         ackMode,
		OriginalReceivedAt:          now,
		OriginalUserAgent:           r.UserAgent(),
		OriginalTransportMetadata: mustJSON(map[string]any{
			"method":       r.Method,
			"content_type": r.Header.Get("Content-Type"),
		}),
	}
	pubCtx := runtimebus.WithCurrentRuntimeEpoch(requestCtx)
	envelope := events.EnvelopeForFlowInstance(events.EnvelopeForEntityID(events.EventEnvelope{}, entityID), target.FlowInstance)
	if target.AdmissionPlan.PolicySource() == providertriggers.PolicySourceRawDeclaration {
		envelope = events.EnvelopeForTargetRoute(envelope, events.RouteIdentity{EntityID: entityID, FlowInstance: target.FlowInstance})
	}
	published := events.NewRootIngressEvent(publicationEventID, pubType, "inbound-gateway", "", envelopeBytes, 0, target.RunID, "", envelope, now)
	evidencePayload := mustJSON(map[string]any{
		"publication_id":       publicationID,
		"publication_event_id": publicationEventID,
		"provider":             provider,
		"provider_event_id":    providerEventID,
		"entity_id":            entityID,
	})
	evidence := events.NewDiagnosticDirectEvent(markerEventID, events.EventType("platform.inbound_recorded"), "runtime", "", evidencePayload, 0, target.RunID, "", events.EnvelopeForEntityID(events.EventEnvelope{}, entityID), now)
	var prepared runtimebus.PreparedPublish
	record, err := g.store.RunInboundPublicationMutation(pubCtx, request, func(mutation runtimeinbound.Mutation) error {
		var prepareErr error
		prepared, prepareErr = g.bus.PreparePublishInMutation(mutation.Context(), published)
		if prepareErr != nil {
			return prepareErr
		}
		manifest, _, _, manifestErr := runtimeinbound.CanonicalRecipientManifest(prepared.DeliveryRoutes())
		if manifestErr != nil {
			return manifestErr
		}
		return mutation.FinalizeInboundPublication(mutation.Context(), runtimeinbound.Finalization{
			EvidenceEvent: evidence, PublicationEvent: prepared.Event, RecipientManifest: manifest,
		})
	})
	if err != nil {
		if g.logger != nil {
			handleRuntimeLogPersistenceError("inbound-gateway", "publish_failed", g.logger.Error(requestCtx, "inbound-gateway", "publish_failed", map[string]any{
				"provider": provider, "entity_id": entityID, "provider_event_id": providerEventID,
			}, err))
		}
		http.Error(w, "publish inbound failed", http.StatusServiceUnavailable)
		return
	}
	if !record.Created {
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "duplicate", "provider": provider, "provider_event_id": providerEventID,
			"provider_event_type": delivery.ProviderEventType, "event_name": string(delivery.EventName),
			"publication_id": record.PublicationID, "event_id": record.PublicationEventID,
		})
		return
	}
	_, committedFingerprint, committedCount, err := runtimeinbound.CanonicalRecipientManifest(prepared.DeliveryRoutes())
	if err != nil || committedFingerprint != record.RecipientFingerprint || committedCount != record.RecipientCount {
		if err == nil {
			err = fmt.Errorf("committed inbound recipient manifest does not match the prepared publication")
		}
		if g.logger != nil {
			handleRuntimeLogPersistenceError("inbound-gateway", "committed_manifest_mismatch", g.logger.Error(requestCtx, "inbound-gateway", "committed_manifest_mismatch", map[string]any{
				"publication_id": record.PublicationID, "event_id": record.PublicationEventID,
			}, err))
		}
		http.Error(w, "publish inbound failed", http.StatusServiceUnavailable)
		return
	}
	if record.AcknowledgementMode == runtimeinbound.AcknowledgementDurableBeforeDispatch {
		g.bus.DispatchPreparedPublishAsync(pubCtx, prepared)
	} else if err := g.bus.DispatchPreparedPublish(pubCtx, prepared); err != nil {
		http.Error(w, "publish inbound failed", http.StatusServiceUnavailable)
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":              "accepted",
		"entity_id":           entityID,
		"entity_slug":         entitySlug,
		"provider":            provider,
		"provider_event_id":   providerEventID,
		"provider_event_type": delivery.ProviderEventType,
		"event_name":          string(delivery.EventName),
		"publication_id":      record.PublicationID,
		"event_id":            record.PublicationEventID,
	})
}

func parseWebhookPath(path string) (entityID, provider string, ok bool) {
	p := strings.Trim(path, "/")
	parts := strings.Split(p, "/")
	if len(parts) != 3 || parts[0] != "webhooks" {
		return "", "", false
	}
	entityID = strings.TrimSpace(parts[1])
	provider = strings.TrimSpace(parts[2])
	if entityID == "" || provider == "" {
		return "", "", false
	}
	return entityID, provider, true
}

func inboundRequestURL(r *http.Request) string {
	if r == nil || r.URL == nil || strings.TrimSpace(r.URL.Fragment) != "" {
		return ""
	}
	scheme := "http"
	host := strings.TrimSpace(r.Host)
	if r.URL.IsAbs() {
		if strings.TrimSpace(r.URL.Scheme) == "" {
			return ""
		}
		scheme = strings.TrimSpace(r.URL.Scheme)
		if host == "" {
			host = strings.TrimSpace(r.URL.Host)
		}
	} else if r.TLS != nil {
		scheme = "https"
	}
	if host == "" {
		return ""
	}
	uri := r.URL.RequestURI()
	if strings.TrimSpace(uri) == "" {
		uri = "/"
	}
	return scheme + "://" + host + uri
}

func inboundQueryValues(r *http.Request) (url.Values, string) {
	if r == nil || r.URL == nil || strings.TrimSpace(r.URL.RawQuery) == "" {
		return nil, ""
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, err.Error()
	}
	return values, ""
}

func inboundFormValues(contentType string, body []byte) (url.Values, bool, string) {
	contentType = strings.TrimSpace(contentType)
	if contentType == "" {
		return nil, false, ""
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, false, err.Error()
	}
	if !strings.EqualFold(mediaType, "application/x-www-form-urlencoded") {
		return nil, false, ""
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, true, err.Error()
	}
	return values, true, ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
