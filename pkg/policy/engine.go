package policy

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"log"
	"sort"
	"strings"
	"sync"

	//nolint:staticcheck // OPA v1 migration pending
	"github.com/open-policy-agent/opa/ast"
	//nolint:staticcheck // OPA v1 migration pending
	"github.com/open-policy-agent/opa/rego"

	"github.com/polisai/polis-oss/pkg/domain"
)

// EngineOptions control OPA engine construction and runtime behaviour.
type EngineOptions struct {
	// Entrypoint is the default policy decision path (e.g. "policy/decision").
	Entrypoint string
	// Modules contains the Rego modules that should be loaded into the engine.
	Modules map[string]string
	// CacheMaxEntries bounds the decision cache size (LRU). Zero selects the
	// default size; negative disables caching entirely.
	CacheMaxEntries int
}

// Engine evaluates policy decisions using an embedded OPA SDK instance.
type Engine struct {
	modules       map[string]string
	moduleOrder   []string
	parsedModules map[string]*ast.Module
	entrypoint    string
	cache         *decisionCache
	queries       map[string]*rego.PreparedEvalQuery
	mu            sync.RWMutex
}

const (
	defaultEntrypoint    = "policy/decision"
	defaultCacheCapacity = 1024
)

// NewEngine constructs an Engine for the supplied configuration and entrypoint.
func NewEngine(ctx context.Context, opts EngineOptions) (*Engine, error) {
	entry := strings.TrimSpace(opts.Entrypoint)
	if entry == "" {
		entry = defaultEntrypoint
	}

	if len(opts.Modules) == 0 {
		return nil, errors.New("policy engine requires at least one rego module")
	}

	maxEntries := opts.CacheMaxEntries
	switch {
	case maxEntries == 0:
		maxEntries = defaultCacheCapacity
	case maxEntries < 0:
		maxEntries = 0
	}

	var cache *decisionCache
	if maxEntries > 0 {
		cache = newDecisionCache(maxEntries)
	}

	moduleCopy := make(map[string]string, len(opts.Modules))
	moduleOrder := make([]string, 0, len(opts.Modules))
	for name, src := range opts.Modules {
		moduleCopy[name] = src
		moduleOrder = append(moduleOrder, name)
	}
	sort.Strings(moduleOrder)

	parsedModules := make(map[string]*ast.Module, len(moduleCopy))
	for _, name := range moduleOrder {
		src := moduleCopy[name]
		module, err := ast.ParseModuleWithOpts(name, src, ast.ParserOptions{RegoVersion: ast.RegoV1})
		if err != nil {
			return nil, fmt.Errorf("parse rego module %q: %w", name, err)
		}
		parsedModules[name] = module
	}

	engine := &Engine{
		modules:       moduleCopy,
		moduleOrder:   moduleOrder,
		parsedModules: parsedModules,
		entrypoint:    entry,
		cache:         cache,
		queries:       make(map[string]*rego.PreparedEvalQuery),
	}

	// Warm the default entrypoint to surface syntax errors early.
	if _, err := engine.getPreparedQuery(ctx, entry); err != nil {
		return nil, fmt.Errorf("compile rego modules: %w", err)
	}

	return engine, nil
}

// Evaluate executes the policy using the supplied input and converts the result.
func (e *Engine) Evaluate(ctx context.Context, input Input) (Decision, error) {
	entry := strings.TrimSpace(input.Entrypoint)
	if entry == "" {
		entry = e.entrypoint
	}
	if entry == "" {
		return Decision{}, errors.New("policy engine requires an entrypoint")
	}

	payload := map[string]any{
		"route_id":          input.RouteID,
		"policy_generation": strings.TrimSpace(input.Generation),
		"identity":          identityToMap(input.Identity),
		"attributes":        cloneAnyMap(input.Attributes),
		"findings":          cloneAnyMap(input.Findings),
	}

	cacheKey, shouldCache := e.cacheKey(entry, input)
	if shouldCache {
		if cached, ok := e.cache.Get(cacheKey); ok {
			return cloneDecision(cached), nil
		}
	}

	prepared, err := e.getPreparedQuery(ctx, entry)
	if err != nil {
		return Decision{}, fmt.Errorf("prepare query: %w", err)
	}

	log.Printf("DEBUG: Evaluating OPA with entrypoint: %s, payload keys: %v", entry, getMapKeys(payload))
	results, err := prepared.Eval(ctx, rego.EvalInput(payload))
	if err != nil {
		return Decision{}, fmt.Errorf("opa decision: %w", err)
	}

	if len(results) == 0 {
		log.Println("DEBUG: OPA returned 0 results")
		return Decision{Action: ActionAllow, Metadata: map[string]string{}}, nil
	}

	if len(results[0].Expressions) == 0 {
		log.Println("DEBUG: OPA returned 0 expressions")
		return Decision{Action: ActionAllow, Metadata: map[string]string{}}, nil
	}

	decisionPayload, ok := results[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return Decision{}, fmt.Errorf("opa decision: unexpected result type %T", results[0].Expressions[0].Value)
	}
	log.Printf("DEBUG: OPA Result: %+v\n", decisionPayload)

	action, err := parseAction(decisionPayload["action"])
	if err != nil {
		return Decision{}, err
	}

	reason, _ := decisionPayload["reason"].(string)
	metadata := parseMetadata(decisionPayload["metadata"])

	outputs := extractDecisionOutputs(decisionPayload)

	decision := Decision{Action: action, Reason: reason, Metadata: metadata, Outputs: outputs}

	if shouldCache {
		e.cache.Add(cacheKey, decision)
	}

	return decision, nil
}

// FlushCache clears all cached decisions. Safe to call concurrently.
func (e *Engine) FlushCache() {
	if e.cache != nil {
		e.cache.Clear()
	}
}

// Close releases underlying OPA resources.
func (e *Engine) Close(_ context.Context) error {
	return nil
}

func (e *Engine) getPreparedQuery(ctx context.Context, entry string) (*rego.PreparedEvalQuery, error) {
	queryKey := entry

	e.mu.RLock()
	if prepared, ok := e.queries[queryKey]; ok {
		e.mu.RUnlock()
		return prepared, nil
	}
	e.mu.RUnlock()

	query := "data." + strings.ReplaceAll(entry, "/", ".")

	opts := make([]func(*rego.Rego), 0, len(e.parsedModules)+1)
	opts = append(opts, rego.Query(query))
	for _, name := range e.moduleOrder {
		module := e.parsedModules[name]
		opts = append(opts, rego.ParsedModule(module))
	}

	r := rego.New(opts...)

	prepared, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Another goroutine may have already prepared the query; respect first entry.
	if existing, ok := e.queries[queryKey]; ok {
		return existing, nil
	}

	e.queries[queryKey] = &prepared
	return &prepared, nil
}

// cacheKey generates a deterministic hash key for caching policy decisions.
func (e *Engine) cacheKey(entry string, input Input) (string, bool) {
	if !e.shouldCache(input) {
		return "", false
	}

	components, ok := e.extractCacheKeyComponents(input)
	if !ok {
		return "", false
	}

	hash := e.buildCacheKeyHash(entry, components)
	return hex.EncodeToString(hash), true
}

// shouldCache determines if the input is eligible for caching.
func (e *Engine) shouldCache(input Input) bool {
	return e.cache != nil && !input.DisableCache
}

// cacheKeyComponents holds the normalized fields required for cache key generation.
type cacheKeyComponents struct {
	route      string
	generation string
	issuer     string
	subject    string
	audiences  []string
	scopes     []string
}

// extractCacheKeyComponents validates and extracts required fields from the input.
func (e *Engine) extractCacheKeyComponents(input Input) (cacheKeyComponents, bool) {
	components := cacheKeyComponents{
		route:      strings.TrimSpace(input.RouteID),
		generation: strings.TrimSpace(input.Generation),
		issuer:     strings.TrimSpace(input.Identity.Issuer),
		subject:    strings.TrimSpace(input.Identity.Subject),
	}

	if components.route == "" || components.generation == "" {
		return cacheKeyComponents{}, false
	}

	if components.issuer == "" || components.subject == "" {
		return cacheKeyComponents{}, false
	}

	components.audiences = normalizeStringSlice(input.Identity.Audience)
	components.scopes = normalizeStringSlice(input.Identity.Scopes)

	return components, true
}

// buildCacheKeyHash constructs a SHA-256 hash from the entry point and cache key components.
func (e *Engine) buildCacheKeyHash(entry string, components cacheKeyComponents) []byte {
	h := sha256.New()

	writeCacheKeyField(h, entry)
	writeCacheKeyField(h, components.route)
	writeCacheKeyField(h, components.generation)
	writeCacheKeyField(h, components.issuer)
	writeCacheKeyField(h, components.subject)
	writeCacheKeyField(h, strings.Join(components.audiences, ","))
	writeCacheKeyField(h, strings.Join(components.scopes, ","))

	return h.Sum(nil)
}

// writeCacheKeyField writes a field to the hash followed by a null delimiter.
// The trailing null byte provides field separation and doesn't affect hash security.
func writeCacheKeyField(h hash.Hash, value string) {
	h.Write([]byte(value))
	h.Write([]byte{0})
}

// normalizeStringSlice creates a sorted copy of the input slice for consistent hashing.
func normalizeStringSlice(input []string) []string {
	if len(input) == 0 {
		return nil
	}
	normalized := append([]string(nil), input...)
	sort.Strings(normalized)
	return normalized
}

func cloneDecision(dec Decision) Decision {
	return Decision{
		Action:   dec.Action,
		Reason:   dec.Reason,
		Metadata: cloneStringMap(dec.Metadata),
		Outputs:  cloneAnyMap(dec.Outputs),
	}
}

func cloneAnyMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return map[string]any{}
	}
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

type decisionCache struct {
	mu      sync.Mutex
	max     int
	order   *list.List
	entries map[string]*list.Element
}

type cacheItem struct {
	key   string
	value Decision
}

func newDecisionCache(capacity int) *decisionCache {
	return &decisionCache{
		max:     capacity,
		order:   list.New(),
		entries: make(map[string]*list.Element, capacity),
	}
}

func (c *decisionCache) Get(key string) (Decision, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	elem, ok := c.entries[key]
	if !ok {
		return Decision{}, false
	}
	c.order.MoveToFront(elem)
	item := elem.Value.(cacheItem)
	return item.value, true
}

func (c *decisionCache) Add(key string, value Decision) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.entries[key]; ok {
		elem.Value = cacheItem{key: key, value: value}
		c.order.MoveToFront(elem)
		return
	}

	elem := c.order.PushFront(cacheItem{key: key, value: value})
	c.entries[key] = elem

	if c.order.Len() <= c.max {
		return
	}

	tail := c.order.Back()
	if tail != nil {
		c.order.Remove(tail)
		item := tail.Value.(cacheItem)
		delete(c.entries, item.key)
	}
}

func (c *decisionCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.order.Init()
	c.entries = make(map[string]*list.Element, c.max)
}

func parseAction(value any) (Action, error) {
	if value == nil {
		return ActionAllow, nil
	}
	text, ok := value.(string)
	if !ok {
		return Action(""), fmt.Errorf("opa decision: action must be string, got %T", value)
	}
	switch Action(strings.ToLower(text)) {
	case ActionAllow:
		return ActionAllow, nil
	case ActionRedact:
		return ActionRedact, nil
	case ActionBlock:
		return ActionBlock, nil
	default:
		return Action(""), fmt.Errorf("opa decision: unknown action %q", text)
	}
}

func parseMetadata(value any) map[string]string {
	if value == nil {
		return map[string]string{}
	}

	switch typed := value.(type) {
	case map[string]string:
		return cloneStringMap(typed)
	case map[string]any:
		result := make(map[string]string, len(typed))
		for key, raw := range typed {
			if str, ok := raw.(string); ok {
				result[key] = str
			}
		}
		return result
	default:
		return map[string]string{}
	}
}

func extractDecisionOutputs(payload map[string]any) map[string]any {
	if len(payload) == 0 {
		return map[string]any{}
	}

	outputs := make(map[string]any)
	for key, value := range payload {
		switch strings.ToLower(key) {
		case "action", "reason", "metadata":
			continue
		default:
			outputs[key] = value
		}
	}

	if len(outputs) == 0 {
		return map[string]any{}
	}

	return outputs
}

func identityToMap(id domain.PolicyIdentity) map[string]any {
	return map[string]any{
		"issuer":   id.Issuer,
		"subject":  id.Subject,
		"audience": append([]string(nil), id.Audience...),
		"scopes":   append([]string(nil), id.Scopes...),
	}
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func getMapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
