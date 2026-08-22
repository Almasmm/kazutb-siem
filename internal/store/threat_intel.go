package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/kcsp/platform/internal/core"
)

const threatFeedColumns = `tenant_id,feed_id,name,kind,description,state,source_url,auth_reference,
	refresh_interval_seconds,default_confidence,tags,version,created_by,updated_by,created_at,updated_at`

const threatIndicatorColumns = `tenant_id,indicator_id,feed_id,indicator_type,value,normalized_value,source,
	confidence,reputation,ttl_seconds,first_seen,last_seen,valid_from,valid_until,tags,campaign,malware,
	threat_actors,description,external_id,state,version,created_by,updated_by,created_at,updated_at`

const threatMatchColumns = `tenant_id,match_id,indicator_id,indicator_version,feed_id,event_id,indicator_type,
	indicator_value,matched_field,matched_value,confidence,reputation,matched_at`

type threatRow interface {
	Scan(...interface{}) error
}

func (p *Postgres) CreateThreatIntelFeed(ctx context.Context, feed core.ThreatIntelFeed) (core.ThreatIntelFeed, error) {
	tags, err := json.Marshal(feed.Tags)
	if err != nil {
		return core.ThreatIntelFeed{}, fmt.Errorf("encode threat intelligence feed tags: %w", err)
	}
	created, err := scanThreatFeed(p.pool.QueryRow(ctx, `INSERT INTO threat_intel_feeds(
		tenant_id,feed_id,name,kind,description,state,source_url,auth_reference,refresh_interval_seconds,
		default_confidence,tags,version,created_by,updated_by,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		RETURNING `+threatFeedColumns, feed.TenantID, feed.ID, feed.Name, feed.Kind, feed.Description,
		feed.State, feed.SourceURL, feed.AuthReference, feed.RefreshIntervalSeconds, feed.DefaultConfidence,
		tags, feed.Version, feed.CreatedBy, feed.UpdatedBy, feed.CreatedAt, feed.UpdatedAt))
	if err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "23505" {
			return core.ThreatIntelFeed{}, ErrAlreadyExists
		}
		return core.ThreatIntelFeed{}, fmt.Errorf("create threat intelligence feed: %w", err)
	}
	return created, nil
}

func (p *Postgres) GetThreatIntelFeed(ctx context.Context, tenantID, feedID string) (core.ThreatIntelFeed, error) {
	feed, err := scanThreatFeed(p.pool.QueryRow(ctx, `SELECT `+threatFeedColumns+` FROM threat_intel_feeds
		WHERE tenant_id=$1 AND feed_id=$2`, tenantID, feedID))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.ThreatIntelFeed{}, ErrNotFound
	}
	if err != nil {
		return core.ThreatIntelFeed{}, fmt.Errorf("get threat intelligence feed: %w", err)
	}
	return feed, nil
}

func (p *Postgres) ListThreatIntelFeeds(ctx context.Context, tenantID string) ([]core.ThreatIntelFeed, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+threatFeedColumns+` FROM threat_intel_feeds
		WHERE tenant_id=$1 ORDER BY name,feed_id`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list threat intelligence feeds: %w", err)
	}
	defer rows.Close()
	feeds := make([]core.ThreatIntelFeed, 0)
	for rows.Next() {
		feed, scanErr := scanThreatFeed(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan threat intelligence feed: %w", scanErr)
		}
		feeds = append(feeds, feed)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate threat intelligence feeds: %w", err)
	}
	return feeds, nil
}

func (p *Postgres) UpdateThreatIntelFeed(ctx context.Context, feed core.ThreatIntelFeed) (core.ThreatIntelFeed, error) {
	tags, err := json.Marshal(feed.Tags)
	if err != nil {
		return core.ThreatIntelFeed{}, fmt.Errorf("encode threat intelligence feed tags: %w", err)
	}
	updated, err := scanThreatFeed(p.pool.QueryRow(ctx, `UPDATE threat_intel_feeds SET
		name=$4,description=$5,state=$6,source_url=$7,auth_reference=$8,refresh_interval_seconds=$9,
		default_confidence=$10,tags=$11,updated_by=$12,updated_at=$13,version=version+1
		WHERE tenant_id=$1 AND feed_id=$2 AND version=$3 RETURNING `+threatFeedColumns,
		feed.TenantID, feed.ID, feed.Version, feed.Name, feed.Description, feed.State, feed.SourceURL,
		feed.AuthReference, feed.RefreshIntervalSeconds, feed.DefaultConfidence, tags, feed.UpdatedBy, feed.UpdatedAt))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.ThreatIntelFeed{}, ErrVersionConflict
	}
	if err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "23505" {
			return core.ThreatIntelFeed{}, ErrAlreadyExists
		}
		return core.ThreatIntelFeed{}, fmt.Errorf("update threat intelligence feed: %w", err)
	}
	return updated, nil
}

func (p *Postgres) UpsertThreatIndicator(ctx context.Context, candidate core.ThreatIndicator) (core.ThreatIndicator, bool, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return core.ThreatIndicator{}, false, fmt.Errorf("begin threat indicator upsert: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	lockKey := candidate.TenantID + "|" + string(candidate.Type) + "|" + candidate.NormalizedValue
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", lockKey); err != nil {
		return core.ThreatIndicator{}, false, fmt.Errorf("lock threat indicator identity: %w", err)
	}
	existing, err := scanThreatIndicator(tx.QueryRow(ctx, `SELECT `+threatIndicatorColumns+` FROM threat_intel_indicators
		WHERE tenant_id=$1 AND indicator_type=$2 AND normalized_value=$3 FOR UPDATE`,
		candidate.TenantID, candidate.Type, candidate.NormalizedValue))
	created := false
	var stored core.ThreatIndicator
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		stored, err = insertThreatIndicator(ctx, tx, candidate)
		created = true
	case err != nil:
		return core.ThreatIndicator{}, false, fmt.Errorf("load deduplicated threat indicator: %w", err)
	default:
		merged := mergeThreatIndicator(existing, candidate)
		stored, err = updateThreatIndicator(ctx, tx, merged)
	}
	if err != nil {
		return core.ThreatIndicator{}, false, err
	}
	if err := upsertThreatIndicatorSource(ctx, tx, candidate, stored.ID); err != nil {
		return core.ThreatIndicator{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return core.ThreatIndicator{}, false, fmt.Errorf("commit threat indicator upsert: %w", err)
	}
	return stored, created, nil
}

func (p *Postgres) GetThreatIndicator(ctx context.Context, tenantID, indicatorID string) (core.ThreatIndicator, error) {
	indicator, err := scanThreatIndicator(p.pool.QueryRow(ctx, `SELECT `+threatIndicatorColumns+` FROM threat_intel_indicators
		WHERE tenant_id=$1 AND indicator_id=$2`, tenantID, indicatorID))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.ThreatIndicator{}, ErrNotFound
	}
	if err != nil {
		return core.ThreatIndicator{}, fmt.Errorf("get threat indicator: %w", err)
	}
	return indicator, nil
}

func (p *Postgres) ListThreatIndicators(ctx context.Context, tenantID string, filter core.ThreatIndicatorFilter) ([]core.ThreatIndicator, error) {
	if filter.Limit <= 0 || filter.Limit > 500 {
		filter.Limit = 100
	}
	rows, err := p.pool.Query(ctx, `SELECT `+threatIndicatorColumns+` FROM threat_intel_indicators
		WHERE tenant_id=$1
		  AND ($2='' OR feed_id=$2)
		  AND ($3='' OR indicator_type=$3)
		  AND ($4='' OR (CASE WHEN state='ACTIVE' AND valid_until IS NOT NULL AND valid_until < now()
			THEN 'EXPIRED' ELSE state END)=$4)
		  AND ($5='' OR position(lower($5) in lower(value)) > 0 OR position(lower($5) in lower(source)) > 0
			OR position(lower($5) in lower(campaign)) > 0 OR position(lower($5) in lower(malware)) > 0)
		ORDER BY last_seen DESC,indicator_id LIMIT $6`,
		tenantID, filter.FeedID, filter.Type, filter.State, strings.TrimSpace(filter.Query), filter.Limit)
	if err != nil {
		return nil, fmt.Errorf("list threat indicators: %w", err)
	}
	defer rows.Close()
	indicators := make([]core.ThreatIndicator, 0)
	for rows.Next() {
		indicator, scanErr := scanThreatIndicator(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan threat indicator: %w", scanErr)
		}
		indicators = append(indicators, indicator)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate threat indicators: %w", err)
	}
	return indicators, nil
}

func (p *Postgres) SetThreatIndicatorState(ctx context.Context, tenantID, indicatorID, state string, version int, actor string) (core.ThreatIndicator, error) {
	updated, err := scanThreatIndicator(p.pool.QueryRow(ctx, `UPDATE threat_intel_indicators
		SET state=$4,version=version+1,updated_by=$5,updated_at=$6
		WHERE tenant_id=$1 AND indicator_id=$2 AND version=$3 RETURNING `+threatIndicatorColumns,
		tenantID, indicatorID, version, state, actor, time.Now().UTC()))
	if errors.Is(err, pgx.ErrNoRows) {
		return core.ThreatIndicator{}, ErrVersionConflict
	}
	if err != nil {
		return core.ThreatIndicator{}, fmt.Errorf("update threat indicator state: %w", err)
	}
	return updated, nil
}

func (p *Postgres) MatchThreatIntelObservables(ctx context.Context, tenantID, eventID string, eventTime time.Time, observables []core.ThreatObservable) ([]core.ThreatIntelMatch, error) {
	if len(observables) == 0 {
		return []core.ThreatIntelMatch{}, nil
	}
	types := make([]string, 0, len(observables))
	values := make([]string, 0, len(observables))
	fields := make([]string, 0, len(observables))
	rawValues := make([]string, 0, len(observables))
	for _, observable := range observables {
		types = append(types, string(observable.Type))
		values = append(values, observable.NormalizedValue)
		fields = append(fields, observable.Field)
		rawValues = append(rawValues, observable.RawValue)
	}
	if eventTime.IsZero() {
		eventTime = time.Now().UTC()
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin threat intelligence matching: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := tx.Query(ctx, `WITH candidates AS (
			SELECT * FROM unnest($2::text[],$3::text[],$4::text[],$5::text[])
				AS c(indicator_type,normalized_value,matched_field,matched_value)
		)
		SELECT i.indicator_id,i.version,i.feed_id,i.indicator_type,i.normalized_value,
			i.confidence,i.reputation,c.matched_field,c.matched_value
		FROM candidates c
		JOIN threat_intel_indicators i ON i.tenant_id=$1 AND i.indicator_type=c.indicator_type
			AND i.normalized_value=c.normalized_value
		JOIN threat_intel_feeds f ON f.tenant_id=i.tenant_id AND f.feed_id=i.feed_id
		WHERE i.state='ACTIVE' AND f.state='ACTIVE' AND i.reputation <> 'TRUSTED'
		  AND i.valid_from <= $6 AND (i.valid_until IS NULL OR i.valid_until >= $6)
		ORDER BY i.indicator_id,c.matched_field`, tenantID, types, values, fields, rawValues, eventTime.UTC())
	if err != nil {
		return nil, fmt.Errorf("match threat intelligence observables: %w", err)
	}
	type candidateMatch struct {
		indicatorID, feedID, indicatorType, value, reputation, field, rawValue string
		version, confidence                                                    int
	}
	candidates := make([]candidateMatch, 0)
	for rows.Next() {
		var item candidateMatch
		if err := rows.Scan(&item.indicatorID, &item.version, &item.feedID, &item.indicatorType, &item.value,
			&item.confidence, &item.reputation, &item.field, &item.rawValue); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan threat intelligence match candidate: %w", err)
		}
		candidates = append(candidates, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("iterate threat intelligence match candidates: %w", err)
	}
	rows.Close()
	matchedAt := time.Now().UTC()
	matches := make([]core.ThreatIntelMatch, 0, len(candidates))
	for _, candidate := range candidates {
		match, err := scanThreatIntelMatch(tx.QueryRow(ctx, `INSERT INTO threat_intel_matches(
				tenant_id,match_id,indicator_id,indicator_version,feed_id,event_id,indicator_type,indicator_value,
				matched_field,matched_value,confidence,reputation,matched_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
			ON CONFLICT (tenant_id,indicator_id,event_id,matched_field)
			DO UPDATE SET match_id=threat_intel_matches.match_id
			RETURNING `+threatMatchColumns, tenantID, core.NewID("tim"), candidate.indicatorID, candidate.version,
			candidate.feedID, eventID, candidate.indicatorType, candidate.value, candidate.field, candidate.rawValue,
			candidate.confidence, candidate.reputation, matchedAt))
		if err != nil {
			return nil, fmt.Errorf("persist threat intelligence match: %w", err)
		}
		matches = append(matches, match)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit threat intelligence matching: %w", err)
	}
	return matches, nil
}

func (p *Postgres) ListThreatIntelMatches(ctx context.Context, tenantID, indicatorID, eventID string, limit int) ([]core.ThreatIntelMatch, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := p.pool.Query(ctx, `SELECT `+threatMatchColumns+` FROM threat_intel_matches
		WHERE tenant_id=$1 AND ($2='' OR indicator_id=$2) AND ($3='' OR event_id=$3)
		ORDER BY matched_at DESC,match_id LIMIT $4`, tenantID, indicatorID, eventID, limit)
	if err != nil {
		return nil, fmt.Errorf("list threat intelligence matches: %w", err)
	}
	defer rows.Close()
	matches := make([]core.ThreatIntelMatch, 0)
	for rows.Next() {
		match, scanErr := scanThreatIntelMatch(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan threat intelligence match: %w", scanErr)
		}
		matches = append(matches, match)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate threat intelligence matches: %w", err)
	}
	return matches, nil
}

func insertThreatIndicator(ctx context.Context, tx pgx.Tx, indicator core.ThreatIndicator) (core.ThreatIndicator, error) {
	tags, actors, err := encodeThreatIndicatorLists(indicator)
	if err != nil {
		return core.ThreatIndicator{}, err
	}
	stored, err := scanThreatIndicator(tx.QueryRow(ctx, `INSERT INTO threat_intel_indicators(
		tenant_id,indicator_id,feed_id,indicator_type,value,normalized_value,source,confidence,reputation,
		ttl_seconds,first_seen,last_seen,valid_from,valid_until,tags,campaign,malware,threat_actors,
		description,external_id,state,version,created_by,updated_by,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)
		RETURNING `+threatIndicatorColumns, indicator.TenantID, indicator.ID, indicator.FeedID, indicator.Type,
		indicator.Value, indicator.NormalizedValue, indicator.Source, indicator.Confidence, indicator.Reputation,
		indicator.TTLSeconds, indicator.FirstSeen, indicator.LastSeen, indicator.ValidFrom, indicator.ValidUntil,
		tags, indicator.Campaign, indicator.Malware, actors, indicator.Description, indicator.ExternalID,
		indicator.State, indicator.Version, indicator.CreatedBy, indicator.UpdatedBy, indicator.CreatedAt, indicator.UpdatedAt))
	if err != nil {
		return core.ThreatIndicator{}, fmt.Errorf("insert threat indicator: %w", err)
	}
	return stored, nil
}

func updateThreatIndicator(ctx context.Context, tx pgx.Tx, indicator core.ThreatIndicator) (core.ThreatIndicator, error) {
	tags, actors, err := encodeThreatIndicatorLists(indicator)
	if err != nil {
		return core.ThreatIndicator{}, err
	}
	stored, err := scanThreatIndicator(tx.QueryRow(ctx, `UPDATE threat_intel_indicators SET
		feed_id=$4,value=$5,source=$6,confidence=$7,reputation=$8,ttl_seconds=$9,first_seen=$10,
		last_seen=$11,valid_from=$12,valid_until=$13,tags=$14,campaign=$15,malware=$16,
		threat_actors=$17,description=$18,external_id=$19,state=$20,version=$21,updated_by=$22,updated_at=$23
		WHERE tenant_id=$1 AND indicator_type=$2 AND normalized_value=$3 RETURNING `+threatIndicatorColumns,
		indicator.TenantID, indicator.Type, indicator.NormalizedValue, indicator.FeedID, indicator.Value,
		indicator.Source, indicator.Confidence, indicator.Reputation, indicator.TTLSeconds, indicator.FirstSeen,
		indicator.LastSeen, indicator.ValidFrom, indicator.ValidUntil, tags, indicator.Campaign, indicator.Malware,
		actors, indicator.Description, indicator.ExternalID, indicator.State, indicator.Version,
		indicator.UpdatedBy, indicator.UpdatedAt))
	if err != nil {
		return core.ThreatIndicator{}, fmt.Errorf("update deduplicated threat indicator: %w", err)
	}
	return stored, nil
}

func upsertThreatIndicatorSource(ctx context.Context, tx pgx.Tx, imported core.ThreatIndicator, indicatorID string) error {
	sourceIdentity := imported.FeedID + "|" + imported.Source + "|" + imported.ExternalID
	sourceSum := sha256.Sum256([]byte(sourceIdentity))
	payload, err := json.Marshal(struct {
		Type       core.ThreatIndicatorType
		Value      string
		Confidence int
		Reputation string
		FirstSeen  time.Time
		LastSeen   time.Time
		ValidUntil *time.Time
	}{imported.Type, imported.NormalizedValue, imported.Confidence, imported.Reputation,
		imported.FirstSeen, imported.LastSeen, imported.ValidUntil})
	if err != nil {
		return fmt.Errorf("encode threat indicator provenance: %w", err)
	}
	payloadSum := sha256.Sum256(payload)
	_, err = tx.Exec(ctx, `INSERT INTO threat_intel_indicator_sources(
		tenant_id,indicator_id,source_key,feed_id,external_id,source,confidence,first_seen,last_seen,
		valid_until,payload_hash,imported_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (tenant_id,indicator_id,source_key) DO UPDATE SET
			confidence=EXCLUDED.confidence,first_seen=LEAST(threat_intel_indicator_sources.first_seen,EXCLUDED.first_seen),
			last_seen=GREATEST(threat_intel_indicator_sources.last_seen,EXCLUDED.last_seen),
			valid_until=EXCLUDED.valid_until,payload_hash=EXCLUDED.payload_hash,imported_at=EXCLUDED.imported_at`,
		imported.TenantID, indicatorID, hex.EncodeToString(sourceSum[:]), imported.FeedID, imported.ExternalID,
		imported.Source, imported.Confidence, imported.FirstSeen, imported.LastSeen, imported.ValidUntil,
		hex.EncodeToString(payloadSum[:]), imported.UpdatedAt)
	if err != nil {
		return fmt.Errorf("persist threat indicator provenance: %w", err)
	}
	return nil
}

func mergeThreatIndicator(existing, incoming core.ThreatIndicator) core.ThreatIndicator {
	merged := existing
	merged.FeedID = incoming.FeedID
	merged.Value = incoming.Value
	merged.Source = incoming.Source
	if incoming.Confidence > merged.Confidence {
		merged.Confidence = incoming.Confidence
	}
	if reputationRank(incoming.Reputation) > reputationRank(merged.Reputation) {
		merged.Reputation = incoming.Reputation
	}
	if incoming.FirstSeen.Before(merged.FirstSeen) {
		merged.FirstSeen = incoming.FirstSeen
	}
	if incoming.LastSeen.After(merged.LastSeen) {
		merged.LastSeen = incoming.LastSeen
		merged.TTLSeconds = incoming.TTLSeconds
	}
	if incoming.ValidFrom.Before(merged.ValidFrom) {
		merged.ValidFrom = incoming.ValidFrom
	}
	merged.ValidUntil = laterExpiry(merged.ValidUntil, incoming.ValidUntil)
	merged.Tags = mergeThreatStrings(merged.Tags, incoming.Tags)
	merged.ThreatActors = mergeThreatStrings(merged.ThreatActors, incoming.ThreatActors)
	if incoming.Campaign != "" {
		merged.Campaign = incoming.Campaign
	}
	if incoming.Malware != "" {
		merged.Malware = incoming.Malware
	}
	if incoming.Description != "" {
		merged.Description = incoming.Description
	}
	if incoming.ExternalID != "" {
		merged.ExternalID = incoming.ExternalID
	}
	if existing.State == core.ThreatIntelStateRevoked {
		merged.State = core.ThreatIntelStateRevoked
	} else {
		merged.State = core.ThreatIntelStateActive
	}
	merged.Version = existing.Version + 1
	merged.UpdatedBy = incoming.UpdatedBy
	merged.UpdatedAt = incoming.UpdatedAt
	return merged
}

func laterExpiry(left, right *time.Time) *time.Time {
	if left == nil || right == nil {
		return nil
	}
	if right.After(*left) {
		value := right.UTC()
		return &value
	}
	value := left.UTC()
	return &value
}

func mergeThreatStrings(left, right []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(left)+len(right))
	for _, values := range [][]string{left, right} {
		for _, value := range values {
			key := strings.ToLower(value)
			if value != "" && !seen[key] {
				seen[key] = true
				result = append(result, value)
			}
		}
	}
	sort.Strings(result)
	return result
}

func reputationRank(value string) int {
	switch value {
	case "MALICIOUS":
		return 4
	case "SUSPICIOUS":
		return 3
	case "UNKNOWN":
		return 2
	case "TRUSTED":
		return 1
	default:
		return 0
	}
}

func encodeThreatIndicatorLists(indicator core.ThreatIndicator) ([]byte, []byte, error) {
	tags, err := json.Marshal(indicator.Tags)
	if err != nil {
		return nil, nil, fmt.Errorf("encode threat indicator tags: %w", err)
	}
	actors, err := json.Marshal(indicator.ThreatActors)
	if err != nil {
		return nil, nil, fmt.Errorf("encode threat indicator actors: %w", err)
	}
	return tags, actors, nil
}

func scanThreatFeed(row threatRow) (core.ThreatIntelFeed, error) {
	var feed core.ThreatIntelFeed
	var tags []byte
	err := row.Scan(&feed.TenantID, &feed.ID, &feed.Name, &feed.Kind, &feed.Description, &feed.State,
		&feed.SourceURL, &feed.AuthReference, &feed.RefreshIntervalSeconds, &feed.DefaultConfidence,
		&tags, &feed.Version, &feed.CreatedBy, &feed.UpdatedBy, &feed.CreatedAt, &feed.UpdatedAt)
	if err != nil {
		return core.ThreatIntelFeed{}, err
	}
	if err := json.Unmarshal(tags, &feed.Tags); err != nil {
		return core.ThreatIntelFeed{}, fmt.Errorf("decode threat intelligence feed tags: %w", err)
	}
	return feed, nil
}

func scanThreatIndicator(row threatRow) (core.ThreatIndicator, error) {
	var indicator core.ThreatIndicator
	var tags, actors []byte
	err := row.Scan(&indicator.TenantID, &indicator.ID, &indicator.FeedID, &indicator.Type, &indicator.Value,
		&indicator.NormalizedValue, &indicator.Source, &indicator.Confidence, &indicator.Reputation,
		&indicator.TTLSeconds, &indicator.FirstSeen, &indicator.LastSeen, &indicator.ValidFrom,
		&indicator.ValidUntil, &tags, &indicator.Campaign, &indicator.Malware, &actors,
		&indicator.Description, &indicator.ExternalID, &indicator.State, &indicator.Version,
		&indicator.CreatedBy, &indicator.UpdatedBy, &indicator.CreatedAt, &indicator.UpdatedAt)
	if err != nil {
		return core.ThreatIndicator{}, err
	}
	if err := json.Unmarshal(tags, &indicator.Tags); err != nil {
		return core.ThreatIndicator{}, fmt.Errorf("decode threat indicator tags: %w", err)
	}
	if err := json.Unmarshal(actors, &indicator.ThreatActors); err != nil {
		return core.ThreatIndicator{}, fmt.Errorf("decode threat indicator actors: %w", err)
	}
	if indicator.State == core.ThreatIntelStateActive && indicator.ValidUntil != nil && indicator.ValidUntil.Before(time.Now().UTC()) {
		indicator.State = core.ThreatIntelStateExpired
	}
	return indicator, nil
}

func scanThreatIntelMatch(row threatRow) (core.ThreatIntelMatch, error) {
	var match core.ThreatIntelMatch
	err := row.Scan(&match.TenantID, &match.ID, &match.IndicatorID, &match.IndicatorVersion,
		&match.FeedID, &match.EventID, &match.Type, &match.Value, &match.MatchedField,
		&match.MatchedValue, &match.Confidence, &match.Reputation, &match.MatchedAt)
	return match, err
}
