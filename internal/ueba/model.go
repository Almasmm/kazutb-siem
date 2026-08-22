package ueba

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
)

const (
	ModelVersion   = "robust-online-v1"
	FeatureVersion = "ocsf-behavior-v1"
)

type Config struct {
	MinimumObservations int
	MinimumPeerSamples  int
	TrainingWindowDays  int
	MaximumCardinality  int
	MinimumRisk         int
}

func DefaultConfig() Config {
	return Config{
		MinimumObservations: 20, MinimumPeerSamples: 50, TrainingWindowDays: 28,
		MaximumCardinality: 256, MinimumRisk: 35,
	}
}

type Profile struct {
	Hours        map[string]int `json:"hours"`
	Devices      map[string]int `json:"devices"`
	IPs          map[string]int `json:"ips"`
	Countries    map[string]int `json:"countries"`
	ASNs         map[string]int `json:"asns"`
	Processes    map[string]int `json:"processes"`
	Destinations map[string]int `json:"destinations"`
	AdminActions map[string]int `json:"admin_actions"`
}

type Baseline struct {
	TenantID           string
	EntityType         string
	EntityID           string
	EntityName         string
	PeerGroup          string
	ModelVersion       string
	FeatureVersion     string
	TrainingWindowDays int
	ObservationCount   int
	FirstSeen          time.Time
	LastSeen           time.Time
	DriftScore         float64
	DriftStatus        string
	Profile            Profile
	UpdatedAt          time.Time
}

type VolumeStats struct {
	CurrentCount int
	Samples      int
	Mean         float64
	StdDev       float64
	Median       float64
	MAD          float64
	ZScore       float64
	RobustZScore float64
}

type FeatureValues struct {
	Hour        string
	Device      string
	IP          string
	Country     string
	ASN         string
	Process     string
	Destination string
	AdminAction string
}

func NewBaseline(tenantID, entityType, entityID, entityName, peerGroup string, at time.Time) Baseline {
	config := DefaultConfig()
	return Baseline{
		TenantID: tenantID, EntityType: entityType, EntityID: entityID, EntityName: entityName,
		PeerGroup: peerGroup, ModelVersion: ModelVersion, FeatureVersion: FeatureVersion,
		TrainingWindowDays: config.TrainingWindowDays, DriftStatus: "COLD_START",
		Profile: NewProfile(), FirstSeen: at, LastSeen: at, UpdatedAt: at,
	}
}

func NewProfile() Profile {
	return Profile{
		Hours: map[string]int{}, Devices: map[string]int{}, IPs: map[string]int{},
		Countries: map[string]int{}, ASNs: map[string]int{}, Processes: map[string]int{},
		Destinations: map[string]int{}, AdminActions: map[string]int{},
	}
}

func EntityForEvent(event core.CanonicalEvent) (entityType, entityID, entityName string, ok bool) {
	if value := firstNonEmpty(event.User.ID, event.User.Name); value != "" {
		return "user", normalizeValue(value), firstNonEmpty(event.User.Name, event.User.ID), true
	}
	if value := firstNonEmpty(event.Device.ID, event.Device.Hostname); value != "" {
		return "device", normalizeValue(value), firstNonEmpty(event.Device.Hostname, event.Device.ID), true
	}
	return "", "", "", false
}

func PeerGroupForEvent(event core.CanonicalEvent) string {
	department := normalizeValue(event.Device.Department)
	if department == "" {
		department = "unknown"
	}
	privilege := "standard"
	if event.User.IsPrivileged {
		privilege = "privileged"
	}
	return department + "|" + privilege
}

func Evaluate(baseline *Baseline, peer *Baseline, event core.CanonicalEvent, volume VolumeStats,
	config Config, now time.Time) *core.UEBAAnomaly {
	if config.MinimumObservations < 1 {
		config = DefaultConfig()
	}
	ensureProfile(&baseline.Profile)
	ensureProfile(&peer.Profile)
	decayBaseline(baseline, now, config.TrainingWindowDays)
	decayBaseline(peer, now, config.TrainingWindowDays)
	values := ValuesForEvent(event)
	features := []core.UEBAFeatureEvidence{}
	noveltyCount := 0
	totalFeatures := 0
	if baseline.ObservationCount >= config.MinimumObservations {
		addNovel := func(code, field, value string, score int, counts map[string]int, explanation string) {
			if value == "" {
				return
			}
			totalFeatures++
			count := counts[value]
			frequency := float64(count) / float64(max(1, baseline.ObservationCount))
			if count == 0 {
				noveltyCount++
				features = append(features, core.UEBAFeatureEvidence{
					Code: code, Field: field, Value: value, Score: score,
					BaselineFrequency: frequency, Explanation: explanation,
				})
			}
		}
		addNovel("new_device", "device.hostname", values.Device, 55, baseline.Profile.Devices,
			"Device was not observed for this entity during the rolling training window.")
		addNovel("new_ip", "src_endpoint.ip", values.IP, 45, baseline.Profile.IPs,
			"Source IP was not observed for this entity during the rolling training window.")
		addNovel("new_country", "metadata.src_country", values.Country, 65, baseline.Profile.Countries,
			"Country was not observed for this entity during the rolling training window.")
		addNovel("new_asn", "metadata.src_asn", values.ASN, 55, baseline.Profile.ASNs,
			"ASN was not observed for this entity during the rolling training window.")
		if values.Process != "" {
			totalFeatures++
			entityCount := baseline.Profile.Processes[values.Process]
			peerCount := peer.Profile.Processes[values.Process]
			peerRare := peer.ObservationCount >= config.MinimumPeerSamples &&
				peerCount <= max(1, peer.ObservationCount/100)
			if entityCount == 0 && peerRare {
				noveltyCount++
				features = append(features, core.UEBAFeatureEvidence{
					Code: "rare_process", Field: "process.name", Value: values.Process, Score: 45,
					BaselineFrequency: float64(entityCount) / float64(max(1, baseline.ObservationCount)),
					Explanation:       "Process is new for the entity and rare in its peer group.",
				})
			}
		}
		if values.Destination != "" {
			totalFeatures++
			entityCount := baseline.Profile.Destinations[values.Destination]
			peerCount := peer.Profile.Destinations[values.Destination]
			peerRare := peer.ObservationCount >= config.MinimumPeerSamples &&
				peerCount <= max(1, peer.ObservationCount/100)
			if entityCount == 0 && peerRare {
				noveltyCount++
				features = append(features, core.UEBAFeatureEvidence{
					Code: "rare_destination", Field: "dst_endpoint", Value: values.Destination, Score: 50,
					BaselineFrequency: float64(entityCount) / float64(max(1, baseline.ObservationCount)),
					Explanation:       "Destination is new for the entity and rare in its peer group.",
				})
			}
		}
		addNovel("unusual_admin_action", "activity_name", values.AdminAction, 60,
			baseline.Profile.AdminActions,
			"Privileged activity was not observed for this identity during the rolling training window.")
		if values.Hour != "" {
			totalFeatures++
			count := baseline.Profile.Hours[values.Hour]
			frequency := float64(count) / float64(max(1, baseline.ObservationCount))
			if count == 0 || frequency < 0.02 {
				noveltyCount++
				features = append(features, core.UEBAFeatureEvidence{
					Code: "time_of_day_deviation", Field: "event_time", Value: values.Hour,
					Score: 35, BaselineFrequency: frequency,
					Explanation: "Event occurred in an hour rarely observed for this entity.",
				})
			}
		}
		if volume.Samples >= 8 && volume.CurrentCount >= 5 &&
			(volume.ZScore >= 3.5 || volume.RobustZScore >= 3.5) {
			totalFeatures++
			noveltyCount++
			features = append(features, core.UEBAFeatureEvidence{
				Code: "volume_anomaly", Field: "event_volume_15m",
				Value: fmt.Sprint(volume.CurrentCount), Score: 55,
				Explanation: fmt.Sprintf(
					"15-minute volume deviates from baseline (z=%.2f, robust_z=%.2f, median=%.2f).",
					volume.ZScore, volume.RobustZScore, volume.Median,
				),
			})
		}
	}
	updateDrift(baseline, noveltyCount, totalFeatures, config.MinimumObservations)
	updateBaseline(baseline, values, now, config.MaximumCardinality)
	updateBaseline(peer, values, now, config.MaximumCardinality)
	if len(features) == 0 {
		return nil
	}
	sort.SliceStable(features, func(i, j int) bool {
		if features[i].Score == features[j].Score {
			return features[i].Code < features[j].Code
		}
		return features[i].Score > features[j].Score
	})
	risk := features[0].Score + min(15, (len(features)-1)*5)
	risk = min(75, risk)
	if risk < config.MinimumRisk {
		return nil
	}
	confidence := min(95, 50+baseline.ObservationCount/5)
	severity := core.SeverityMedium
	if risk >= 60 {
		severity = core.SeverityHigh
	} else if risk < 40 {
		severity = core.SeverityLow
	}
	explanation := map[string]interface{}{
		"deterministic": true, "opaque_ml": false, "cold_start": false,
		"baseline_observations": baseline.ObservationCount, "peer_observations": peer.ObservationCount,
		"drift_score": baseline.DriftScore, "drift_status": baseline.DriftStatus,
		"volume_samples": volume.Samples, "volume_mean": volume.Mean, "volume_median": volume.Median,
		"volume_z_score": volume.ZScore, "volume_robust_z_score": volume.RobustZScore,
	}
	return &core.UEBAAnomaly{
		ID: core.NewID("uba"), TenantID: event.TenantID, EventID: event.ID,
		EntityType: baseline.EntityType, EntityID: baseline.EntityID, EntityName: baseline.EntityName,
		PeerGroup: baseline.PeerGroup,
		Title:     fmt.Sprintf("Behavior deviation for %s (%d explainable feature(s))", baseline.EntityName, len(features)),
		Severity:  severity, RiskScore: risk, Confidence: confidence, Features: features,
		Explanation: explanation, ModelVersion: ModelVersion, FeatureVersion: FeatureVersion,
		TrainingWindowDays:   config.TrainingWindowDays,
		BaselineObservations: baseline.ObservationCount, Status: core.UEBAAnomalyNew,
		Version: 1, CreatedAt: now, UpdatedAt: now,
	}
}

func ValuesForEvent(event core.CanonicalEvent) FeatureValues {
	device := normalizeValue(firstNonEmpty(event.Device.ID, event.Device.Hostname))
	ip := normalizeValue(firstNonEmpty(event.SrcEndpoint.IP, event.Device.IP))
	destination := normalizeValue(firstNonEmpty(event.DstEndpoint.Hostname, event.DstEndpoint.IP))
	action := ""
	if event.User.IsPrivileged {
		action = normalizeValue(firstNonEmpty(event.ActivityName, event.SecurityResult.Action))
	}
	return FeatureValues{
		Hour:   fmt.Sprintf("%02d", event.EventTime.UTC().Hour()),
		Device: device, IP: ip, Country: metadataString(event.Metadata, "src_country", "country"),
		ASN:     metadataString(event.Metadata, "src_asn", "asn"),
		Process: normalizeValue(event.Process.Name), Destination: destination, AdminAction: action,
	}
}

func ComputeVolumeStats(current int, historical []int) VolumeStats {
	result := VolumeStats{CurrentCount: current, Samples: len(historical)}
	if len(historical) == 0 {
		return result
	}
	values := append([]int(nil), historical...)
	sort.Ints(values)
	sum := 0.0
	for _, value := range values {
		sum += float64(value)
	}
	result.Mean = sum / float64(len(values))
	variance := 0.0
	for _, value := range values {
		delta := float64(value) - result.Mean
		variance += delta * delta
	}
	result.StdDev = math.Sqrt(variance / float64(len(values)))
	result.Median = medianInts(values)
	deviations := make([]float64, 0, len(values))
	for _, value := range values {
		deviations = append(deviations, math.Abs(float64(value)-result.Median))
	}
	sort.Float64s(deviations)
	result.MAD = medianFloats(deviations)
	if result.StdDev > 0 {
		result.ZScore = (float64(current) - result.Mean) / result.StdDev
	}
	if result.MAD > 0 {
		result.RobustZScore = (float64(current) - result.Median) / (1.4826 * result.MAD)
	} else if float64(current) > result.Median {
		result.RobustZScore = float64(current) - result.Median
	}
	return result
}

func updateBaseline(baseline *Baseline, values FeatureValues, now time.Time, maximum int) {
	if maximum < 1 {
		maximum = 256
	}
	incrementBounded(baseline.Profile.Hours, values.Hour, maximum)
	incrementBounded(baseline.Profile.Devices, values.Device, maximum)
	incrementBounded(baseline.Profile.IPs, values.IP, maximum)
	incrementBounded(baseline.Profile.Countries, values.Country, maximum)
	incrementBounded(baseline.Profile.ASNs, values.ASN, maximum)
	incrementBounded(baseline.Profile.Processes, values.Process, maximum)
	incrementBounded(baseline.Profile.Destinations, values.Destination, maximum)
	incrementBounded(baseline.Profile.AdminActions, values.AdminAction, maximum)
	baseline.ObservationCount++
	if baseline.FirstSeen.IsZero() {
		baseline.FirstSeen = now
	}
	if now.After(baseline.LastSeen) {
		baseline.LastSeen = now
	}
	baseline.ModelVersion = ModelVersion
	baseline.FeatureVersion = FeatureVersion
	baseline.UpdatedAt = now
}

func updateDrift(baseline *Baseline, novel, total, minimum int) {
	sample := 0.0
	if total > 0 {
		sample = float64(novel) / float64(total) * 100
	}
	baseline.DriftScore = math.Round((baseline.DriftScore*0.95+sample*0.05)*100) / 100
	switch {
	case baseline.ObservationCount < minimum:
		baseline.DriftStatus = "COLD_START"
	case baseline.DriftScore >= 30:
		baseline.DriftStatus = "DRIFTING"
	case baseline.DriftScore >= 15:
		baseline.DriftStatus = "WATCH"
	default:
		baseline.DriftStatus = "STABLE"
	}
}

func decayBaseline(baseline *Baseline, now time.Time, windowDays int) {
	if baseline.LastSeen.IsZero() || !now.After(baseline.LastSeen.Add(24*time.Hour)) {
		return
	}
	if windowDays < 1 {
		windowDays = 28
	}
	days := now.Sub(baseline.LastSeen).Hours() / 24
	factor := math.Exp(-days / float64(windowDays))
	scaleMap(baseline.Profile.Hours, factor)
	scaleMap(baseline.Profile.Devices, factor)
	scaleMap(baseline.Profile.IPs, factor)
	scaleMap(baseline.Profile.Countries, factor)
	scaleMap(baseline.Profile.ASNs, factor)
	scaleMap(baseline.Profile.Processes, factor)
	scaleMap(baseline.Profile.Destinations, factor)
	scaleMap(baseline.Profile.AdminActions, factor)
	baseline.ObservationCount = int(math.Round(float64(baseline.ObservationCount) * factor))
}

func incrementBounded(values map[string]int, value string, maximum int) {
	if value == "" {
		return
	}
	if _, exists := values[value]; !exists && len(values) >= maximum {
		victim := ""
		victimCount := math.MaxInt
		for key, count := range values {
			if count < victimCount || (count == victimCount && key < victim) {
				victim, victimCount = key, count
			}
		}
		delete(values, victim)
	}
	values[value]++
}

func scaleMap(values map[string]int, factor float64) {
	for key, count := range values {
		scaled := int(math.Round(float64(count) * factor))
		if scaled < 1 {
			delete(values, key)
		} else {
			values[key] = scaled
		}
	}
}

func ensureProfile(profile *Profile) {
	empty := NewProfile()
	if profile.Hours == nil {
		profile.Hours = empty.Hours
	}
	if profile.Devices == nil {
		profile.Devices = empty.Devices
	}
	if profile.IPs == nil {
		profile.IPs = empty.IPs
	}
	if profile.Countries == nil {
		profile.Countries = empty.Countries
	}
	if profile.ASNs == nil {
		profile.ASNs = empty.ASNs
	}
	if profile.Processes == nil {
		profile.Processes = empty.Processes
	}
	if profile.Destinations == nil {
		profile.Destinations = empty.Destinations
	}
	if profile.AdminActions == nil {
		profile.AdminActions = empty.AdminActions
	}
}

func metadataString(metadata map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		switch value := metadata[key].(type) {
		case string:
			if normalized := normalizeValue(value); normalized != "" {
				return normalized
			}
		case float64:
			return fmt.Sprintf("%.0f", value)
		case int:
			return fmt.Sprint(value)
		}
	}
	return ""
}

func normalizeValue(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func medianInts(values []int) float64 {
	if len(values)%2 == 1 {
		return float64(values[len(values)/2])
	}
	return float64(values[len(values)/2-1]+values[len(values)/2]) / 2
}

func medianFloats(values []float64) float64 {
	if len(values)%2 == 1 {
		return values[len(values)/2]
	}
	return (values[len(values)/2-1] + values[len(values)/2]) / 2
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
