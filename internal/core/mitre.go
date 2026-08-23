package core

import "time"

type MITRERuleSummary struct {
	RuleID     string   `json:"rule_id"`
	Title      string   `json:"title"`
	Version    string   `json:"version"`
	Severity   Severity `json:"severity"`
	Confidence int      `json:"confidence"`
}

type MITREDataSourceStatus struct {
	Name       string   `json:"name"`
	Available  bool     `json:"available"`
	Collectors []string `json:"collectors"`
}

type MITRETechniqueCoverage struct {
	TechniqueID        string                  `json:"technique_id"`
	Name               string                  `json:"name"`
	Tactics            []string                `json:"tactics"`
	Status             string                  `json:"status"`
	Rules              []MITRERuleSummary      `json:"rules"`
	DataSources        []MITREDataSourceStatus `json:"data_sources"`
	MissingDataSources []string                `json:"missing_data_sources"`
	IncidentCount      int                     `json:"incident_count"`
	AverageRisk        int                     `json:"average_risk"`
	MaximumRisk        int                     `json:"maximum_risk"`
}

type MITRETacticCoverage struct {
	TacticID   string `json:"tactic_id"`
	Name       string `json:"name"`
	Techniques int    `json:"techniques"`
	Covered    int    `json:"covered"`
	Partial    int    `json:"partial"`
	Gaps       int    `json:"gaps"`
	Coverage   int    `json:"coverage_percent"`
}

type MITRECoverageReport struct {
	Framework         string                   `json:"framework"`
	CatalogVersion    string                   `json:"catalog_version"`
	Techniques        []MITRETechniqueCoverage `json:"techniques"`
	Tactics           []MITRETacticCoverage    `json:"tactics"`
	TotalTechniques   int                      `json:"total_techniques"`
	CoveredTechniques int                      `json:"covered_techniques"`
	PartialTechniques int                      `json:"partial_techniques"`
	CoverageGaps      int                      `json:"coverage_gaps"`
	CoveragePercent   int                      `json:"coverage_percent"`
	PublishedRules    int                      `json:"published_rules"`
	ActiveCollectors  int                      `json:"active_collectors"`
	IncidentCount     int                      `json:"incident_count"`
	GeneratedAt       time.Time                `json:"generated_at"`
}
