package mitre

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/kcsp/platform/internal/core"
	"github.com/kcsp/platform/internal/store"
)

const (
	StatusCovered = "COVERED"
	StatusPartial = "PARTIAL"
	StatusGap     = "GAP"
)

type Repository interface {
	ListRules(context.Context) ([]core.DetectionRule, error)
	PublishedDetectionContent(context.Context, string) ([]core.DetectionContent, error)
	ListCollectors(context.Context, string) ([]core.Collector, error)
	ListIncidents(context.Context, string, store.IncidentFilter) ([]core.Incident, error)
}

type Service struct{ repository Repository }

func NewService(repository Repository) *Service { return &Service{repository: repository} }

type catalogEntry struct {
	ID      string
	Name    string
	Tactics []string
}

var enterpriseBaseline = []catalogEntry{
	{"T1078", "Valid Accounts", []string{"Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"}},
	{"T1190", "Exploit Public-Facing Application", []string{"Initial Access"}},
	{"T1136", "Create Account", []string{"Persistence"}},
	{"T1098", "Account Manipulation", []string{"Persistence", "Privilege Escalation"}},
	{"T1547.001", "Registry Run Keys / Startup Folder", []string{"Persistence", "Privilege Escalation"}},
	{"T1059.001", "PowerShell", []string{"Execution"}},
	{"T1047", "Windows Management Instrumentation", []string{"Execution"}},
	{"T1204", "User Execution", []string{"Execution"}},
	{"T1055", "Process Injection", []string{"Privilege Escalation", "Defense Evasion"}},
	{"T1562.001", "Impair Defenses", []string{"Defense Evasion"}},
	{"T1218", "System Binary Proxy Execution", []string{"Defense Evasion"}},
	{"T1027", "Obfuscated Files or Information", []string{"Defense Evasion"}},
	{"T1110", "Brute Force", []string{"Credential Access"}},
	{"T1003", "OS Credential Dumping", []string{"Credential Access"}},
	{"T1087", "Account Discovery", []string{"Discovery"}},
	{"T1018", "Remote System Discovery", []string{"Discovery"}},
	{"T1082", "System Information Discovery", []string{"Discovery"}},
	{"T1021", "Remote Services", []string{"Lateral Movement"}},
	{"T1570", "Lateral Tool Transfer", []string{"Lateral Movement"}},
	{"T1560", "Archive Collected Data", []string{"Collection"}},
	{"T1114", "Email Collection", []string{"Collection"}},
	{"T1071", "Application Layer Protocol", []string{"Command and Control"}},
	{"T1105", "Ingress Tool Transfer", []string{"Command and Control"}},
	{"T1041", "Exfiltration Over C2 Channel", []string{"Exfiltration"}},
	{"T1048", "Exfiltration Over Alternative Protocol", []string{"Exfiltration"}},
	{"T1486", "Data Encrypted for Impact", []string{"Impact"}},
	{"T1490", "Inhibit System Recovery", []string{"Impact"}},
}

var tacticIDs = map[string]string{
	"Reconnaissance": "TA0043", "Resource Development": "TA0042", "Initial Access": "TA0001", "Execution": "TA0002",
	"Persistence": "TA0003", "Privilege Escalation": "TA0004", "Defense Evasion": "TA0005", "Credential Access": "TA0006",
	"Discovery": "TA0007", "Lateral Movement": "TA0008", "Collection": "TA0009", "Command and Control": "TA0011",
	"Exfiltration": "TA0010", "Impact": "TA0040", "Uncategorized": "KCSP-UNCATEGORIZED",
}

func (s *Service) Coverage(ctx context.Context, tenantID string) (core.MITRECoverageReport, error) {
	rules, err := s.repository.ListRules(ctx)
	if err != nil {
		return core.MITRECoverageReport{}, err
	}
	published, err := s.repository.PublishedDetectionContent(ctx, tenantID)
	if err != nil {
		return core.MITRECoverageReport{}, err
	}
	collectors, err := s.repository.ListCollectors(ctx, tenantID)
	if err != nil {
		return core.MITRECoverageReport{}, err
	}
	incidents, err := s.repository.ListIncidents(ctx, tenantID, store.IncidentFilter{Limit: 1000})
	if err != nil {
		return core.MITRECoverageReport{}, err
	}

	rulesByID := map[string]core.DetectionRule{}
	for _, rule := range rules {
		if strings.EqualFold(rule.State, "PUBLISHED") || rule.State == "" {
			rulesByID[rule.ID] = rule
		}
	}
	for _, content := range published {
		if content.Rule.ID != "" {
			rulesByID[content.Rule.ID] = content.Rule
		}
	}
	available, activeCollectors := collectorCapabilities(collectors)
	techniques := map[string]*core.MITRETechniqueCoverage{}
	for _, entry := range enterpriseBaseline {
		techniques[entry.ID] = &core.MITRETechniqueCoverage{TechniqueID: entry.ID, Name: entry.Name, Tactics: append([]string(nil), entry.Tactics...), Rules: []core.MITRERuleSummary{}, DataSources: []core.MITREDataSourceStatus{}, MissingDataSources: []string{}}
	}
	for _, rule := range rulesByID {
		for _, techniqueID := range rule.MITRE {
			techniqueID = normalizeTechniqueID(techniqueID)
			if techniqueID == "" {
				continue
			}
			technique := ensureTechnique(techniques, techniqueID)
			technique.Rules = append(technique.Rules, core.MITRERuleSummary{RuleID: rule.ID, Title: rule.Title, Version: rule.Version, Severity: rule.Severity, Confidence: rule.Confidence})
			for _, required := range rule.RequiredDataSources {
				if !containsFold(techniqueDataSourceNames(technique.DataSources), required) {
					matchedCollectors := matchingCollectors(required, available)
					technique.DataSources = append(technique.DataSources, core.MITREDataSourceStatus{Name: required, Available: len(matchedCollectors) > 0, Collectors: matchedCollectors})
				}
			}
		}
	}
	for _, incident := range incidents {
		for _, techniqueID := range incident.MITRE {
			techniqueID = normalizeTechniqueID(techniqueID)
			if techniqueID == "" {
				continue
			}
			technique := ensureTechnique(techniques, techniqueID)
			previous := technique.IncidentCount
			technique.IncidentCount++
			technique.AverageRisk = ((technique.AverageRisk * previous) + incident.RiskScore) / technique.IncidentCount
			if incident.RiskScore > technique.MaximumRisk {
				technique.MaximumRisk = incident.RiskScore
			}
		}
	}

	report := core.MITRECoverageReport{Framework: "MITRE ATT&CK Enterprise", CatalogVersion: "KCSP enterprise baseline 2026.1", Techniques: []core.MITRETechniqueCoverage{}, Tactics: []core.MITRETacticCoverage{}, PublishedRules: len(rulesByID), ActiveCollectors: activeCollectors, IncidentCount: len(incidents), GeneratedAt: time.Now().UTC()}
	for _, technique := range techniques {
		sort.Slice(technique.Rules, func(i, j int) bool { return technique.Rules[i].RuleID < technique.Rules[j].RuleID })
		for _, source := range technique.DataSources {
			if !source.Available {
				technique.MissingDataSources = append(technique.MissingDataSources, source.Name)
			}
		}
		switch {
		case len(technique.Rules) == 0:
			technique.Status = StatusGap
			report.CoverageGaps++
		case len(technique.MissingDataSources) > 0:
			technique.Status = StatusPartial
			report.PartialTechniques++
		default:
			technique.Status = StatusCovered
			report.CoveredTechniques++
		}
		report.Techniques = append(report.Techniques, *technique)
	}
	sort.Slice(report.Techniques, func(i, j int) bool { return report.Techniques[i].TechniqueID < report.Techniques[j].TechniqueID })
	report.TotalTechniques = len(report.Techniques)
	if report.TotalTechniques > 0 {
		report.CoveragePercent = (report.CoveredTechniques*100 + report.PartialTechniques*50) / report.TotalTechniques
	}
	report.Tactics = tacticCoverage(report.Techniques)
	return report, nil
}

func ensureTechnique(techniques map[string]*core.MITRETechniqueCoverage, id string) *core.MITRETechniqueCoverage {
	if technique, ok := techniques[id]; ok {
		return technique
	}
	technique := &core.MITRETechniqueCoverage{TechniqueID: id, Name: "Tenant-mapped technique", Tactics: []string{"Uncategorized"}, Rules: []core.MITRERuleSummary{}, DataSources: []core.MITREDataSourceStatus{}, MissingDataSources: []string{}}
	techniques[id] = technique
	return technique
}

func collectorCapabilities(collectors []core.Collector) (map[string][]string, int) {
	available := map[string][]string{}
	active := 0
	for _, collector := range collectors {
		if strings.EqualFold(collector.State, "DISABLED") {
			continue
		}
		active++
		values := append([]string{collector.Type, collector.Name}, collector.Capabilities...)
		for _, value := range values {
			key := normalizeSource(value)
			if key != "" && !containsFold(available[key], collector.Name) {
				available[key] = append(available[key], collector.Name)
			}
		}
	}
	return available, active
}

func matchingCollectors(required string, available map[string][]string) []string {
	requiredKey := normalizeSource(required)
	result := []string{}
	for capability, collectors := range available {
		matched := strings.Contains(requiredKey, capability) || strings.Contains(capability, requiredKey)
		if !matched && strings.Contains(requiredKey, "windowsprocesscreation") {
			matched = strings.Contains(capability, "sysmon") || strings.Contains(capability, "windows")
		}
		if !matched && (requiredKey == "ad" || strings.Contains(requiredKey, "activedirectory")) {
			matched = capability == "ad" || strings.Contains(capability, "activedirectory") || strings.Contains(capability, "windows")
		}
		if matched {
			for _, collector := range collectors {
				if !containsFold(result, collector) {
					result = append(result, collector)
				}
			}
		}
	}
	sort.Strings(result)
	return result
}

func tacticCoverage(techniques []core.MITRETechniqueCoverage) []core.MITRETacticCoverage {
	byName := map[string]*core.MITRETacticCoverage{}
	for _, technique := range techniques {
		for _, tactic := range technique.Tactics {
			item := byName[tactic]
			if item == nil {
				item = &core.MITRETacticCoverage{TacticID: tacticIDs[tactic], Name: tactic}
				byName[tactic] = item
			}
			item.Techniques++
			switch technique.Status {
			case StatusCovered:
				item.Covered++
			case StatusPartial:
				item.Partial++
			default:
				item.Gaps++
			}
		}
	}
	items := []core.MITRETacticCoverage{}
	for _, item := range byName {
		if item.Techniques > 0 {
			item.Coverage = (item.Covered*100 + item.Partial*50) / item.Techniques
		}
		items = append(items, *item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].TacticID < items[j].TacticID })
	return items
}

func normalizeTechniqueID(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if index := strings.Index(value, "T"); index >= 0 {
		value = value[index:]
	}
	if len(value) < 5 || value[0] != 'T' {
		return ""
	}
	end := 1
	for end < len(value) && ((value[end] >= '0' && value[end] <= '9') || value[end] == '.') {
		end++
	}
	value = value[:end]
	if len(value) < 5 {
		return ""
	}
	return value
}

func normalizeSource(value string) string {
	value = strings.ToLower(value)
	return strings.NewReplacer(" ", "", "-", "", "_", "", "/", "", ".", "").Replace(value)
}

func containsFold(values []string, wanted string) bool {
	for _, value := range values {
		if strings.EqualFold(value, wanted) {
			return true
		}
	}
	return false
}

func techniqueDataSourceNames(values []core.MITREDataSourceStatus) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.Name)
	}
	return result
}
