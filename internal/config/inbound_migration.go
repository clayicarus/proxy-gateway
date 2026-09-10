package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

const migratedHysteria2InboundName = "hy2-public"
const migratedTrojanInboundName = "trojan-public"

// MigrationResult contains validated YAML and non-sensitive diagnostics.
type MigrationResult struct {
	YAML        []byte
	Diagnostics []string
}

type legacyInboundConfig struct {
	Listen               string                `yaml:"listen"`
	TLS                  TLSConfig             `yaml:"tls"`
	Obfs                 *ObfsConfig           `yaml:"obfs,omitempty"`
	QUIC                 *QUICConfig           `yaml:"quic,omitempty"`
	Users                map[string]UserConfig `yaml:"users"`
	Nodes                map[string]NodeConfig `yaml:"nodes"`
	API                  APIConfig             `yaml:"api"`
	Admin                AdminConfig           `yaml:"admin,omitempty"`
	Sub                  *SubConfig            `yaml:"sub,omitempty"`
	Masquerade           *MasqueradeConfig     `yaml:"masquerade,omitempty"`
	Trojan               *legacyTrojanConfig   `yaml:"trojan,omitempty"`
	DBPath               string                `yaml:"dbPath,omitempty"`
	TrafficFlushInterval time.Duration         `yaml:"trafficFlushInterval,omitempty"`
	Timezone             string                `yaml:"timezone,omitempty"`
	Systemd              *SystemdConfig        `yaml:"systemd,omitempty"`
}

type legacyTrojanConfig struct {
	Listen     string `yaml:"listen,omitempty"`
	ServerAddr string `yaml:"serverAddr,omitempty"`
	SNI        string `yaml:"sni,omitempty"`
	Insecure   bool   `yaml:"insecure,omitempty"`
}

// MigrateLegacyInbounds converts a supported legacy YAML document entirely in
// memory and validates the generated document against the strict new schema.
func MigrateLegacyInbounds(data []byte) (*MigrationResult, error) {
	var root yaml.Node
	if err := decodeStrictSingleDocument(data, &root); err != nil {
		return nil, fmt.Errorf("invalid legacy config: %w", err)
	}
	if hasTopLevelKey(&root, "inbounds") {
		return nil, fmt.Errorf("input uses the new inbounds schema; expected a legacy config")
	}
	if hasTopLevelKey(&root, "obfs") {
		return nil, fmt.Errorf("legacy field obfs is unsupported and cannot be migrated")
	}
	if hasTopLevelKey(&root, "masquerade") {
		return nil, fmt.Errorf("legacy field masquerade is unsupported and cannot be migrated")
	}

	var legacy legacyInboundConfig
	if err := decodeStrictSingleDocument(data, &legacy); err != nil {
		return nil, fmt.Errorf("invalid legacy config: %w", err)
	}
	if len(legacy.Users) != 0 || len(legacy.Nodes) != 0 {
		return nil, fmt.Errorf("legacy users/nodes contain management data; migrate management data first")
	}
	if legacy.API.Secret != "" || (legacy.Sub != nil && legacy.Sub.Secret != "") {
		return nil, fmt.Errorf("legacy subscription secret contains management data; migrate management data first")
	}
	if legacy.Sub != nil && legacy.Sub.ServerAddr == "" {
		return nil, fmt.Errorf("sub.serverAddr must be configured; migration will not infer it from listen")
	}

	listen := legacy.Listen
	if listen == "" {
		listen = ":443"
	}
	output := InboundConfig{
		Inbounds: []Inbound{{
			Name:   migratedHysteria2InboundName,
			Type:   Hysteria2InboundType,
			Listen: listen,
			QUIC:   legacy.QUIC,
		}},
		TLS:                  legacy.TLS,
		Admin:                legacy.Admin,
		DBPath:               legacy.DBPath,
		TrafficFlushInterval: legacy.TrafficFlushInterval,
		Timezone:             legacy.Timezone,
		Systemd:              legacy.Systemd,
	}

	result := &MigrationResult{}
	if legacy.Trojan != nil && legacy.Trojan.Listen != "" {
		output.Inbounds = append(output.Inbounds, Inbound{
			Name:   migratedTrojanInboundName,
			Type:   TrojanInboundType,
			Listen: legacy.Trojan.Listen,
		})
		if legacy.Trojan.ServerAddr != "" || legacy.Trojan.SNI != "" || legacy.Trojan.Insecure {
			result.Diagnostics = append(result.Diagnostics, "legacy Trojan subscription metadata was not migrated because Trojan subscription generation is unavailable")
		}
	}
	if output.Admin.Listen == "" {
		output.Admin.Listen = legacy.API.Listen
	} else if legacy.API.Listen != "" && legacy.API.Listen != output.Admin.Listen {
		result.Diagnostics = append(result.Diagnostics, "admin.listen takes precedence; conflicting api.listen was not migrated")
	}
	if legacy.Sub != nil {
		output.Sub = &InboundSubConfig{
			Listen:     legacy.Sub.Listen,
			PublicURL:  legacy.Sub.PublicURL,
			Inbound:    migratedHysteria2InboundName,
			ServerAddr: legacy.Sub.ServerAddr,
			SNI:        legacy.Sub.SNI,
			Insecure:   legacy.Sub.Insecure,
		}
	}

	generated, err := yaml.Marshal(&output)
	if err != nil {
		return nil, fmt.Errorf("failed to encode migrated config: %w", err)
	}
	if _, err := ParseInboundConfig(generated); err != nil {
		return nil, fmt.Errorf("generated config failed validation: %w", err)
	}
	result.YAML = generated
	return result, nil
}

// MigrateLegacyInboundsFile writes a validated migration result using
// exclusive creation. A failed write removes only the newly created output.
func MigrateLegacyInboundsFile(inputPath, outputPath string) ([]string, error) {
	if inputPath == "" || outputPath == "" {
		return nil, fmt.Errorf("both input and output paths are required")
	}
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read input: %w", err)
	}
	result, err := MigrateLegacyInbounds(data)
	if err != nil {
		return nil, err
	}

	file, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("failed to create output exclusively: %w", err)
	}
	removeOutput := true
	defer func() {
		if removeOutput {
			_ = os.Remove(outputPath)
		}
	}()
	written, err := file.Write(result.YAML)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("failed to write output: %w", err)
	}
	if written != len(result.YAML) {
		_ = file.Close()
		return nil, fmt.Errorf("failed to write output: short write")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("failed to sync output: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("failed to close output: %w", err)
	}
	removeOutput = false
	return result.Diagnostics, nil
}

func hasTopLevelKey(root *yaml.Node, key string) bool {
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		root = root.Content[0]
	}
	if root.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == key {
			return true
		}
	}
	return false
}
