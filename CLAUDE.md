# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the UTMStack Correlation Rules repository (v11), which contains YAML-based correlation rules and filters for security event processing. The project follows a modular architecture where each technology/platform has its own directory for storing rules and filters.

## Project Structure

The repository contains 26 directories, each representing a different technology or platform:
- antivirus, aws, azure, cisco, deceptivebytes, filebeat, fortinet, generic, github, google, hids, ibm, json, linux, macos, mikrotik, netflow, nids, office365, paloalto, pfsense, sonicwall, sophos, syslog, vmware, windows

Each directory should contain:
- YAML rule files for threat detection
- YAML filter files for log parsing and transformation

## Key Concepts

### Rules
Rules are YAML files that define security threat detection logic. They are used by the analysis plugin to generate alerts when specific conditions are met.

Rule structure:
```yaml
- id: <unique_id>
  dataTypes: [<data_type>]
  name: <rule_name>
  description: <description>
  where: <CEL_expression>
  confidentiality: <low|medium|high>
  integrity: <low|medium|high>
  availability: <low|medium|high>
```

### Filters
Filters are YAML files that define how to parse, extract, and transform raw log data. They use a pipeline of steps to process events.

Filter structure:
```yaml
pipeline:
  - dataTypes: [<data_type>]
    steps:
      - <step_type>:
          <step_parameters>
```

Common step types include: json, grok, rename, cast, add, delete, trim, reformat, expand, kv, csv, dynamic

## Architecture Context

This repository is part of the ThreatWinds EventProcessor and UTMStack ecosystem:
- **EventProcessor**: Core engine that processes security events using a plugin-based architecture
- **Plugins communicate via gRPC over Unix sockets**
- **Rules and filters are loaded by respective plugins** to process events

## Development Guidelines

1. **Rule files should be placed in the appropriate technology directory**
2. **Filter files should be placed in the same directory as their corresponding rules**
3. **Use CEL (Common Expression Language) for rule conditions**
4. **Test rules and filters with real event data before deployment**
5. **Follow existing naming conventions and file structures**

## No Build/Test Commands

This repository contains only YAML configuration files. There are no build, test, or lint commands required. The YAML files are loaded and validated by the EventProcessor at runtime.