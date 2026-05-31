# Wazuh Rule Generator

## Overview

**Wazuh Rule Generator** is a Python utility that automatically generates Wazuh Security Monitoring rules for detection of common security events, authentication failures, file integrity changes, privilege escalation attempts, and more.

It allows you to quickly create detection rules from predefined patterns, command-line arguments, or configuration files without manual XML writing.

## Features

- **Quick rule generation** - Pre-built rule templates for common scenarios
- **Pattern-based generation** - Convert log patterns into Wazuh rules
- **Categorized rules** - Organize rules by category (syslog, audit, file_integrity, etc.)
- **Config file support** - Load settings from JSON configuration
- **Batch mode** - Generate multiple rules from a list
- **Output options** - Save to file or print to stdout
- **Level customization** - Set detection severity levels per rule

## Installation

No external dependencies required beyond Python 3.x:

```bash
# Ensure yaml is available (optional)
pip install pyyaml

# Optional for rich output
pip install pygments
```

## Quick Start

### Generate All 28 Categories

```bash
# Generate all quick rules for all categories
python wazuh_rule_generator.py -q -o quick_rules.txt

# Or use the extended rules file
python wazuh_rule_generator.py -q -o quick_rules.txt

# For 28 categories
python wazuh_rule_generator.py -q -o all_rules_28.txt
```
- Network intrusion (level 1)
- SQL injection (level 1)
- Phishing attempt (level 1)
- DNS tunneling (level 1)
- Proxy abuse (level 1)
- Malware detected (level 1)
- Process injection (level 1)
- Failed auth (level 1)
- Port scan (level 1)
- VPN breach (level 1)
- Zero-day attack (level 1)
- Malicious file (level 1)
- Compliance violation (level 2)
- SIEM alert (level 3)
- Threat intel (level 1)
- Suspicious user (level 2)

### Generate from Patterns

```bash
# Generate rules from pattern file
python wazuh_rule_generator.py -p -o rules.txt

# Or programmatically
python -c "
import wazuh_rule_generator
generator = wazuh_rule_generator.WazuhRuleGenerator()
rule = generator.generate_from_pattern('syslog:authentication failure; hostname=any', 'output.txt')
print(rule)
"
```

### Generate Custom Rules

```python
import wazuh_rule_generator

generator = wazuh_rule_generator.WazuhRuleGenerator()

# Generate a custom rule
rule = generator.generate_rule(
    category='syslog',
    title='Authentication Failure',
    username='* authentication',
    level='1',
    description='Detect failed authentication attempts'
)

print(rule)
```

### Command Line Options

```bash
python wazuh_rule_generator.py -h
```

**Available options:**
| Option | Description |
|--------|-----------|
| `-c CATEGORY` | Rule category (default: syslog) |
| `-r RULE` | Rule specification |
| `-o OUTPUT` | Output file (default: rules.txt) |
| `-w` | Write to output file |
| `-p` | Generate from patterns file |
| `-q` | Generate quick rules |
| `-C CATEGORY` | Rule category (alternative syntax) |

## Usage Examples

### Example 1: Generate Multiple Quick Rules

```python
import wazuh_rule_generator

generator = wazuh_rule_generator.WazuhRuleGenerator()

configs = [
    {'category': 'syslog', 'title': 'Auth failure', 'username': '* authentication', 'level': '1'},
    {'category': 'file_integrity', 'title': 'File modification', 'path': '* mod', 'level': '1'},
    {'category': 'syslog', 'title': 'Brute force', 'username': '* failed password', 'level': '1'},
]

rules = [generator.generate_rule(**c) for c in configs]

with open('wazuh_quick_rules.txt', 'w') as f:
    for rule in rules:
        f.write(rule + '\n')

print(f'Generated {len(rules)} rules')
```

### Example 2: Generate from Pattern String

```python
generator = wazuh_rule_generator.WazuhRuleGenerator()

pattern = 'syslog:authentication failure; hostname=any; level=1'
rule = generator.generate_from_pattern(pattern, 'output.txt')
print(rule)
```

### Example 3: Load Configuration

```json
// config.json
{
    "rule_id_start": 10050,
    "level": "2",
    "categories": ["syslog", "audit", "file_integrity"]
}
```

```python
generator = wazuh_rule_generator.WazuhRuleGenerator(config_file='config.json')
```

### Example 4: Batch Rule Generation

```python
configs = [
    {'category': 'syslog', 'title': 'Rule 1', 'username': 'user1', 'level': '3'},
    {'category': 'syslog', 'title': 'Rule 2', 'username': 'user2', 'level': '2'},
]

generator.batch_mode = True
for config in configs:
    generator.add_batch_rule(config)

generator.generate_batch(configs, 'batch_rules.txt')
```

## Full Category List (28 categories)

| # | Category | Fields |
|---|---|---|
| 1 | syslog | hostname, username, remote_addr, path, user, category |
| 2 | audit | user, user_sid, target_sid, path, category |
| 3 | file_integrity | path, user |
| 4 | command/windows | hostname, user |
| 5 | command/bash | hostname, user |
| 6 | registry | path, user |
| 7 | network | remote_addr, destination, protocol, category |
| 8 | database | connection, user, db_name, operation |
| 9 | email | sender, receiver, subject, status |
| 10 | dns | query, response, status |
| 11 | proxy | url, method, status, user |
| 12 | antivirus | file, status, detection |
| 13 | endpoint | process, path, command, user |
| 14 | authentication | username, method, status, timestamp |
| 15 | firewall | source, destination, port, action |
| 16 | vpn | client, server, protocol, status |
| 17 | ids | signature, severity, category, source |
| 18 | iocs | malware, hash, behavior, threat |
| 19 | compliance | control, standard, status, result |
| 20 | siem_events | event_type, severity, category, source |
| 21 | threat_intel | indicator, source, confidence, action |
| 22 | user_activity | user, action, resource, time |
| 23 | process_monitoring | pid, name, parent, user |
| 24 | logon | type, status, method, location |
| 25 | file_ops | action, path, user, time |
| 26 | registry_ops | action, key, user, time |
| 27 | scheduled_tasks | task_name, status, schedule, user |
| 28 | service_monitoring | service, status, start_time, user |

## Default Rule Template

```xml
<rule id="{rule_id}">
<title>{title}</title>
<level>{level}</level>
<if>{fields}</if>
<description>{description}</description>
<date>{generation_date}</date>
<rule_name>{title}</rule_name>
</rule>
```

## Configuration File Format

### JSON Config Example

```json
{
    "rule_id_start": 10050,
    "level": "2",
    "categories": [
        "syslog",
        "audit", 
        "file_integrity"
    ]
}
```

### Supported Formats

- .json files (JSON load)
- .yaml / .yml files (simple key=value parsing)

## Pattern Syntax

Patterns support these prefixes:

| Prefix | Category | Example |
|--------|----------|---------|
| syslog: | syslog | syslog:authentication failure |
| file: | file_integrity | file:path=/etc/passwd |
| malware: | malware | malware:root access |
| command/windows: | command/windows | command/windows:execution |
| command/bash: | command/bash | command/bash:command execution |

### Pattern Parameters

pattern: [CATEGORY[:]]TITLE; [PARAMETER=value;][PARAMETER2=value;...]

Examples:
- syslog:authentication failure; hostname=any; level=1
- file_integrity:modification; path=* mod
- malware:root access; category=malware; level=1

## Advanced Features

### Batch Mode

```python
generator = wazuh_rule_generator.WazuhRuleGenerator()
generator.batch_mode = True

for config in configs:
    generator.add_batch_rule(config)

generator.generate_batch(configs, 'output.txt')
```

### Save Rules to File

```python
with open('rules.txt', 'w') as f:
    for rule in rules:
        f.write(rule + '\n')
```

### Stats Tracking

```python
print(f'Rules generated: {generator.stats["rules_generated"]}')
print(f'Errors: {generator.stats["errors"]}')
```

## Troubleshooting

### Common Issues

1. **No modules found**: Ensure Python is in PATH and module files are correct

2. **Module not found**: Check Python installation and add to PATH

3. **AttributeError**: Check imports and module versions

### Debug Mode

```bash
python wazuh_rule_generator.py
```

Run without arguments to see help and default usage.

## Output Examples

### Quick Rule Output

```xml
<rule id="10001">
<title>Auth failure</title>
<level>1</level>
<if>username=* authentication category=syslog </if>
<description># Auth failure</description>
<date>2026-05-31</date>
<rule_name>Auth failure</rule_name>
</rule>
```

### Pattern Rule Output

```xml
<rule id="10001">
<title>Authentication failure</title>
<level>1</level>
<if>username='* authentication' category='file_integrity' </if>
<description># Authentication failure</description>
<date>2026-05-31</date>
<rule_name>Authentication failure</rule_name>
</rule>
```

## Contributing

1. Fix bugs: Report issues or submit pull requests
2. Improve patterns: Add new pattern detection rules
3. Add categories: Extend supported Wazuh categories

## License

MIT License - Feel free to use and modify for your security operations needs.

## Examples Folder

Examples and sample rules are located in the examples/ directory.

## Support

For issues or questions:
- Open an issue
- Check the examples in this repository
- Review the code documentation

## Changelog

### Version 1.0
- Initial release
- Quick rule generation
- Pattern-based generation
- Command-line interface
- Config file support
- Batch mode

---

Built with love for security operations

Created by Dr. Abhirup Guha