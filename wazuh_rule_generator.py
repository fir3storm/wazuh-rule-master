#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import argparse
import logging
import datetime as dt
from typing import Optional, List, Dict
from pathlib import Path
import json

class WazuhRuleGenerator:
    WAZUH_FIELDS = {
        'hostname': 'Hostname', 'username': 'Username', 
        'remote_addr': 'Remote', 'path': 'Path', 'user': 'User',
        'category': 'Category',
    }
    FIELD_DEFINITIONS = {
        'syslog': ['hostname', 'username', 'remote_addr', 'path', 'user', 'category'],
        'audit': ['user', 'user_sid', 'target_sid', 'path', 'category'],
        'file_integrity': ['path', 'user'],
        'command/windows': ['hostname', 'user'],
        'command/bash': ['hostname', 'user'],
        'registry': ['path', 'user'],
    }
    RULE_ID_OFFSET = 10001
    CATEGORY_PREFIXES = {
        'syslog': 'syslog', 'audit': 'audit', 'bash': 'command/bash',
        'powershell': 'command/powershell', 'file_integrity': 'file_integrity',
        'registry': 'registry', 'scheduled_scan': 'scheduled_scan',
    }
    DEFAULT_LEVEL = '3'
    DATE_FMT = '%Y-%m-%d'
    RULE_TEMPLATE = '''<rule id=\"{rule_id}\">
<title>{title}</title>
<level>{level}</level>
<if>{fields}</if>
<description>{description}</description>
<date>{generation_date}</date>
<rule_name>{title}</rule_name>
</rule>'''

    def __init__(self, config_file=None):
        self.rule_id_offset = 10001
        self.categories = list(self.CATEGORY_PREFIXES.keys())
        self.config_file = config_file
        self.logger = self._setup_logging()
        self.stats = {'rules_generated': 0, 'bytes_processed': 0, 'errors': 0}
        self.batch_mode = False
        self.batch_rules = []
        self._load_config(config_file)

    def _setup_logging(self):
        logger = logging.getLogger('WazuhRuleGenerator')
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def _load_config(self, config_file):
        if config_file:
            try:
                path = Path(config_file)
                if path.exists():
                    self.logger.info('Loading from ' + config_file)
                    if path.suffix.lower() in ['.json']:
                        self._parse_config_json(path)
            except Exception as e:
                self.logger.error('Error loading config ' + config_file + ': ' + str(e))

    def _parse_config_json(self, path):
        try:
            with open(path) as f:
                c = json.load(f)
                if 'rule_id_start' in c:
                    self.rule_id_offset = c['rule_id_start']
        except Exception:
            pass

    def _parse_config_yaml(self, path):
        try:
            text = open(path).read()
            for line in text.splitlines():
                if line.strip().startswith('rule_id_start='):
                    try:
                        self.rule_id_offset = int(line.split('=')[1])
                    except:
                        pass
        except Exception:
            pass

    def add_batch_rule(self, config):
        if self.batch_mode:
            self.batch_rules.append(config)
        self._process_rule_config(config)

    def _process_rule_config(self, config, immediate=True):
        rule = self.generate_rule(**config)
        if immediate or not self.batch_rules:
            self.stats['rules_generated'] += 1
            return rule
        return rule

    def generate_rule(self, title='', **kwargs):
        title = kwargs.pop('title', title)
        if not title:
            raise ValueError('Title required')
        rule_id = str(kwargs.get('rule_id', self.rule_id_offset))
        cat = kwargs.get('category', 'syslog')
        level = str(kwargs.get('level', self.DEFAULT_LEVEL))
        fields = ''
        for fn, d in self.WAZUH_FIELDS.items():
            v = kwargs.get(fn, None)
            if v:
                fields += fn + '=' + str(v) + ' '
        opt = kwargs.get('fields', '').strip()
        if opt:
            fields += opt
        desc = kwargs.get('description', '')
        if not desc:
            desc = title
        # Use dt.now() not datetime.now()
        now_str = dt.datetime.now().strftime(self.DATE_FMT)
        return self.RULE_TEMPLATE.format(title=title, rule_id=rule_id, level=level, description='# ' + desc, fields=fields, generation_date=now_str)

    def save_rules(self, filename, rules=None, overwrite=True):
        path = Path(filename)
        if rules:
            with open(path, 'w') as f:
                for r in rules:
                    f.write(r + '\n')
        return path

    def generate_batch(self, configs, filename):
        rules = [self.generate_rule(title=c.get('title', 'Batch Rule ' + str(i)), **c) for i, c in enumerate(configs)]
        self.stats['rules_generated'] += len(configs)
        return self.save_rules(filename, rules)

    def generate_quick(self, name, output):
        quick = {
            'syslog_auth_failure': {'level': '1', 'category': 'syslog', 'username': '* authentication', 'title': 'Auth failure', 'description': 'Auth failure'},
            'file_integrity_modification': {'level': '1', 'category': 'file_integrity', 'path': '*mod', 'title': 'File mod', 'description': 'File modification'},
            'brute_force': {'level': '1', 'category': 'syslog', 'username': '* failed password', 'title': 'Brute force', 'description': 'Brute force detection'},
            'root_squid': {'level': '1', 'category': 'syslog', 'username': '* root', 'title': 'Root squid', 'description': 'Root Squid detection'},
            'privilege_escalation': {'level': '2', 'category': 'command/windows', 'user': '* privileged', 'title': 'Priv escal', 'description': 'Privilege escalation'},
        }
        c = quick.get(name, {})
        return self.generate_rule(**c) if c else ''

    def generate_from_pattern(self, pattern, output):
        if not pattern or not pattern.strip():
            return ''
        fields = ''
        level = '3'
        cat = 'syslog'
        
        if 'file' in pattern.lower():
            cat = 'file_integrity'
            fields += "category='file_integrity' "
        elif 'directory' in pattern.lower():
            cat = 'file_integrity'
            fields += "category='file_integrity' "
        elif 'authentication' in pattern.lower():
            fields += "username='* authentication'"
        elif 'failed password' in pattern.lower():
            fields += "username='* failed password'"
        
        if 'user=' in pattern.lower():
            parts = pattern.lower().split('user=')
            if len(parts) > 1:
                user = parts[1].split(';')[0].strip('\"')
                fields += 'user=\"' + user + '\" '
        
        if 'path=' in pattern.lower():
            parts = pattern.lower().split('path=')
            if len(parts) > 1:
                pth = parts[1].split(';')[0].strip('\"')
                fields += 'path=\'' + pth + '\''
        
        if 'hostname=' in pattern.lower():
            parts = pattern.lower().split('hostname=')
            if len(parts) > 1:
                host = parts[1].split(';')[0].strip()
                fields += 'hostname=\'' + host + '\' '
        
        try:
            if 'level=' in pattern.lower():
                level = pattern.split('level=')[1].split(';')[0]
            
            self.logger.info('Generating from pattern: ' + str(pattern[:50]))
            return self.generate_rule(title=str(pattern[:50]), category=cat, level=level, description=str(pattern))
        except Exception as e:
            self.logger.debug('Pattern parsing failed: ' + str(pattern) + ' Error: ' + str(e))
            return ''


def main():
    parser = argparse.ArgumentParser(description='Wazuh Rule Generator CLI')
    parser.add_argument('-c', '--category', action='append', metavar='CATEGORY', help='Rule category')
    parser.add_argument('-r', '--rule', action='append', metavar='RULE', help='Rule spec')
    parser.add_argument('-o', '--output', default='rules.txt', help='Output file')
    parser.add_argument('-w', '--write', action='store_true', help='Write to output')
    parser.add_argument('-p', '--patterns', action='store_true', help='Generate from patterns')
    parser.add_argument('-q', '--quick', action='store_true', help='Generate quick rules')
    parser.add_argument('categories', nargs='*', help='Categories')
    
    args = parser.parse_args()
    generator = WazuhRuleGenerator()
    patterns_dir = Path(__file__).parent / 'rules'
    pattern_file = patterns_dir / 'wazuh_rules.txt'
    
    all_patterns = []
    try:
        if pattern_file.exists():
            with open(pattern_file, 'r') as f:
                all_patterns = f.readlines()
            generator.logger.info('Found ' + str(len(all_patterns)) + ' patterns in ' + str(pattern_file))
        else:
            generator.logger.info('Pattern file ' + str(pattern_file) + ' not found')
    except Exception as e:
        generator.logger.error('Error reading patterns: ' + str(e))
        all_patterns = []

    rule_templates = []

    if args.quick:
        for name in ['syslog_auth_failure', 'file_integrity_modification', 'brute_force', 'root_squid', 'privilege_escalation']:
            rule = generator.generate_quick(name, args.output)
            if rule:
                rule_templates.append(rule)
                generator.logger.info('Quick rule generated: ' + name)

    if args.patterns or all_patterns:
        for pattern in all_patterns:
            pattern = pattern.strip()
            if pattern and not pattern.startswith('#'):
                rule = generator.generate_from_pattern(pattern, args.output)
                if rule:
                    rule_templates.append(rule)
                    generator.logger.info('Pattern rule generated: ' + str(pattern[:80]))

    if args.patterns:
        generator.logger.info('Patterns argument set')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\n\nGoodbye!')
    except Exception as e:
        print('\nError occurred: ' + str(e))