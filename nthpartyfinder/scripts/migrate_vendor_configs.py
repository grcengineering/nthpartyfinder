#!/usr/bin/env python3
"""
Migration script for nthpartyfinder vendor configuration consolidation.

This script reads the existing configuration files:
  - config/known_vendors.json
  - config/saas_platforms.json
  - config/nthpartyfinder.toml

And generates individual vendor JSON files in config/vendors/

Usage:
    python scripts/migrate_vendor_configs.py

"""

import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

# Try to import toml - fall back to tomllib (Python 3.11+) or manual parsing
try:
    import toml
except ImportError:
    try:
        import tomllib as toml
        # tomllib only has load() for binary files
        def toml_load(f):
            return toml.load(f)
    except ImportError:
        toml = None


def normalize_org_name(org_name: str) -> str:
    """
    Normalize organization name for grouping.
    Removes common suffixes like Inc., LLC, etc.
    """
    org = org_name.strip()

    # Normalize common variations
    replacements = {
        ", Inc.": "",
        ", Inc": "",
        " Inc.": "",
        " Inc": "",
        " LLC": "",
        " Ltd.": "",
        " Ltd": "",
        " Limited": "",
        ", Ltd.": "",
        " Corporation": "",
        " Corp.": "",
        " Corp": "",
        " B.V.": "",
        " s.r.o.": "",
        " SE": "",
        " N.V.": "",
    }

    for suffix, replacement in replacements.items():
        if org.endswith(suffix):
            org = org[:-len(suffix)] + replacement

    return org.strip()


def parse_org_with_annotation(org_name: str) -> tuple[str, str | None]:
    """
    Parse org name that may have a parenthetical annotation.
    Returns (base_name, annotation or None)

    Examples:
    - "Google LLC" -> ("Google LLC", None)
    - "Slack Technologies (Salesforce)" -> ("Slack Technologies", "Salesforce")
    - "Google (YouTube)" -> ("Google", "YouTube")
    """
    match = re.match(r'^(.+?)\s*\(([^)]+)\)$', org_name)
    if match:
        return match.group(1).strip(), match.group(2).strip()
    return org_name, None


def determine_parent_relationship(org_name: str, domain: str) -> tuple[str, str | None, bool]:
    """
    Determine if the annotation represents a parent company or a product name.

    Returns (effective_org, parent_vendor or None, is_subsidiary)

    The logic:
    - "Google (YouTube)" for youtube.com: YouTube is a Google product/acquisition
      -> effective_org = "YouTube", parent = "Google", is_subsidiary = True
    - "Slack Technologies (Salesforce)" for slack.com: Salesforce owns Slack
      -> effective_org = "Slack Technologies", parent = "Salesforce", is_subsidiary = True
    - "Google LLC" for google.com: No parent
      -> effective_org = "Google LLC", parent = None, is_subsidiary = False
    """
    base_name, annotation = parse_org_with_annotation(org_name)

    if not annotation:
        return org_name, None, False

    domain_lower = domain.lower().replace('.', '').replace('-', '')
    annotation_lower = re.sub(r'[^a-z0-9]', '', annotation.lower())
    base_lower = re.sub(r'[^a-z0-9]', '', normalize_org_name(base_name).lower())

    # If the annotation matches the domain, the annotation is the product/company name
    # and the base is the parent company
    # e.g., "Google (YouTube)" for youtube.com -> YouTube is the org, Google is parent
    if annotation_lower in domain_lower or domain_lower.startswith(annotation_lower[:4]):
        return annotation, base_name, True

    # If the base name matches the domain, the annotation is the parent company
    # e.g., "Slack Technologies (Salesforce)" for slack.com -> Slack is org, Salesforce is parent
    if base_lower[:4] in domain_lower or domain_lower.startswith(base_lower[:4]):
        return base_name, annotation, True

    # Default: treat annotation as parent
    return base_name, annotation, True


def generate_vendor_id(org_name: str) -> str:
    """Generate a vendor ID from organization name."""
    # Remove any parenthetical annotation
    base_name, _ = parse_org_with_annotation(org_name)

    # Normalize and convert to ID format
    vendor_id = normalize_org_name(base_name)
    vendor_id = vendor_id.lower()
    vendor_id = re.sub(r'[^a-z0-9]+', '-', vendor_id)
    vendor_id = vendor_id.strip('-')

    return vendor_id


def infer_domain_type(domain: str, primary_domain: str, org_name: str) -> str:
    """Infer domain type from domain pattern."""
    # Primary domain check
    if domain == primary_domain:
        return 'primary'

    # CDN patterns
    if any(cdn in domain for cdn in ['cdn.', 'static.', 'assets.', 'edge.']):
        return 'cdn'
    if 'edge' in domain.lower():
        return 'cdn'

    # API patterns
    if 'api' in domain.lower():
        return 'api'

    # Email patterns
    if any(mail in domain.lower() for mail in ['mail', 'smtp', 'email']):
        return 'email'

    # Default to service
    return 'service'


def infer_category(domain: str, org_name: str) -> str:
    """Infer category from domain and organization patterns."""
    domain_lower = domain.lower()
    org_lower = org_name.lower()

    # Tracking/Analytics
    if any(t in domain_lower or t in org_lower for t in [
        'analytics', 'tracking', 'pixel', 'tag', 'tagmanager'
    ]):
        return 'tracking'

    # Advertising
    if any(a in domain_lower or a in org_lower for a in [
        'ads', 'advertising', 'syndication', 'doubleclick', 'marketing', 'pardot'
    ]):
        return 'advertising'

    # Security
    if any(s in domain_lower or s in org_lower for s in [
        'security', 'auth', 'sso', 'identity', 'okta', 'duo', 'crowdstrike'
    ]):
        return 'security'

    # Payment
    if any(p in domain_lower or p in org_lower for p in [
        'payment', 'stripe', 'paypal', 'braintree', 'pay'
    ]):
        return 'payment'

    # Communication
    if any(c in domain_lower or c in org_lower for c in [
        'slack', 'zoom', 'webex', 'teams', 'chat', 'mail', 'email'
    ]):
        return 'communication'

    # Storage
    if any(s in domain_lower or s in org_lower for s in [
        'storage', 'box', 'dropbox', 's3', 'files'
    ]):
        return 'storage'

    # Development
    if any(d in domain_lower or d in org_lower for d in [
        'github', 'gitlab', 'bitbucket', 'circleci', 'jenkins'
    ]):
        return 'development'

    # Monitoring
    if any(m in domain_lower or m in org_lower for m in [
        'monitor', 'datadog', 'newrelic', 'sentry', 'rollbar'
    ]):
        return 'monitoring'

    # Media
    if any(m in domain_lower or m in org_lower for m in [
        'youtube', 'vimeo', 'video', 'media'
    ]):
        return 'media'

    # Support
    if any(s in domain_lower or s in org_lower for s in [
        'zendesk', 'support', 'helpdesk', 'freshdesk', 'intercom'
    ]):
        return 'support'

    # Analytics/BI
    if any(a in domain_lower or a in org_lower for a in [
        'looker', 'tableau', 'amplitude', 'mixpanel', 'heap'
    ]):
        return 'analytics'

    # Infrastructure (CDN, cloud)
    if any(i in domain_lower for i in [
        'cloudflare', 'akamai', 'fastly', 'cloudfront', 'aws', 'azure', 'gcp'
    ]):
        return 'infrastructure'

    # Default to platform
    return 'platform'


def load_known_vendors(config_dir: Path) -> dict:
    """Load known_vendors.json and return vendors dict."""
    vendors_file = config_dir / 'known_vendors.json'
    with open(vendors_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return data.get('vendors', {})


def load_saas_platforms(config_dir: Path) -> list:
    """Load saas_platforms.json and return platforms list."""
    platforms_file = config_dir / 'saas_platforms.json'
    with open(platforms_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return data.get('platforms', [])


def load_toml_patterns(config_dir: Path) -> tuple[dict, dict]:
    """Load verification patterns and provider mappings from TOML."""
    toml_file = config_dir / 'nthpartyfinder.toml'

    verification = {}
    provider_mappings = {}

    if toml is not None:
        with open(toml_file, 'rb') as f:
            try:
                data = toml.load(f)
            except:
                # Try text mode for older toml library
                f.seek(0)
                with open(toml_file, 'r', encoding='utf-8') as ft:
                    data = toml.load(ft)

        patterns = data.get('patterns', {})
        verification = patterns.get('verification', {})
        provider_mappings = patterns.get('provider_mappings', {})
    else:
        # Manual parsing fallback
        print("Warning: toml library not available, skipping TOML patterns")

    return verification, provider_mappings


def find_primary_domain(domains: list[str], org_name: str) -> str:
    """Find the primary domain for an organization."""
    base_org = normalize_org_name(org_name)
    base_org_clean = re.sub(r'[^a-z0-9]', '', base_org.lower())

    # Look for exact .com match first
    for domain in domains:
        domain_base = domain.split('.')[0].lower()
        domain_base_clean = re.sub(r'[^a-z0-9]', '', domain_base)

        if domain_base_clean == base_org_clean and domain.endswith('.com'):
            return domain

    # Look for .com domain containing org name
    for domain in domains:
        if domain.endswith('.com') and base_org_clean in domain.lower().replace('.', '').replace('-', ''):
            return domain

    # Look for any domain matching org
    for domain in domains:
        if base_org_clean in domain.lower().replace('.', '').replace('-', ''):
            return domain

    # Fall back to first domain
    return domains[0] if domains else ''


def main():
    # Determine paths
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    config_dir = project_root / 'config'
    vendors_dir = config_dir / 'vendors'

    print(f"Project root: {project_root}")
    print(f"Config dir: {config_dir}")
    print(f"Vendors dir: {vendors_dir}")

    # Create vendors directory if it doesn't exist
    vendors_dir.mkdir(parents=True, exist_ok=True)

    # Clean existing vendor files (except schema)
    for f in vendors_dir.glob('*.json'):
        if f.name != '_schema.json':
            f.unlink()

    # Load source data
    print("\n=== Loading source configuration files ===")

    known_vendors = load_known_vendors(config_dir)
    print(f"Loaded {len(known_vendors)} domain mappings from known_vendors.json")

    saas_platforms = load_saas_platforms(config_dir)
    print(f"Loaded {len(saas_platforms)} SaaS platforms from saas_platforms.json")

    verification, provider_mappings = load_toml_patterns(config_dir)
    print(f"Loaded {len(verification)} verification patterns from nthpartyfinder.toml")
    print(f"Loaded {len(provider_mappings)} provider mappings from nthpartyfinder.toml")

    # Group domains by effective organization (after resolving parent relationships)
    print("\n=== Processing domain mappings ===")

    # First pass: determine effective org for each domain
    # Structure: {effective_org: {domain: (parent_org, original_org_name)}}
    org_data = defaultdict(lambda: {'domains': {}, 'parent': None})

    for domain, org_name in known_vendors.items():
        effective_org, parent, is_subsidiary = determine_parent_relationship(org_name, domain)

        # Normalize the effective org name
        effective_org_normalized = normalize_org_name(effective_org)

        org_data[effective_org_normalized]['domains'][domain] = org_name
        if parent and is_subsidiary:
            org_data[effective_org_normalized]['parent'] = parent

    print(f"Found {len(org_data)} unique organizations after relationship resolution")

    # Generate vendor configs
    print("\n=== Generating vendor configuration files ===")

    generated = 0
    parent_refs = []  # Track for summary

    for org_name, data in sorted(org_data.items()):
        domains = list(data['domains'].keys())
        parent = data['parent']

        vendor_id = generate_vendor_id(org_name)

        # Find primary domain
        primary_domain = find_primary_domain(domains, org_name)

        # Build config
        config = {
            '$schema': './_schema.json',
            'id': vendor_id,
            'organization': org_name,
            'primary_domain': primary_domain,
        }

        # Add parent reference if applicable
        if parent:
            parent_id = generate_vendor_id(parent)
            config['parent_vendor'] = parent_id
            parent_refs.append((vendor_id, parent_id, parent))

        # Build domains map
        domains_map = {}
        for domain in domains:
            domain_type = infer_domain_type(domain, primary_domain, org_name)
            category = infer_category(domain, org_name)

            domains_map[domain] = {
                'type': domain_type,
                'category': category,
            }

        config['domains'] = domains_map

        # Find verification patterns for this vendor
        vendor_patterns = []
        for pattern, target_domain in verification.items():
            if target_domain in domains:
                vendor_patterns.append(pattern)
        config['verification_patterns'] = vendor_patterns

        # Find provider aliases for this vendor
        provider_aliases = []
        for alias, target_domain in provider_mappings.items():
            if target_domain in domains:
                provider_aliases.append(alias)
        config['provider_aliases'] = provider_aliases

        # Find SaaS tenants for this vendor
        saas_tenants = []
        for platform in saas_platforms:
            if platform.get('vendor_domain') in domains:
                tenant = {
                    'name': platform['name'],
                    'patterns': platform.get('tenant_patterns', []),
                }
                if 'detection' in platform:
                    tenant['detection'] = platform['detection']
                saas_tenants.append(tenant)
        config['saas_tenants'] = saas_tenants

        # Write output
        output_file = vendors_dir / f"{vendor_id}.json"

        # Handle ID collisions by merging
        if output_file.exists():
            with open(output_file, 'r', encoding='utf-8') as f:
                existing = json.load(f)

            # Merge domains
            for domain, meta in config['domains'].items():
                if domain not in existing['domains']:
                    existing['domains'][domain] = meta

            # Merge patterns
            for pattern in config['verification_patterns']:
                if pattern not in existing['verification_patterns']:
                    existing['verification_patterns'].append(pattern)

            for alias in config['provider_aliases']:
                if alias not in existing['provider_aliases']:
                    existing['provider_aliases'].append(alias)

            for tenant in config['saas_tenants']:
                existing_names = [t['name'] for t in existing['saas_tenants']]
                if tenant['name'] not in existing_names:
                    existing['saas_tenants'].append(tenant)

            config = existing
            print(f"  Merged: {vendor_id}.json")
        else:
            print(f"  Created: {vendor_id}.json ({len(domains)} domains)")

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)

        generated += 1

    print(f"\n=== Migration complete ===")
    print(f"Generated {generated} vendor files in {vendors_dir}")

    # Report parent references
    if parent_refs:
        print("\n=== Parent-child relationships ===")
        for child_id, parent_id, parent_name in parent_refs:
            parent_file = vendors_dir / f"{parent_id}.json"
            status = "OK" if parent_file.exists() else "NEEDS PARENT FILE"
            print(f"  {child_id} -> {parent_id} [{status}]")

    # Report unmatched SaaS platforms
    all_vendor_domains = set(known_vendors.keys())
    unmatched_platforms = []
    for platform in saas_platforms:
        vendor_domain = platform.get('vendor_domain')
        if vendor_domain and vendor_domain not in all_vendor_domains:
            unmatched_platforms.append((platform['name'], vendor_domain))

    if unmatched_platforms:
        print(f"\n=== SaaS platforms needing vendor entries ===")
        for name, domain in unmatched_platforms:
            print(f"  - {name} ({domain})")


if __name__ == '__main__':
    main()
