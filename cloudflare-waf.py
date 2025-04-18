import os
import sys
import yaml
import requests
from dotenv import load_dotenv
import cloudflare
from cloudflare import Cloudflare

load_dotenv()
API_TOKEN = os.getenv("CF_API_TOKEN")
CONFIG_FILE = "config.yaml"

if not API_TOKEN:
    print("❌ CF_API_TOKEN not found in environment. Please set it in a .env file.")
    sys.exit(1)

cf = Cloudflare(api_token=API_TOKEN)

def load_config():
    with open(CONFIG_FILE, 'r') as f:
        return yaml.safe_load(f)

def waf_rules_id(zone_id):
    waf = cf.rulesets.list(zone_id=zone_id)
    for rule in waf:
        if rule.kind == 'zone':
            return rule.id
    return None

def get_rules(zone_id, ruleset_id):
    return cf.rulesets.get(ruleset_id=ruleset_id, zone_id=zone_id).rules
    
def find_rule_by_name(rules, name):
    for rule in rules:
        if rule.description == name:
            return rule
    return None

def build_expression(allowed_ips, uri_path, field):
    uri_check = f'({field} r"{uri_path}")'
    if current_ip := get_current_ip():
        allowed_ips.append(current_ip)
    if current_ip_vpn := get_current_vpn_ip('dum-e:8000'):
        allowed_ips.append(current_ip_vpn)
    ip_check = f"(ip.src in {{{' '.join(allowed_ips)}}})"
    return f"{uri_check} and not {ip_check}"

def get_current_ip():
    try:
        response = requests.get("https://api.ipify.org?format=json")
        response.raise_for_status()
        return response.json()["ip"]
    except requests.RequestException as e:
        print(f"Error retrieving IP address: {e}")
        return None

def get_current_vpn_ip(host):
    try:
        response = requests.get(f"http://{host}/v1/publicip/ip")
        response.raise_for_status()
        return response.json()["public_ip"]
    except requests.RequestException as e:
        print(f"Error retrieving IP address: {e}")
        return None

def create_waf_rule(ruleset_id, zone_id, expression, name, dry_run):
    print(f"🆕 Creating rule: {name}")
    if dry_run:
        print(f"[Dry Run] Would create rule with expression: {expression}")
        return
    try:
        cf.rulesets.rules.create(ruleset_id=ruleset_id,
                                zone_id=zone_id,
                                action='block',
                                expression=expression,
                                description=name,
                                enabled=True)
        print("✅ Rule created.")
    except cloudflare.APIConnectionError as ErrConnection:
        print("❌ Error creating rule:", ErrConnection)
    except cloudflare.RateLimitError as ErrRate:
        print("❌ Error creating rule:", ErrConnection)
    except cloudflare.APIStatusError as ErrStatus:
        print("Another non-200-range status code was received")
        print(ErrStatus.status_code)
        print(ErrStatus.response)

def update_waf_rule(ruleset_id, zone_id, active_rule, expression, dry_run):
    print(f"✏️ Updating rule: {active_rule.description}")
    if dry_run:
        print(f"[Dry Run] Would update expression to: {expression}")
        return
    try:
        cf.rulesets.rules.edit(rule_id=active_rule.id,
                               zone_id=zone_id, 
                               ruleset_id=ruleset_id, 
                               action=active_rule.action, 
                               expression=expression,
                               description=active_rule.description,
                               enabled=True)
        print("✅ Rule updated.")
    except cloudflare.APIConnectionError as ErrConnection:
        print("❌ Error creating rule:", ErrConnection)
    except cloudflare.RateLimitError as ErrRate:
        print("❌ Error creating rule:", ErrConnection)
    except cloudflare.APIStatusError as ErrStatus:
        print("Another non-200-range status code was received")
        print(ErrStatus.status_code)
        print(ErrStatus.response)

def process_rules(config):
    zone_id = config.get("zone_id", None)
    dry_run = config.get("dry_run", True)
    rules_config = config.get("rules", [])

    if not zone_id or not rules_config:
        print("Invalid config: zone and rules are required.")
        return
    ruleset_id = waf_rules_id(zone_id)
    rulesets = get_rules(zone_id, ruleset_id)

    for rule_definition in rules_config:
        name = rule_definition["name"]
        uri = rule_definition["uri"]
        ips = rule_definition["allowed_ips"]
        field = rule_definition["field"]
        expression = build_expression(ips, uri, field)
        active_rule = find_rule_by_name(rulesets, name)

        if active_rule:
            update_waf_rule(ruleset_id, zone_id, active_rule, expression, dry_run)
        else:
            create_waf_rule(ruleset_id, zone_id, expression, name, uri, ips, dry_run)

def main():
    config = load_config()
    try:
        process_rules(config)
    except Exception as e:
        print("❌ Fatal error:", e)
        sys.exit(1)

if __name__ == "__main__":
    main()
