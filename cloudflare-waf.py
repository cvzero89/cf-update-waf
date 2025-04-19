import os
import sys
import yaml
import requests
import logging
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv
import cloudflare
from cloudflare import Cloudflare

def setup_logging(log_file, log_level, max_log_size, backup_count):
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    log_file_location = f'{os.path.abspath(os.path.dirname(__file__))}/{log_file}'
    handler = RotatingFileHandler(log_file_location, maxBytes=max_log_size, backupCount=backup_count)
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))

    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[handler, logging.StreamHandler()]
    )

load_dotenv()
API_TOKEN = os.getenv("CF_API_TOKEN")
CONFIG_FILE = f"{os.path.abspath(os.path.dirname(__file__))}/config.yaml"

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

def build_expression(allowed_ips, uri_path, field, gluetun_vpn_host):
    uri_check = f'({field} r"{uri_path}")'
    if current_ip := get_current_ip():
        allowed_ips.append(current_ip)
    if current_ip_vpn := get_current_vpn_ip(gluetun_vpn_host):
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
        logging.info(f"Created rule: {name} with expression: {expression}.")
    except cloudflare.APIConnectionError as ErrConnection:
        print("❌ Error creating rule:", ErrConnection)
        logging.error(f"Failed to create rule: {ErrConnection}.")
    except cloudflare.RateLimitError as ErrRate:
        print("❌ Error creating rule:", ErrRate)
        logging.error(f"Failed to create rule: {ErrRate}.")
    except cloudflare.APIStatusError as ErrStatus:
        print(f"Another non-200-range status code was received. Status code: {ErrStatus.status_code}, {ErrStatus.response}")
        logging.error(f"Failed to create rule: {ErrStatus}.")

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
        logging.info(f"Updated rule: {active_rule.description} with expression: {expression}.")
    except cloudflare.APIConnectionError as ErrConnection:
        print("❌ Error creating rule:", ErrConnection)
        logging.error(f"Failed to create rule: {ErrConnection}.")
    except cloudflare.RateLimitError as ErrRate:
        print("❌ Error creating rule:", ErrRate)
        logging.error(f"Failed to create rule: {ErrRate}.")
    except cloudflare.APIStatusError as ErrStatus:
        print(f"Another non-200-range status code was received. Status code: {ErrStatus.status_code}, {ErrStatus.response}")
        logging.error(f"Failed to create rule: {ErrStatus}.")

def process_rules(config):
    zone_id = config.get("zone_id", None)
    dry_run = config.get("dry_run", True)
    rules_config = config.get("rules", [])
    gluetun_vpn_host = config.get("gluetun_vpn_host", None)
    if not zone_id or not rules_config:
        print("Invalid config: zone and rules are required.")
        logging.warning("Invalid config: zone and rules are required.")
        return
    ruleset_id = waf_rules_id(zone_id)
    rulesets = get_rules(zone_id, ruleset_id)
    logging.info(f"Processing rules for {zone_id}. Number of rules: {len(rules_config)}.")
    for rule_definition in rules_config:
        name = rule_definition["name"]
        uri = rule_definition["uri"]
        ips = rule_definition["allowed_ips"]
        field = rule_definition["field"]
        expression = build_expression(ips, uri, field, gluetun_vpn_host)
        active_rule = find_rule_by_name(rulesets, name)
        if active_rule:
            update_waf_rule(ruleset_id, zone_id, active_rule, expression, dry_run)
        else:
            create_waf_rule(ruleset_id, zone_id, expression, name, uri, ips, dry_run)

def main():
    _version = 'v0.2'
    config = load_config()
    setup_logging(config["logging"]["log_file"], config["logging"]["log_level"], config["logging"]["max_log_size"], config["logging"]["backup_count"])
    logging.info(f"Configuration loaded! Script version: {_version}")
    try:
        process_rules(config)
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        logging.error(f"❌ Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
