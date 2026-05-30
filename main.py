import os
import json
import re
import concurrent.futures
import ipaddress
import requests
import yaml
import subprocess
from urllib.parse import urlparse

# 核心映射基准 (已移除废弃的 GEOIP)
MAP_DICT = {
    'DOMAIN-SUFFIX': 'domain_suffix', 'HOST-SUFFIX': 'domain_suffix', 'host-suffix': 'domain_suffix',
    'DOMAIN': 'domain', 'HOST': 'domain', 'host': 'domain',
    'DOMAIN-KEYWORD':'domain_keyword', 'HOST-KEYWORD': 'domain_keyword', 'host-keyword': 'domain_keyword',
    'IP-CIDR': 'ip_cidr', 'ip-cidr': 'ip_cidr', 'IP-CIDR6': 'ip_cidr', 'IP6-CIDR': 'ip_cidr',
    'SRC-IP-CIDR': 'source_ip_cidr', 
    'DST-PORT': 'port', 'SRC-PORT': 'source_port',
    "URL-REGEX": "domain_regex", "DOMAIN-REGEX": "domain_regex"
}

def is_ip_network(address):
    try:
        ipaddress.ip_network(address, strict=False)
        return True
    except ValueError:
        return False

# ==========================================
# AST 解析器组件 (逻辑保持不变)
# ==========================================
def strip_outer_parens(s):
    s = s.strip()
    while s.startswith('(') and s.endswith(')'):
        depth = 0
        is_single_group = True
        for i in range(len(s) - 1):
            if s[i] == '(': depth += 1
            elif s[i] == ')': depth -= 1
            if depth == 0:
                is_single_group = False
                break
        if is_single_group:
            s = s[1:-1].strip()
        else:
            break
    return s

def split_args_by_comma(s):
    args = []
    depth = 0
    current_arg = []
    for char in s:
        if char == '(': depth += 1
        elif char == ')': depth -= 1
        
        if char == ',' and depth == 0:
            args.append("".join(current_arg).strip())
            current_arg = []
        else:
            current_arg.append(char)
            
    if current_arg:
        args.append("".join(current_arg).strip())
    return [arg for arg in args if arg]

def build_standard_rule(item):
    if ',' in item and not item.startswith('/'): 
        parts = item.split(',', 1)
        pattern = parts[0].strip()
        address = parts[1].split(',')[0].strip()
    else:
        address = item
        if is_ip_network(address):
            pattern = 'IP-CIDR' if ':' not in address else 'IP-CIDR6'
        elif address.startswith('+.') or address.startswith('.'):
            pattern = 'DOMAIN-SUFFIX'
            address = address.lstrip('+.')
        else:
            pattern = 'DOMAIN'

    if pattern in MAP_DICT:
        mapped_pattern = MAP_DICT[pattern]
        value = address
        if mapped_pattern in ['port', 'source_port']:
            if str(value).isdigit():
                value = int(value) 
            else:
                mapped_pattern = f"{mapped_pattern}_range" 
                value = str(value).replace('-', ':') 
        return {mapped_pattern: [value]}
    return None

def parse_logic_rule_ast(s):
    s = strip_outer_parens(s)
    match = re.match(r'^(AND|OR|NOT),(.*)$', s, re.IGNORECASE)
    if not match: return build_standard_rule(s)
        
    mode = match.group(1).lower()
    rest = strip_outer_parens(match.group(2))
    raw_args = split_args_by_comma(rest)
    
    parsed_rules = []
    for arg in raw_args:
        parsed = parse_logic_rule_ast(arg)
        if parsed: parsed_rules.append(parsed)
            
    if not parsed_rules: return None
        
    if mode == 'not':
        if len(parsed_rules) == 1:
            parsed_rules[0]['invert'] = True
            return parsed_rules[0]
        else:
            return {"type": "logical", "mode": "and", "rules": parsed_rules, "invert": True}
    else:
        return {"type": "logical", "mode": mode, "rules": parsed_rules}

def fetch_and_parse_rules(url):
    headers = {'User-Agent': 'Mozilla/5.0'}
    # 🚨 安全限制 1：设置严格超时，防止服务器恶意挂起导致 Actions 超时扣费
    response = requests.get(url, headers=headers, timeout=15)
    response.raise_for_status()
    
    # 🚨 安全限制 2：防止内存溢出 (OOM) 攻击，拒绝处理大于 5MB 的单文件
    if len(response.content) > 5 * 1024 * 1024:
        raise ValueError("File too large (exceeds 5MB)")
    
    raw_text = response.text
    standard_rules_data = []
    logical_rules_data = [] 

    if url.endswith('.yaml') or 'payload:' in raw_text:
        try:
            yaml_data = yaml.safe_load(raw_text)
            items = yaml_data.get('payload', yaml_data) if isinstance(yaml_data, dict) else yaml_data
            if not isinstance(items, list):
                items = raw_text.splitlines()
        except yaml.YAMLError:
            items = raw_text.splitlines()
    else:
        items = raw_text.splitlines()

    for item in items:
        if not isinstance(item, str): continue
        item = item.strip("'\" \t")
        if item.startswith('- '): item = item[2:].strip("'\" \t")
        if not item or item.startswith('#'): continue

        if item.startswith(('AND,', 'OR,')):
            parsed_logic = parse_logic_rule_ast(item)
            if parsed_logic: logical_rules_data.append(parsed_logic)
            continue 

        rule_obj = build_standard_rule(item)
        if rule_obj:
            for k, v in rule_obj.items():
                standard_rules_data.append((k, str(v[0])))

    return standard_rules_data, logical_rules_data

def process_single_link(link, output_dir):
    try:
        # 🚨 安全限制 3：安全提取文件名，防范路径遍历 (Path Traversal) 攻击
        parsed_url = urlparse(link)
        base_name = os.path.basename(parsed_url.path).split('.')[0]
        if not base_name or not re.match(r'^[\w\-\.]+$', base_name):
            base_name = f"ruleset_{abs(hash(link))}"

        standard_rules, logical_rules = fetch_and_parse_rules(link)
        if not standard_rules and not logical_rules: return None

        result_rules = {"version": 4, "rules": []}

        if standard_rules:
            categorized_rules = {}
            for pattern, address in set(standard_rules): 
                if pattern not in categorized_rules: categorized_rules[pattern] = set()
                categorized_rules[pattern].add(address)

            for pattern, addresses in categorized_rules.items():
                sorted_addresses = sorted(list(addresses))
                if pattern in ['port', 'source_port', 'port_range', 'source_port_range']:
                    ports, port_ranges = [], []
                    for a in sorted_addresses:
                        (ports.append(int(a)) if a.isdigit() else port_ranges.append(a.replace('-', ':')))
                    if ports: result_rules["rules"].append({pattern.replace('_range', ''): ports})
                    if port_ranges: result_rules["rules"].append({f"{pattern.replace('_range', '')}_range": port_ranges})
                else:
                    result_rules["rules"].append({pattern: sorted_addresses})

        if logical_rules: result_rules["rules"].extend(logical_rules)

        os.makedirs(output_dir, exist_ok=True)
        json_file_path = os.path.join(output_dir, f"{base_name}.json")
        srs_file_path = os.path.join(output_dir, f"{base_name}.srs")

        with open(json_file_path, 'w', encoding='utf-8') as f:
            json.dump(result_rules, f, ensure_ascii=False, indent=2, sort_keys=True)

        # 🚨 安全限制 4：防御命令注入，强制以安全列表形式传递参数给底层操作系统
        try:
            subprocess.run(
                ["sing-box", "rule-set", "compile", "--output", srs_file_path, json_file_path],
                check=True, 
                capture_output=True
            )
            print(f"✅ 成功编译: {srs_file_path}")
            return srs_file_path
        except subprocess.CalledProcessError as e:
            print(f"❌ 编译失败 {base_name}: {e.stderr.decode('utf-8', errors='ignore')}")
            return None

    except Exception as e:
        print(f"❌ 处理跳过 {link}: {str(e)}")
        return None

if __name__ == "__main__":
    links_file_path = "../links.txt"
    output_directory = "./"
    
    if os.path.exists(links_file_path):
        with open(links_file_path, 'r', encoding='utf-8') as f:
            links = [line.strip() for line in f if line.strip() and not line.startswith('#')]

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(process_single_link, link, output_directory) for link in links]
            for future in concurrent.futures.as_completed(futures):
                future.result() 
    else:
        print(f"找不到文件: {links_file_path}")
