import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
import os
import paramiko
import time
import ipaddress
import concurrent.futures
import re
import subprocess
import threading
import requests
import urllib3
from datetime import datetime
urllib3.disable_warnings()

# ----------- DNA CENTER KONFIGURATION (RET DISSE) -----------
DNAC_URL = "https://"
DNAC_USER = ""
DNAC_PASS = ""
TEMPLATE_NAME = "JinjaPlain_1749633521"          # Navn på eksisterende template (den der omdøbes)
NEW_TEMPLATE_NAME = ""    # Navn på NY template, der oprettes med script-output
VERIFY_SSL = False
# ------------------------------------------------------------

# ----------- BRUGERNAVN OG PASSWORD HER ----------- #
SSH_USERNAME = "ShowScript"
SSH_PASSWORD = "Show123123"
# -------------------------------------------------- #

SUBNETS = [
    
]
output_root = r"C:\LINUX\LOKATIONER\DNA"
os.makedirs(output_root, exist_ok=True)

MATCH_MODELS_DEFAULT = [
    "9200", "9300", "9400", "9500", "9600", "2960CX", "3560CX", "3850",
    "38XX", "NEXUS", "4331", "4351", "4431", "4451", "8500", "8200", "1121", "1111", "92xx", "ASA", "FPR"
]

SPING_SCRIPT = "sping.py"
SPING_IP_TXT = "ip.txt"

PORT_MODEL_MAP = {
   
}

class DNACAuth:
    def __init__(self, dnac_url, username, password, verify_ssl=False):
        self.dnac_url = dnac_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.token = None
        self.token_expiry = 0

    def get_token(self, force_new=False):
        now = time.time()
        if self.token and (now < self.token_expiry - 60) and not force_new:
            return self.token
        url = f"{self.dnac_url}/dna/system/api/v1/auth/token"
        resp = requests.post(url, auth=(self.username, self.password), verify=self.verify_ssl)
        resp.raise_for_status()
        self.token = resp.json()["Token"]
        self.token_expiry = now + 3600
        return self.token

    def request(self, method, endpoint, **kwargs):
        headers = kwargs.pop("headers", {})
        for attempt in range(2):
            token = self.get_token(force_new=(attempt == 1))
            headers["X-Auth-Token"] = token
            url = f"{self.dnac_url}{endpoint}"
            resp = requests.request(method, url, headers=headers, verify=self.verify_ssl, **kwargs)
            if resp.status_code != 401:
                return resp
        resp.raise_for_status()

def find_template_id_by_name(dnac: DNACAuth, name):
    endpoint = f"/dna/intent/api/v1/template-programmer/template"
    resp = dnac.request("GET", endpoint)
    templates = resp.json()
    for tmpl in templates:
        if tmpl.get("name") == name:
            return tmpl["id"], tmpl
    raise Exception(f"Template med navn '{name}' ikke fundet")

def rename_template(dnac: DNACAuth, template_json, new_name):
    template_json = dict(template_json)
    template_json['name'] = new_name
    resp = dnac.request("PUT", "/dna/intent/api/v1/template-programmer/template", json=template_json)
    return resp.json()

def create_new_template(dnac: DNACAuth, base_template_json, new_name, new_content):
    new_template = {
        "name": new_name,
        "projectId": base_template_json["projectId"],
        "templateContent": new_content,
        "language": base_template_json.get("language", "JINJA"),
        "deviceTypes": base_template_json.get("deviceTypes", []),
        "rollbackTemplateContent": base_template_json.get("rollbackTemplateContent", ""),
        "rollbackTemplateParams": base_template_json.get("rollbackTemplateParams", []),
        "parameters": base_template_json.get("parameters", []),
        "description": f"Oprettet automatisk {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    }
    resp = dnac.request("POST", "/dna/intent/api/v1/template-programmer/template", json=new_template)
    return resp.json()

def commit_template(dnac: DNACAuth, template_id, comments="Commit via script"):
    data = {
        "commitNote": comments
    }
    endpoint = f"/dna/intent/api/v1/templates/{template_id}/versions/commit?force=true"
    resp = dnac.request("POST", endpoint, json=data)
    if resp.status_code not in (200, 202):
        print("FEJL ved commit:", resp.status_code, resp.text)
        return None
    try:
        task_id = resp.json()["response"]["taskId"]
    except Exception as e:
        print("Kunne ikke finde taskId:", e)
        return None
    for i in range(30):
        time.sleep(2)
        task_endpoint = f"/dna/intent/api/v1/task/{task_id}"
        task_resp = dnac.request("GET", task_endpoint)
        task_json = task_resp.json()["response"]
        progress = str(task_json.get("progress", ""))
        if task_json.get("isError"):
            print("FEJL ved commit-task:", progress)
            return None
        if "committed template" in progress.lower():
            print("Commit OK!")
            return task_json
    print("Timeout: Commit-task ikke færdig efter ventetid.")
    return None

def patch_macro_in_template(template_str, macro_str):
    macro_name_match = re.search(r"\{%\s*macro\s+([A-Za-z0-9_\-]+)\s*\(\)", macro_str)
    if not macro_name_match:
        raise Exception("Kan ikke finde macro-navn i input!")
    macro_name = macro_name_match.group(1)
    macro_re = re.compile(rf"\{{%\s*macro\s+{re.escape(macro_name)}\s*\(\)\s*%\}}.*?\{{%\s*endmacro\s*%\}}", re.DOTALL)
    if macro_re.search(template_str):
        old_macro = macro_re.search(template_str).group(0)
        if old_macro.strip() == macro_str.strip():
            return template_str, False
        template_str = macro_re.sub(macro_str.strip(), template_str)
        return template_str, True
    else:
        template_str = template_str.rstrip() + "\n\n" + macro_str.strip()
        return template_str, True

def find_node_folder(ip):
    ip_addr = ipaddress.IPv4Address(ip)
    for node, net in SUBNETS:
        if ip_addr in net:
            return node
    return "NodeUnknown"

def update_hostnames_txt(ip, hostname):
    node_folder = find_node_folder(ip)
    full_output_folder = os.path.join(output_root, node_folder)
    os.makedirs(full_output_folder, exist_ok=True)
    out_file = os.path.join(full_output_folder, "hostnames.txt")
    lines = []
    if os.path.exists(out_file):
        with open(out_file, "r", encoding="utf-8") as f:
            for l in f:
                if not re.match(rf'^\s*"{re.escape(hostname)}":\s*"\{{\s*{re.escape(hostname)}\(\)\s*\}}",?\s*$', l):
                    lines.append(l.rstrip('\n'))
    lines.append(f'"{hostname}": "{{{hostname}()}}",')
    with open(out_file, "w", encoding="utf-8") as f:
        for l in lines:
            if l.strip():
                f.write(l + "\n")
def update_hostnames_txt_dna(ip, macro_name):
    dna_output_folder = os.path.join(output_root, "DNA")
    os.makedirs(dna_output_folder, exist_ok=True)
    out_file = os.path.join(dna_output_folder, "hostnames.txt")
    lines = []
    if os.path.exists(out_file):
        with open(out_file, "r", encoding="utf-8") as f:
            for l in f:
                if not re.match(rf'^\s*"{re.escape(macro_name)}":\s*"\{{\s*{re.escape(macro_name)}\(\)\s*\}}",?\s*$', l):
                    lines.append(l.rstrip('\n'))
    lines.append(f'"{macro_name}": "{{{macro_name}()}}",')
    with open(out_file, "w", encoding="utf-8") as f:
        for l in lines:
            if l.strip():
                f.write(l + "\n")

def update_ikke_skiftes(ip, hostname, model_output, node_folder):
    full_output_folder = os.path.join(output_root, node_folder)
    os.makedirs(full_output_folder, exist_ok=True)
    ikke_skiftes_file = os.path.join(full_output_folder, f"{node_folder}_Skal_ikke_skiftes.txt")
    model_number = None
    for line in model_output.splitlines():
        m = re.match(r"^Model number\s*:\s*([A-Za-z0-9\-]+)", line.strip(), re.IGNORECASE)
        if m:
            model_number = m.group(1).strip()
            break
    if not model_number:
        model_number = model_output.replace("\n", " ").strip()
    entry = f"{ip};{hostname};{model_number}"
    entries = set()
    if os.path.exists(ikke_skiftes_file):
        with open(ikke_skiftes_file, "r", encoding="utf-8") as f:
            for l in f:
                entries.add(l.strip())
    if entry not in entries:
        entries.add(entry)
        with open(ikke_skiftes_file, "w", encoding="utf-8") as f:
            for l in sorted(entries):
                f.write(l + "\n")

def port_rename(model_number, line):
    line = re.sub(r'^interface FastEthernet0\s*$', 'interface GigabitEthernet0/0', line)
    model_number = model_number.strip().upper()
    for key in PORT_MODEL_MAP:
        if model_number == key.upper():
            for frm, to in PORT_MODEL_MAP[key]:
                if frm.startswith("GigabitEthernet") or frm.startswith("TenGigabitEthernet") or frm.startswith("FastEthernet"):
                    line = line.replace(frm, to)
                else:
                    line = re.sub(frm, to, line)
            break
    return line

def parse_interface_output(lines, model_number, hostname):
    lines = [l for l in lines if l.strip() != "storm-control action shutdown"]
    interfaces = []
    current_block = []
    current_interface = None
    for line in lines:
        line = port_rename(model_number, line)
        if re.match(rf"^{re.escape(hostname)}[>#]?$", line.strip()):
            continue
        m = re.match(r"^interface (\S+)", line)
        if m:
            if current_block and current_interface:
                interfaces.append((current_interface, current_block))
            current_interface = m.group(1)
            current_block = [line]
        elif current_block is not None:
            current_block.append(line)
    if current_block and current_interface:
        interfaces.append((current_interface, current_block))
    filtered = []
    for iface, block in interfaces:
        iface_lower = iface.lower()
        if iface_lower.startswith("vlan"):
            continue
        block_joined = '\n'.join(block).lower()
        if iface_lower.startswith("port-channel") or iface_lower.startswith("po"):
            block = block + ["switchport nonegotiate", "load-interval 30"]
        elif "switchport mode access" in block_joined or "switchport access vlan" in block_joined:
            block = block + [
                "switchport nonegotiate", "switchport port-security", "device-trac attach-policy IPDT_POLICY",
                "load-interval 30", "snmp trap mac-notification change added", "snmp trap mac-notification change removed",
                "storm-control broadcast level pps 200", "storm-control multicast level 30.00",
                "storm-control action shutdo", "storm-control action tr", "spanning-tree portfast"
            ]
        elif "switchport mode trunk" in block_joined:
            block = block + ["switchport nonegotiate", "load-interval 30"]
        block = [l.replace("switchport", "switchpo") for l in block]
        block = [l.replace("description", "desc") for l in block]
        block = [l.replace("storm-control", "storm-contr") for l in block]
        block = [l.replace("spanning-tree portfast", "spanning-tree portfa") for l in block]
        block = [l.replace("load-interval 30", "load-inter 30") for l in block]
        block = [l.replace("shutdown", "shutdow") for l in block]
        filtered.append(block)
    return filtered

def read_until_prompt(shell, prompt, timeout=10):
    shell.settimeout(timeout)
    buffer = ""
    start_time = time.time()
    while True:
        if time.time() - start_time > timeout:
            break
        try:
            recv = shell.recv(65536).decode("utf-8", errors="ignore")
        except Exception:
            break
        buffer += recv
        if prompt in buffer:
            break
    return buffer

def get_config(ip, username, password, match_models):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password, look_for_keys=False, allow_agent=False)
        shell = client.invoke_shell()
        time.sleep(1)
        shell.recv(10000)
        shell.send('\n')
        time.sleep(1)
        prompt_output = shell.recv(10000).decode("utf-8")
        hostname_match = re.search(r'([^\s#>]+)[#>]', prompt_output)
        hostname = hostname_match.group(1) if hostname_match else "UNKNOWN"
        prompt = f"{hostname}#"
        shell.send("terminal length 0\n")
        read_until_prompt(shell, prompt)
        shell.send("sh run | i ^interface Giga.*|^interface Ten.*|^interface Fast.*|^interface Po.*|^interface Port-channel.*|^ desc.*|switchport access.*|switchport voice.*|switchport mode.*|switchport trunk.*|^interface Vlan1| shutdown$\n")
        port_config_output = read_until_prompt(shell, prompt)
        port_config_lines = port_config_output.splitlines()
        port_config_lines = [l for l in port_config_lines if not l.strip().startswith(prompt) and not l.strip().startswith("sh run") and l.strip()]
        port_config_lines = [l for l in port_config_lines if l.strip() != "storm-control action shutdown"]
        shell.send("show version | i [M-m]odel [N-n]umber\n")
        model_output = read_until_prompt(shell, prompt)
        model_lines = [l for l in model_output.splitlines() if "model number" in l.lower()]
        model_number = None
        for line in model_lines:
            m = re.match(r"^Model number\s*:\s*([A-Za-z0-9\-]+)", line.strip(), re.IGNORECASE)
            if m:
                model_number = m.group(1).strip()
                break
        if not model_number:
            model_number = "UNKNOWN"
        if model_number == "UNKNOWN":
            shell.send("show inventory\n")
            inventory_output = read_until_prompt(shell, prompt)
            pid_lines = [l for l in inventory_output.splitlines() if "PID:" in l]
            model_pid = None
            for line in pid_lines:
                m = re.search(r'PID:\s*([A-Za-z0-9\-]+)', line)
                if m:
                    pid = m.group(1).strip()
                    if not pid.lower().startswith(("pwr", "fan", "acs", "nim", "sm")):
                        model_pid = pid
                        break
            if model_pid:
                model_number = model_pid
            elif pid_lines:
                m = re.search(r'PID:\s*([A-Za-z0-9\-]+)', pid_lines[0])
                if m:
                    model_number = m.group(1).strip()
        model_number_lower = model_number.lower()
        if any(match.lower() in model_number_lower for match in match_models):
            node_folder = find_node_folder(ip)
            update_ikke_skiftes(ip, hostname, model_number, node_folder)
            return f"SKAL IKKE SKIFTES: {ip} {hostname} {model_number}"
        lines = port_config_lines
        interfaces_blocks = parse_interface_output(lines, model_number, hostname)
        cleaned_output = [l.strip() for block in interfaces_blocks for l in block if l.strip()]
        macro_start = f"{{% macro {hostname}() %}}"
        macro_end = "{% endmacro %}"
        new_macro_block = "\n".join([macro_start] + cleaned_output + [macro_end]) + "\n"
        node_folder = find_node_folder(ip)
        full_output_folder = os.path.join(output_root, node_folder)
        os.makedirs(full_output_folder, exist_ok=True)
        node_file = os.path.join(full_output_folder, f"{node_folder.lower()}.txt")
        if os.path.exists(node_file):
            with open(node_file, "r", encoding="utf-8") as f:
                old_content = f.read()
        else:
            old_content = ""
        macro_pattern = r"\{%\s*macro\s+" + re.escape(hostname) + r"\s*\(\)\s*%\}.*?\{%\s*endmacro\s*%\}\s*"
        new_content, n_repl = re.subn(macro_pattern, "", old_content, flags=re.DOTALL)
        new_content = (new_content.rstrip() + "\n\n" + new_macro_block).lstrip()
        new_content_clean = re.sub(r'\n{3,}', '\n\n', new_content).strip() + "\n"
        old_content_clean = re.sub(r'\n{3,}', '\n\n', old_content).strip() + "\n"
        if new_content_clean == old_content_clean:
            update_hostnames_txt(ip, hostname)
            return None
        with open(node_file, "w", encoding="utf-8") as f:
            f.write(new_content_clean)
        update_hostnames_txt(ip, hostname)
        return None
    except Exception as e:
        return f"{ip}: {e}"

def get_config_dna(ip, username, password, match_models):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password, look_for_keys=False, allow_agent=False)
        shell = client.invoke_shell()
        time.sleep(1)
        shell.recv(10000)
        shell.send('\n')
        time.sleep(1)
        prompt_output = shell.recv(10000).decode("utf-8")
        hostname_match = re.search(r'([^\s#>]+)[#>]', prompt_output)
        hostname = hostname_match.group(1) if hostname_match else "UNKNOWN"
        macro_name = hostname.replace("-", "_")
        prompt = f"{hostname}#"
        shell.send("terminal length 0\n")
        read_until_prompt(shell, prompt)
        shell.send("sh run | i ^interface Giga.*|^interface Ten.*|^interface Fast.*|^interface Po.*|^interface Port-channel.*|^ desc.*|switchport access.*|switchport voice.*|switchport mode.*|switchport trunk.*|^interface Vlan1| shutdown$\n")
        port_config_output = read_until_prompt(shell, prompt)
        port_config_lines = port_config_output.splitlines()
        port_config_lines = [l for l in port_config_lines if not l.strip().startswith(prompt) and not l.strip().startswith("sh run") and l.strip()]
        port_config_lines = [l for l in port_config_lines if l.strip() != "storm-control action shutdown"]
        shell.send("show version | i [M-m]odel [N-n]umber\n")
        model_output = read_until_prompt(shell, prompt)
        model_lines = [l for l in model_output.splitlines() if "model number" in l.lower()]
        model_number = None
        for line in model_lines:
            m = re.match(r"^Model number\s*:\s*([A-Za-z0-9\-]+)", line.strip(), re.IGNORECASE)
            if m:
                model_number = m.group(1).strip()
                break
        if not model_number:
            model_number = "UNKNOWN"
        if model_number == "UNKNOWN":
            shell.send("show inventory\n")
            inventory_output = read_until_prompt(shell, prompt)
            pid_lines = [l for l in inventory_output.splitlines() if "PID:" in l]
            model_pid = None
            for line in pid_lines:
                m = re.search(r'PID:\s*([A-Za-z0-9\-]+)', line)
                if m:
                    pid = m.group(1).strip()
                    if not pid.lower().startswith(("pwr", "fan", "acs", "nim", "sm")):
                        model_pid = pid
                        break
            if model_pid:
                model_number = model_pid
            elif pid_lines:
                m = re.search(r'PID:\s*([A-Za-z0-9\-]+)', pid_lines[0])
                if m:
                    model_number = m.group(1).strip()
        model_number_lower = model_number.lower()
        if any(match.lower() in model_number_lower for match in match_models):
            return f"SKAL IKKE SKIFTES: {ip} {hostname} {model_number}"
        lines = port_config_lines
        interfaces_blocks = parse_interface_output(lines, model_number, hostname)
        cleaned_output = [l.strip() for block in interfaces_blocks for l in block if l.strip()]
        macro_start = f"{{% macro {macro_name}() %}}"
        macro_end = "{% endmacro %}"
        new_macro_block = "\n".join([macro_start] + cleaned_output + [macro_end]) + "\n"
        return new_macro_block
    except Exception as e:
        return f"{ip}: {e}"

def get_ips_from_sping_output(ip_txt="ip.txt"):
    ips = []
    with open(ip_txt, encoding="utf-8") as f:
        for line in f:
            if re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", line):
                if re.search(r"(cisco|pkix)", line, re.IGNORECASE):
                    ip = line.split()[0]
                    ips.append(ip)
    return ips

stop_batch_flag = threading.Event()

def sping_serial_subnets_with_parallel_ssh(input_file, match_models, sping_script="sping.py", sping_output="ip.txt", output_box=None, ssh_parallel=10):
    with open(input_file, "r", encoding="utf-8") as f:
        subnets = [line.strip() for line in f if line.strip()]
    for idx, subnet in enumerate(subnets, 1):
        if stop_batch_flag.is_set():
            if output_box:
                output_box.insert("end", "\nBatch stoppet af bruger.\n")
                output_box.config(state="disabled")
            return
        if output_box:
            output_box.config(state="normal")
            output_box.insert("end", f"\n[{idx}/{len(subnets)}] Kører sping.py på {subnet} ...\n")
            output_box.update()
        proc = subprocess.run(["python", sping_script, subnet], capture_output=True, text=True)
        with open(sping_output, "w", encoding="utf-8") as outf:
            outf.write(proc.stdout)
        ips = get_ips_from_sping_output(sping_output)
        if output_box:
            output_box.insert("end", f"SSH til {len(ips)} IP'er fundet i {subnet}...\n")
            output_box.update()
        failed = []
        def config_worker(ip):
            return get_config(ip, SSH_USERNAME, SSH_PASSWORD, match_models)
        with concurrent.futures.ThreadPoolExecutor(max_workers=ssh_parallel) as executor:
            config_results = list(executor.map(config_worker, ips))
        for ip, result in zip(ips, config_results):
            if result:
                failed.append(result)
        if output_box:
            if failed:
                output_box.insert("end", f"Fejl/INFO:\n" + "\n".join(failed) + "\n")
            output_box.insert("end", f"Færdig med subnet {subnet}.\n")
            output_box.update()
    if output_box:
        output_box.insert("end", "\nBatch færdig!\n")
        output_box.config(state="disabled")

def sping_serial_dna(input_file, match_models, sping_script="sping.py", sping_output="ip.txt", output_box=None, ssh_parallel=10):
    with open(input_file, "r", encoding="utf-8") as f:
        subnets = [line.strip() for line in f if line.strip()]
    dna_output_folder = os.path.join(output_root, "DNA")
    os.makedirs(dna_output_folder, exist_ok=True)
    dna_file = os.path.join(dna_output_folder, "dna.txt")
    open(dna_file, "w").close()
    all_failed = []
    macro_blocks = []
    for idx, subnet in enumerate(subnets, 1):
        if stop_batch_flag.is_set():
            if output_box:
                output_box.insert("end", "\nBatch stoppet af bruger (DNA).\n")
                output_box.config(state="disabled")
            return
        if output_box:
            output_box.config(state="normal")
            output_box.insert("end", f"\n[{idx}/{len(subnets)}] Kører sping.py på {subnet} (DNA)...\n")
            output_box.update()
        proc = subprocess.run(["python", sping_script, subnet], capture_output=True, text=True)
        with open(sping_output, "w", encoding="utf-8") as outf:
            outf.write(proc.stdout)
        ips = get_ips_from_sping_output(sping_output)
        if output_box:
            output_box.insert("end", f"SSH til {len(ips)} IP'er fundet i {subnet} (DNA)...\n")
            output_box.update()
        failed = []
        def config_worker(ip):
            res = get_config_dna(ip, SSH_USERNAME, SSH_PASSWORD, match_models)
            if isinstance(res, str) and res.startswith("{% macro"):
                macro_blocks.append(res)
                return None
            return res
        with concurrent.futures.ThreadPoolExecutor(max_workers=ssh_parallel) as executor:
            config_results = list(executor.map(config_worker, ips))
        for ip, result in zip(ips, config_results):
            if result:
                failed.append(result)
        all_failed.extend(failed)
        if output_box:
            if failed:
                output_box.insert("end", f"Fejl/INFO:\n" + "\n".join(failed) + "\n")
            output_box.insert("end", f"Færdig med subnet {subnet} (DNA).\n")
            output_box.update()
    if output_box:
        output_box.insert("end", "\nBatch færdig! (DNA)\n")
        output_box.config(state="disabled")
    try:
        if output_box:
            output_box.insert("end", "\nOmdøber eksisterende template og opretter ny template ...\n")
            output_box.update()
        dnac = DNACAuth(DNAC_URL, DNAC_USER, DNAC_PASS, VERIFY_SSL)
        base_template_id, base_template_json = find_template_id_by_name(dnac, TEMPLATE_NAME)
        dato = datetime.now().strftime("%Y-%m-%d")
        renamed_template_name = f"{TEMPLATE_NAME}_{dato}"
        base_template_json['name'] = renamed_template_name
        rename_template(dnac, base_template_json, renamed_template_name)
        if output_box:
            output_box.insert("end", f"\nTemplate '{TEMPLATE_NAME}' omdøbt til '{renamed_template_name}'\n")
            output_box.update()
        macro_output = "\n\n".join(macro_blocks)
        resp = create_new_template(dnac, base_template_json, NEW_TEMPLATE_NAME, macro_output)
        new_template_id = resp['response']['templateId']
        if output_box:
            output_box.insert("end", f"\nNy template oprettet: {NEW_TEMPLATE_NAME}\n")
            output_box.update()
        time.sleep(120)
        commit_result = commit_template(dnac, new_template_id, f"Batch commit for {NEW_TEMPLATE_NAME}")
        if output_box:
            output_box.insert("end", "\nBatch-commit udført!\n")
            output_box.insert("end", f"DNA Commit response: {commit_result}\n")
            output_box.update()
    except Exception as e:
        if output_box:
            output_box.insert("end", f"\nFEJL i batch-commit: {e}\n")
            output_box.update()
    return all_failed
def do_ping_one_ip():
    stop_batch_flag.clear()
    the_ip = ip_entry.get().strip()
    if not the_ip:
        messagebox.showwarning("Fejl", "Indtast en IP eller subnet først!")
        return
    tmp_file = os.path.join(output_root, "__oneip.txt")
    with open(tmp_file, "w", encoding="utf-8") as f:
        f.write(the_ip + "\n")
    match_models = get_selected_models()
    text_area.config(state="normal")
    text_area.delete(1.0, tk.END)
    text_area.insert(tk.END, f"Starter batch ping/SSH for én IP/Subnet: {the_ip}\n")
    text_area.config(state="disabled")
    root.update()
    threading.Thread(
        target=sping_serial_subnets_with_parallel_ssh,
        args=(tmp_file, match_models, SPING_SCRIPT, SPING_IP_TXT, text_area, 10),
        daemon=True
    ).start()

def do_dna_one_ip():
    stop_batch_flag.clear()
    the_ip = ip_entry.get().strip()
    if not the_ip:
        messagebox.showwarning("Fejl", "Indtast en IP eller subnet først!")
        return
    tmp_file = os.path.join(output_root, "__oneip.txt")
    with open(tmp_file, "w", encoding="utf-8") as f:
        f.write(the_ip + "\n")
    match_models = get_selected_models()
    text_area.config(state="normal")
    text_area.delete(1.0, tk.END)
    text_area.insert(tk.END, f"Starter DNA for én IP/Subnet: {the_ip}\n")
    text_area.config(state="disabled")
    root.update()
    threading.Thread(
        target=sping_serial_dna,
        args=(tmp_file, match_models, SPING_SCRIPT, SPING_IP_TXT, text_area, 10),
        daemon=True
    ).start()

def do_ping_from_file():
    stop_batch_flag.clear()
    file_path = filedialog.askopenfilename(title="Vælg txt-fil med subnets/IP'er", filetypes=[("Text files", "*.txt")])
    if not file_path:
        return
    match_models = get_selected_models()
    text_area.config(state="normal")
    text_area.delete(1.0, tk.END)
    text_area.insert(tk.END, "Starter batch sping (én linje ad gangen, SSH x10 for hver)...\n")
    text_area.config(state="disabled")
    root.update()
    threading.Thread(
        target=sping_serial_subnets_with_parallel_ssh,
        args=(file_path, match_models, SPING_SCRIPT, SPING_IP_TXT, text_area, 10),
        daemon=True
    ).start()

def do_dna_from_file():
    stop_batch_flag.clear()
    file_path = filedialog.askopenfilename(title="Vælg txt-fil med subnets/IP'er", filetypes=[("Text files", "*.txt")])
    if not file_path:
        return
    match_models = get_selected_models()
    text_area.config(state="normal")
    text_area.delete(1.0, tk.END)
    text_area.insert(tk.END, "Starter DNA batch (ALT til DNA/dna.txt, SSH x10 for hver)...\n")
    text_area.config(state="disabled")
    root.update()
    threading.Thread(
        target=sping_serial_dna,
        args=(file_path, match_models, SPING_SCRIPT, SPING_IP_TXT, text_area, 10),
        daemon=True
    ).start()

def stop_batch():
    stop_batch_flag.set()

def open_output_folder():
    os.startfile(output_root)

def exit_app():
    root.destroy()

def get_selected_models():
    return [model for model, var in match_model_vars.items() if var.get()]

root = tk.Tk()
root.title("Switch Configuration Tool")
window_width = 750
window_height = 1200
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
center_x = int(screen_width / 2 - window_width / 2)
center_y = int(screen_height / 2 - window_height / 2)
root.geometry(f"{window_width}x{window_height}+{center_x}+{center_y}")
root.configure(bg="#f0f0f0")

label_font = ("Segoe UI", 11)
entry_width = 35
button_width = 32

frame_top = tk.Frame(root, bg="#f0f0f0")
frame_top.grid(row=0, column=0, columnspan=2, sticky="w", padx=0, pady=0)

tk.Label(frame_top, text="IP-adresse / Subnet:", bg="#f0f0f0", font=label_font, anchor="w").grid(row=0, column=0, sticky="w", padx=10, pady=10)
ip_entry = tk.Entry(frame_top, font=label_font, width=entry_width)
ip_entry.grid(row=0, column=1, padx=10, pady=5, sticky="w")

button_style = {
    "padx": 6,
    "pady": 6,
    "bd": 3,
    "relief": tk.RAISED,
    "bg": "#d1e7dd",
    "activebackground": "#a3cfbb",
    "font": label_font,
    "width": button_width,
    "anchor": "w",
    "justify": "left"
}

ping_button = tk.Button(frame_top, text="Kør for én IP/Subnet", command=do_ping_one_ip, **button_style)
ping_button.grid(row=1, column=0, padx=10, pady=6, sticky="w", columnspan=2)

pingfile_button = tk.Button(frame_top, text="Ping fra fil (txt) + SSH x10", command=do_ping_from_file, **button_style)
pingfile_button.grid(row=2, column=0, padx=10, pady=6, sticky="w", columnspan=2)

dna_button = tk.Button(frame_top, text="DNA (ALT output til DNA/dna.txt, fra fil)", command=do_dna_from_file, **button_style)
dna_button.grid(row=3, column=0, padx=10, pady=6, sticky="w", columnspan=2)

dna_oneip_button = tk.Button(frame_top, text="DNA (ALT output til DNA/dna.txt, én IP/Subnet)", command=do_dna_one_ip, **button_style)
dna_oneip_button.grid(row=4, column=0, padx=10, pady=6, sticky="w", columnspan=2)

stop_button = tk.Button(frame_top, text="Stop batch", command=stop_batch, **button_style)
stop_button.grid(row=5, column=0, padx=10, pady=6, sticky="w", columnspan=2)

output_button = tk.Button(frame_top, text="Åbn Outputmappe", command=open_output_folder, **button_style)
output_button.grid(row=6, column=0, padx=10, pady=6, sticky="w", columnspan=2)

exit_button = tk.Button(frame_top, text="Afslut", command=exit_app, **button_style)
exit_button.grid(row=7, column=0, padx=10, pady=6, sticky="w", columnspan=2)

match_model_labelframe = tk.LabelFrame(root, text="Enheder til SKAL IKKE SKIFTES (fravælg for at ignorere)", font=label_font, bg="#f0f0f0")
match_model_labelframe.grid(row=1, column=0, columnspan=2, sticky="w", padx=10, pady=10)

match_model_vars = {}
for i, model in enumerate(MATCH_MODELS_DEFAULT):
    var = tk.BooleanVar(value=True)
    match_model_vars[model] = var
    c = tk.Checkbutton(match_model_labelframe, text=model, variable=var, bg="#f0f0f0", font=label_font)
    c.grid(row=i//6, column=i%6, sticky="w", padx=6, pady=2)

text_area = scrolledtext.ScrolledText(root, height=38, width=90, font=label_font, state="disabled", wrap="word")
text_area.grid(row=2, column=0, columnspan=2, padx=8, pady=10, sticky="w")

root.mainloop()	