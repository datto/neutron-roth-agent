#!/usr/bin/python3
# Copyright 2022 Datto, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import subprocess
import json
import re
import logging
import configparser

logging.basicConfig(filename="/var/log/frr/bgpd.log", level=logging.DEBUG)


def execute_command(command):
    result = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True
    )
    logging.info("EXECUTE_COMMAND: %s" % command)
    stdout = result.stdout.read()
    if stdout:
        return stdout
    else:
        return None


def get_asn(vtysh_config):
    router_bgp = re.search("router bgp [0-9]*", vtysh_config)
    if router_bgp:
        asn = re.search(r"(\d+)", router_bgp.group())
        if asn:
            try:
                int(asn.group())
                return asn.group()
            except ValueError:
                pass
    return None


def get_bgp_password():
    bgp_pass = "abc123HiFive4u!"
    try:
        config = configparser.ConfigParser()
        config.read('/etc/neutron/roth_agent.ini')
    except FileNotFoundError as e:
        logging.error("ERROR: %s" % e)
        logging.warning("WARNING: Using a default bgp password...")
        return bgp_pass
    if config.has_option("BGP", "BGP_PASSWORD"):
        return config.get("BGP", "BGP_PASSWORD")
    else:
        logging.error("ERROR: No BGP Password found! Ensure /etc/neutron/roth_agent.ini is updated.")
    logging.warning("WARNING: Using a default bgp password...")
    return bgp_pass


def ensure_frr_config(vtysh_config, asn, vrf_id, vni, bgp_pass, bgp_neigh):
    # Check whether vrf + vni already exist
    pattern = rf"vrf {vrf_id}\s+vni {vni}"
    if not re.search(pattern, vtysh_config):
        cmd = (
            f"sudo /usr/bin/vtysh "
            f"-c 'conf t' "
            f"-c 'vrf {vrf_id}' "
            f"-c ' vni {vni}' "
            f"-c 'exit-vrf'"
        )
        execute_command(cmd)

    commands = ["sudo /usr/bin/vtysh", "'conf t'"]
    config_template = """'route-map QROUTER_OUT deny 1'
'exit'
'router bgp %s vrf %s'
' no bgp ebgp-requires-policy'
' no bgp network import-check'
' neighbor QROUTER peer-group'
' neighbor QROUTER remote-as internal'
' neighbor QROUTER bfd'
' neighbor QROUTER password %s'
' address-family ipv4 unicast'
'  redistribute connected'
'  neighbor QROUTER soft-reconfiguration inbound'
'  neighbor QROUTER route-map QROUTER_OUT out'
' exit-address-family'
' address-family l2vpn evpn'
'  advertise ipv4 unicast'
'  flooding disable'
' exit-address-family'""" % (asn, vrf_id, bgp_pass)
    commands += config_template.split("\n")
    execute_command(" -c ".join(commands))

    if not bgp_neigh:
        return
    peer_ips = [n["ip"] for n in bgp_neigh if n["vrf"] == vrf_id]
    peer_statements = ["neighbor %s peer-group QROUTER" % i for i in peer_ips]
    if not peer_statements:
        return
    for ps in peer_statements:
        commands = ["sudo /usr/bin/vtysh", "'conf t'"]
        config_template = """'router bgp %s vrf %s'
' %s'""" % (asn, vrf_id, ps)
        commands += config_template.split("\n")
        execute_command(" -c ".join(commands))


def ensure_default_originate(asn, vrf_id):
    # Check for a static default route in the vrf
    ip_output = execute_command(
        "/sbin/ip route show proto boot scope global type unicast vrf %s default"
        % vrf_id
    )

    # Add default-originate if a static default route
    # is present in the vrf routing table
    if ip_output:
        commands = ["sudo /usr/bin/vtysh", "'conf t'"]
        config_template = """'router bgp %s vrf %s'
' address-family l2vpn evpn'
'  default-originate ipv4'
' exit-address-family'""" % (asn, vrf_id)
        commands += config_template.split("\n")
        execute_command(" -c ".join(commands))


def get_qrouters():
    try:
        output = str(execute_command("systemctl list-unit-files frr-*"), 'UTF-8')
        services = [x for x in output.split() if ".service" in x]
        return [x.replace("frr-", "qrouter-").replace(".service", "") for x in services]
    except Exception as e:
        logging.warning("WARNING: %s" % e)
    return False


def get_qrouter_ip(ns):
    try:
        output = json.loads(execute_command("ip netns exec %s ip -j address" % ns))
        if not output:
            return False
        for interface in output:
            if interface["ifname"].startswith("qg-") and interface["addr_info"][0]["family"] == "inet":
                return interface["addr_info"][0]["local"]
    except Exception as e:
        logging.warning("WARNING: %s" % e)
    return False


def get_qrouter_vrf(ns):
    try:
        output = str(execute_command("sudo /usr/bin/vtysh -N %s -c 'show running-config no-header'" % ns), 'UTF-8')
        if not output:
            return False
        peer = re.search(r"neighbor.*peer-group", output)
        if peer:
            return peer.group().split()[1]
    except Exception as e:
        logging.warning("WARNING: %s" % e)
    return False


def get_bgp_neighbors():
    try:
        neighbors = []
        qrouters = get_qrouters()
        if not qrouters:
            return False
        for q in qrouters:
            ip = get_qrouter_ip(q)
            vrf = get_qrouter_vrf(q)
            if ip and vrf:
                neighbors.append({"ip": ip, "vrf": vrf})
        return neighbors
    except Exception as e:
        logging.warning("WARNING: %s" % e)
    return False


def get_frr_vrfs(vtysh_config):
    """Extract VRF information from FRR config.
    Returns a list of dicts with 'name' and 'table' (VNI) keys."""
    try:
        vrfs = []
        # Find all "router bgp <asn> vrf <vrf_name>" entries
        bgp_vrf_pattern = r"router bgp \d+ vrf (\S+)"
        vrf_matches = re.findall(bgp_vrf_pattern, vtysh_config)

        for vrf_name in vrf_matches:
            # Extract VNI from VRF name (e.g., vrf5002 -> 5002)
            vni_match = re.search(r"vrf(\d+)", vrf_name)
            if vni_match:
                vni = vni_match.group(1)
                vrfs.append({"name": vrf_name, "table": vni})
                logging.info(f"Found BGP VRF: {vrf_name} with VNI: {vni}")

        return vrfs if vrfs else []
    except Exception as e:
        logging.warning("WARNING: %s" % e)
    return []


def main():
    # Ensure FRR config for each vrf
    conf = str(execute_command("/usr/bin/vtysh -c 'show run'"), 'UTF-8')
    asn = get_asn(conf)
    if not asn:
        logging.warning("WARNING: No BGP ASN found! Aborting...")
        return False

    # Try to get VRFs from kernel first
    vrfJson = json.loads(execute_command("/sbin/ip -j vrf show"))

    # If no kernel VRFs, get VRFs from FRR BGP config
    if not vrfJson:
        logging.info("No kernel VRFs found, extracting VRFs from FRR config")
        vrfJson = get_frr_vrfs(conf)

    bgp_pass = get_bgp_password()
    bgp_neighbors = get_bgp_neighbors()
    for vrf in vrfJson:
        ensure_frr_config(conf, asn, vrf["name"], vrf["table"], bgp_pass, bgp_neighbors)
        ensure_default_originate(asn, vrf["name"])


if __name__ == "__main__":
    main()
