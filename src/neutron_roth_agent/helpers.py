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

import time
import json
import re
import os
import neutron_roth_agent.parseconfig as conf
from neutron_roth_agent.data.roth_startup import get_bgp_password, get_asn
from oslo_log import log as logging
from jinja2 import Environment, FileSystemLoader, TemplateNotFound, exceptions
from neutron.agent.linux import utils  # TODO: replace run_as_root

LOG = logging.getLogger(__name__)


def cleanup_file(file):
    try:
        os.remove(file)
    except PermissionError:
        LOG.warning("Permission error removing file: %s" % file)
    except FileNotFoundError:
        pass


def get_ip(interface):
    try:
        ip_output = utils.execute(["ip", "-j", "addr"])
    except RuntimeError:
        LOG.exception("Failed to get ip details!")

    if not ip_output:
        return None

    iface = [x for x in json.loads(ip_output.strip()) if x["ifname"] == interface]
    ip = [x for x in iface[0]["addr_info"] if x["prefixlen"] == 32]
    return ip[0]["local"]


def ensure_bridge(bridge_id):
    try:
        ip_output = utils.execute(
            ["ip", "-j", "link", "show", "dev", bridge_id], extra_ok_codes=[1]
        )
    except RuntimeError:
        LOG.exception("Failed to check tenant bridge existence: %s" % bridge_id)

    # Check if we found the bridge if not add it
    if not ip_output:
        try:
            command = [
                "ip",
                "link",
                "add",
                bridge_id,
                "mtu",
                "8950",
                "type",
                "bridge",
            ]
            LOG.info("IP Configuration: %s" % (" ".join(command)))
            utils.execute(command, check_exit_code=True, run_as_root=True)
        except RuntimeError:
            LOG.exception("Failed to add tenant bridge: %s" % bridge_id)

        # Disable ipv6 on the bridge before
        # bringing it online
        disable_ipv6(bridge_id)

        try:
            command = ["ip", "link", "set", bridge_id, "up"]
            LOG.info("IP Configuration: %s" % (" ".join(command)))
            utils.execute(command, check_exit_code=True, run_as_root=True)
        except RuntimeError:
            LOG.exception("Failed to up tenant bridge: %s" % bridge_id)


def ensure_vxlan(bridge_id, vxlan, vni, vxlan_vtep_ip):
    try:
        ip_output = utils.execute(
            ["ip", "-j", "link", "show", "dev", vxlan], extra_ok_codes=[1]
        )
    except RuntimeError:
        LOG.exception("Failed to check vxlan existence: %s" % vxlan)

    # If the interface was found, ensure it is bound to the tenant bridge
    if ip_output:
        try:
            vxlan_json = json.loads(ip_output)
            if "master" not in vxlan_json[0]:
                command = ["ip", "link", "set", vxlan, "master", bridge_id]
                LOG.info("IP Configuration: %s" % (" ".join(command)))
                utils.execute(command, check_exit_code=True, run_as_root=True)
                # Bounce the interface after setting the bridge master
                command = ["ip", "link", "set", vxlan, "down"]
                LOG.info("IP Configuration: %s" % (" ".join(command)))
                utils.execute(command, check_exit_code=True, run_as_root=True)
                command = ["ip", "link", "set", vxlan, "up"]
                LOG.info("IP Configuration: %s" % (" ".join(command)))
                utils.execute(command, check_exit_code=True, run_as_root=True)
        except RuntimeError:
            LOG.exception(
                "Failed to set tenant vxlan: %s master to bridge: %s"
                % (vxlan, bridge_id)
            )

    # If vxlan was not found create it and add it to the bridge
    if not ip_output:
        try:
            command = [
                "ip",
                "link",
                "add",
                vxlan,
                "mtu",
                "8950",
                "type",
                "vxlan",
                "id",
                vni,
                "local",
                vxlan_vtep_ip,
                "dstport",
                "4789",
                "nolearning",
            ]
            LOG.info("IP Configuration: %s" % (" ".join(command)))
            utils.execute(command, check_exit_code=True, run_as_root=True)
        except RuntimeError:
            LOG.exception(
                "Failed to add tenant vxlan: %s with vni: %s and vxlan_vtep_ip: %s"
                % (vxlan, vni, vxlan_vtep_ip)
            )

        try:
            command = ["ip", "link", "set", vxlan, "master", bridge_id]
            LOG.info("IP Configuration: %s" % (" ".join(command)))
            utils.execute(command, check_exit_code=True, run_as_root=True)
        except RuntimeError:
            LOG.exception(
                "Failed to set tenant vxlan: %s master to bridge: %s"
                % (vxlan, bridge_id)
            )

        try:
            command = ["ip", "link", "set", vxlan, "up"]
            LOG.info("IP Configuration: %s" % (" ".join(command)))
            utils.execute(command, check_exit_code=True, run_as_root=True)
        except RuntimeError:
            LOG.exception("Failed to up tenant vxlan: %s" % vxlan)


def ensure_gateway(bridge_id, gateway, prefix):
    try:
        ip_output = utils.execute(["ip", "-j", "addr"])
    except RuntimeError:
        LOG.exception("Failed to get ip details!")

    if ip_output is None:
        return None

    brdg = [x for x in json.loads(ip_output.strip()) if x["ifname"] == bridge_id]
    gw = [x for x in brdg[0]["addr_info"] if x["local"] == gateway and str(x["prefixlen"]) == prefix]
    if len(gw) == 0:
        try:
            gateway_with_prefix = "%s/%s" % (gateway, prefix)
            command = ["ip", "address", "add", gateway_with_prefix, "dev", bridge_id]
            LOG.info("IP Configuration: %s" % (" ".join(command)))
            utils.execute(command, check_exit_code=True, run_as_root=True, extra_ok_codes=[2])
        except RuntimeError:
            LOG.exception(
                "Failed to add gateway: %s to bridge: %s"
                % (gateway_with_prefix, bridge_id)
            )


def ensure_neigh_suppress(bridge_id):
    try:
        ip_output = utils.execute(
            ["ip", "-d", "-j", "link", "show", "type", "vxlan", "master", bridge_id],
            extra_ok_codes=[1],
        )
    except RuntimeError:
        LOG.exception(
            "Failed to get vxlan interface details for bridge master: %s" % bridge_id
        )

    if ip_output is None:
        return None

    vxlan_json = json.loads(ip_output)
    if not vxlan_json[0]["linkinfo"]["info_slave_data"]["neigh_suppress"]:
        try:
            command = [
                "bridge",
                "link",
                "set",
                "dev",
                vxlan_json[0]["ifname"],
                "neigh_suppress",
                "on",
            ]
            LOG.info("Bridge Configuration: %s" % (" ".join(command)))
            utils.execute(command, check_exit_code=True, run_as_root=True)
        except RuntimeError:
            LOG.exception(
                "Failed configure neighbor suppression for bridge: %s"
                % vxlan_json[0]["ifname"]
            )


def ensure_mac_address(bridge_id, transit):
    try:
        ip_output = utils.execute(
            ["ip", "-j", "link", "show", "dev", bridge_id], extra_ok_codes=[1]
        )
    except RuntimeError:
        LOG.exception("Failed to get bridge interface details: %s" % bridge_id)

    if ip_output:
        output = json.loads(ip_output.strip())
        command = False
        if (
            "address" in output[0]
            and output[0]["address"] != conf.OS_BRIDGE_MAC
            and not transit
        ):
            command = [
                "ip",
                "link",
                "set",
                "dev",
                bridge_id,
                "address",
                conf.OS_BRIDGE_MAC,
            ]
        elif "address" in output[0] and output[0]["address"] != conf.TRANSIT_MAC and transit:
            command = [
                "ip",
                "link",
                "set",
                "dev",
                bridge_id,
                "address",
                conf.TRANSIT_MAC,
            ]
        if command:
            try:
                time.sleep(1)
                LOG.info("IP Configuration: %s" % (" ".join(command)))
                utils.execute(command, check_exit_code=True, run_as_root=True)
            except RuntimeError:
                LOG.exception(
                    "Failed to configure mac address for bridge: %s" % bridge_id
                )


def ensure_vrf(vrf_id, vni):
    try:
        ip_output = utils.execute(
            ["ip", "-j", "link", "show", "dev", vrf_id], extra_ok_codes=[1]
        )
    except RuntimeError:
        LOG.exception("Failed to get vrf interface details: %s" % vrf_id)

    if not ip_output:
        try:
            command = ["ip", "link", "add", vrf_id, "type", "vrf", "table", vni]
            LOG.info("IP Configuration: %s" % (" ".join(command)))
            utils.execute(command, check_exit_code=True, run_as_root=True)
        except RuntimeError:
            LOG.exception(
                "Failed to add vrf interface: %s with vni: %s" % (vrf_id, vni)
            )

        try:
            command = ["ip", "link", "set", vrf_id, "up"]
            LOG.info("IP Configuration: %s" % (" ".join(command)))
            utils.execute(command, check_exit_code=True, run_as_root=True)
        except RuntimeError:
            LOG.exception("Failed to up vrf: %s" % vrf_id)


def ensure_iptables(vni, bridge_id, ip_address, mac_address):
    if not ip_address or not mac_address:
        LOG.info(
            "No ip_address (%s) or mac_address (%s) provided"
            % (ip_address, mac_address)
        )
        return True

    try:
        fdb_output = json.loads(
            utils.execute(
                ["bridge", "-j", "fdb", "show", "br", bridge_id], extra_ok_codes=[1]
            )
        )
    except RuntimeError:
        LOG.exception(
            "Failed to lookup bridge fdb info for iptables configuration: %s %s"
            % (ip_address, mac_address)
        )
        return False

    if fdb_output:
        try:
            ifname = next(x["ifname"] for x in fdb_output if x["mac"] == mac_address)
            ichain = 'neutron-linuxbri-i%s' % ifname.replace('tap', '')[0:10]
        except NameError:
            LOG.exception(
                "Failed to find the tap interface for iptables configuration: %s %s"
                % (bridge_id, mac_address)
            )
            return False

        try:
            forward_entry_exists = True
            roth_chain_exists = True
            rule_exists = True
            command = ["iptables", "-C", "FORWARD", "-j", "neutron-roth-protected-chain"]
            stdout, stderr = utils.execute(
                command,
                check_exit_code=False,
                return_stderr=True,
                log_fail_as_error=False,
                run_as_root=True
            )
            if stderr:
                forward_entry_exists = False
        except RuntimeError:
            LOG.exception("Unable to determine the existence of the FORWARD chain rule!")
            forward_entry_exists = False

        try:
            command = ["iptables", "-L", "neutron-roth-protected-chain"]
            stdout, stderr = utils.execute(
                command,
                check_exit_code=False,
                return_stderr=True,
                log_fail_as_error=False,
                run_as_root=True
            )
            if stderr:
                roth_chain_exists = False
                rule_exists = False
        except RuntimeError:
            LOG.exception("Unable to determine the existence of neutron-roth-protected-chain!")
            roth_chain_exists = False
            rule_exists = False

        if rule_exists:
            try:
                command = [
                    "iptables",
                    "-C",
                    "neutron-roth-protected-chain",
                    "--dst",
                    ip_address,
                    "-m",
                    "physdev",
                    "--physdev-in",
                    "vxlan%s" % vni,
                    "-j",
                    ichain
                ]
                stdout, stderr = utils.execute(
                    command,
                    check_exit_code=False,
                    return_stderr=True,
                    log_fail_as_error=False,
                    run_as_root=True
                )
                if stderr:
                    rule_exists = False
            except RuntimeError:
                LOG.exception("Unable to check neutron-roth-protected-chain for a given rule!")
                rule_exists = False

        if not roth_chain_exists:
            try:
                command = ["iptables", "-N", "neutron-roth-protected-chain"]
                utils.execute(command, check_exit_code=True, run_as_root=True)
            except RuntimeError:
                LOG.exception("neutron-roth-protected-chain could not be created!")
                return False

        if not rule_exists:
            try:
                command = [
                    "iptables",
                    "-A",
                    "neutron-roth-protected-chain",
                    "--dst",
                    ip_address,
                    "-m",
                    "physdev",
                    "--physdev-in",
                    "vxlan%s" % vni,
                    "-j",
                    ichain
                ]
                utils.execute(command, check_exit_code=True, run_as_root=True)
            except RuntimeError:
                LOG.exception(
                    "Could not add a rule in neutron-roth-protected-chain for: %s %s"
                    % (ip_address, ichain)
                )
                return False

        if not forward_entry_exists:
            try:
                command = ["iptables", "-A", "FORWARD", "-j", "neutron-roth-protected-chain"]
                utils.execute(command, check_exit_code=True, run_as_root=True)
            except RuntimeError:
                LOG.exception("FORWARD rule could not be created!")
                return False

    return True


def ensure_host_route(vrf_id, asn, host_route, gateway):
    remove_legacy_route = False
    ip_output = False
    # Check for an existing host route
    try:
        json_output = json.loads(
            utils.execute(
                ["ip", "-j", "route", "show", "vrf", vrf_id, host_route["destination"]],
                extra_ok_codes=[1],
            )
        )
        if json_output:
            ip_output = json_output[0]
            # Make dst consistent
            if ip_output["dst"] == "default":
                ip_output["dst"] = "0.0.0.0/0"
            # Exit if requested route already exists
            if (
                host_route["destination"] == ip_output["dst"]
                and host_route["nexthop"] == ip_output["gateway"]
            ):
                return
    except RuntimeError:
        LOG.exception("Failed to get host route for vrf: %s" % vrf_id)

    try:
        json_output = json.loads(
            utils.execute(
                [
                    "ip",
                    "-j",
                    "route",
                    "show",
                    "vrf",
                    vrf_id,
                    "via",
                    host_route["nexthop"],
                ],
                extra_ok_codes=[1],
            )
        )
        if json_output:
            del_output = json_output[0]
            # Make dst consistent
            if del_output["dst"] == "default":
                del_output["dst"] = "0.0.0.0/0"
            if host_route["destination"] != del_output["dst"]:
                remove_legacy_route = True
    except RuntimeError:
        LOG.exception("Failed to lookup route for gateway in vrf: %s" % vrf_id)

    # Add host route to bridge
    if not ip_output or remove_legacy_route:
        try:
            command = ["ip", "route", "show", "vrf", vrf_id, "src", gateway]
            # 10s to configure a host route, otherwise log an error and skip it
            for x in range(6):
                subnet_output = utils.execute(command, extra_ok_codes=[1])
                if not subnet_output:
                    if x == 5:
                        LOG.error("Failed to configure a static host route!")
                        return
                    time.sleep(2)
                else:
                    command = [
                        "ip",
                        "route",
                        "add",
                        "vrf",
                        vrf_id,
                        host_route["destination"],
                        "via",
                        host_route["nexthop"],
                    ]
                    LOG.info("IP Configuration: %s" % (" ".join(command)))
                    utils.execute(command, check_exit_code=True, run_as_root=True)
                    break
        except RuntimeError:
            LOG.exception(
                "Failed to configure a host route for vrf: %s to: %s"
                % (vrf_id, host_route["nexthop"])
            )

        # Add advertisement to FRR
        try:
            command = [
                "vtysh",
                "-c",
                "conf t",
                "-c",
                "router bgp %s vrf %s" % (asn, vrf_id),
                "-c",
                " address-family l2vpn evpn",
            ]
            if host_route["destination"] == "0.0.0.0/0":
                command.append("-c")
                command.append("  default-originate ipv4")
            else:
                command.append("-c")
                command.append("  network %s" % host_route["destination"])
            LOG.info("VTYSH Configuration: %s" % (" ".join(command)))
            utils.execute(command, check_exit_code=True, run_as_root=True)
        except RuntimeError:
            LOG.exception(
                "Failed to configure default-originate for asn: %s and vrf: %s"
                % (asn, vrf_id)
            )

        # Remove legacy route
        if remove_legacy_route:
            try:
                command = [
                    "ip",
                    "route",
                    "del",
                    "vrf",
                    vrf_id,
                    del_output["dst"],
                    "via",
                    host_route["nexthop"],
                ]
                LOG.info("IP Configuration: %s" % (" ".join(command)))
                utils.execute(command, check_exit_code=True, run_as_root=True)
            except RuntimeError:
                LOG.exception(
                    "Failed to delete a legacy host route for vrf: %s to: %s"
                    % (vrf_id, ip_output["gateway"])
                )
            # Remove legacy network advertisement
            try:
                command = [
                    "vtysh",
                    "-c",
                    "conf t",
                    "-c",
                    "router bgp %s vrf %s" % (asn, vrf_id),
                    "-c",
                    " address-family l2vpn evpn",
                ]
                if del_output["dst"] == "0.0.0.0/0":
                    command.append("-c")
                    command.append("  no default-originate ipv4")
                else:
                    command.append("-c")
                    command.append("  no network %s" % del_output["dst"])
                LOG.info("VTYSH Configuration: %s" % (" ".join(command)))
                utils.execute(command, check_exit_code=True, run_as_root=True)
            except RuntimeError:
                LOG.exception(
                    "Failed to remove legacy network advertisement for asn: %s and vrf: %s"
                    % (asn, vrf_id)
                )


def add_bridge_to_vrf(vrf_id, bridge_id):
    try:
        ip_output = utils.execute(
            ["ip", "-j", "link", "show", "dev", bridge_id], extra_ok_codes=[1]
        )
    except RuntimeError:
        LOG.exception("Failed to get bridge interface details: %s" % bridge_id)

    if ip_output:
        output = json.loads(ip_output.strip())
        if ("master" not in output[0]) or (
            "master" in output[0] and output[0]["master"] != vrf_id
        ):
            try:
                command = ["ip", "link", "set", "dev", bridge_id, "master", vrf_id]
                LOG.info("IP Configuration: %s" % (" ".join(command)))
                utils.execute(command, check_exit_code=True, run_as_root=True)
            except RuntimeError:
                LOG.exception(
                    "Failed to set bridge: %s master: %s" % (bridge_id, vrf_id)
                )


def ensure_dummy(dummy, bridge_id, segment_id):
    try:
        ip_output = utils.execute(
            ["ip", "-j", "link", "show", "dev", dummy], extra_ok_codes=[1]
        )
    except RuntimeError:
        LOG.exception("Failed to get dummy interface details: %s" % dummy)

    # Confirm the extistence of the dummy interface
    # by checking that the first altname matches
    # what is expected
    if ip_output:
        output = json.loads(ip_output)
        if "altnames" in output[0]:
            if output[0]["altnames"][0] == "REFERENCE:l2vx%s" % segment_id:
                return
    try:
        command = ["ip", "link", "del", dummy]
        LOG.info("IP Configuration: %s" % (" ".join(command)))
        utils.execute(command, check_exit_code=True, run_as_root=True)
    except RuntimeError:
        LOG.exception("Failed to delete the openstack l2 vxlan: %s" % dummy)
    try:
        command = ["ip", "link", "add", dummy, "type", "dummy"]
        LOG.info("IP Configuration: %s" % (" ".join(command)))
        utils.execute(command, check_exit_code=True, run_as_root=True)
    except RuntimeError:
        LOG.exception("Failed to add a dummy interface: %s" % dummy)
    try:
        command = ["ip", "link", "set", dummy, "master", bridge_id]
        LOG.info("IP Configuration: %s" % (" ".join(command)))
        utils.execute(command, check_exit_code=True, run_as_root=True)
    except RuntimeError:
        LOG.exception(
            "Failed to set master for dummy: %s master %s"
            % (dummy, bridge_id)
        )
    try:
        command = [
            "ip",
            "link",
            "property",
            "add",
            "dev",
            dummy,
            "altname",
            "REFERENCE:l2vx%s" % segment_id
        ]
        LOG.info("IP Configuration: %s" % (" ".join(command)))
        utils.execute(command, check_exit_code=True, run_as_root=True)
    except RuntimeError:
        LOG.exception("Failed to set altname for dummy: %s" % dummy)
    try:
        command = ["ip", "link", "set", dummy, "up"]
        LOG.info("IP Configuration: %s" % (" ".join(command)))
        utils.execute(command, check_exit_code=True, run_as_root=True)
    except RuntimeError:
        LOG.exception("Failed to set dummy up: %s master %s" % dummy)


def ensure_vwire(brq_id, brt_id, vethq, vetht):
    vethq_output, vetht_output = False, False
    # Ensure vethq exists, has the correct master
    # and is up
    try:
        ip_output = utils.execute(
            ["ip", "-j", "link", "show", "dev", vethq], extra_ok_codes=[1]
        )
    except RuntimeError:
        LOG.exception("Failed to get vethq interface details: %s" % vethq)

    if ip_output:
        vethq_output = json.loads(ip_output)
        set_master = False
        if "master" in vethq_output[0]:
            if vethq_output[0]["master"] != brq_id:
                set_master = True
        else:
            set_master = True
        if set_master:
            try:
                command = ["ip", "link", "set", vethq, "master", brq_id]
                LOG.info("IP Configuration: %s" % (" ".join(command)))
                utils.execute(
                    command,
                    check_exit_code=True,
                    run_as_root=True
                )
            except RuntimeError:
                LOG.exception(
                    "Failed to set %s master: %s" % (vethq, brq_id)
                )
        if vethq_output[0]["operstate"] != "UP":
            try:
                command = ["ip", "link", "set", vethq, "up"]
                LOG.info("IP Configuration: %s" % (" ".join(command)))
                utils.execute(
                    command,
                    check_exit_code=True,
                    run_as_root=True
                )
            except RuntimeError:
                LOG.exception("Failed to set %s up" % vethq)
        if vethq_output[0]["mtu"] != 8950:
            try:
                command = ["ip", "link", "set", vethq, "mtu", "8950"]
                LOG.info("IP Configuration: %s" % (" ".join(command)))
                utils.execute(
                    command,
                    check_exit_code=True,
                    run_as_root=True
                )
            except RuntimeError:
                LOG.exception("Failed to set %s mtu" % vethq)

    # Ensure vetht exists, has the correct master
    # and is up
    try:
        ip_output = utils.execute(
            ["ip", "-j", "link", "show", "dev", vetht], extra_ok_codes=[1]
        )
    except RuntimeError:
        LOG.exception("Failed to get vetht interface details: %s" % vetht)

    if ip_output:
        vetht_output = json.loads(ip_output)
        set_master = False
        if "master" in vetht_output[0]:
            if vetht_output[0]["master"] != brt_id:
                set_master = True
        else:
            set_master = True
        if set_master:
            try:
                command = ["ip", "link", "set", vetht, "master", brt_id]
                LOG.info("IP Configuration: %s" % (" ".join(command)))
                utils.execute(
                    command,
                    check_exit_code=True,
                    run_as_root=True
                )
            except RuntimeError:
                LOG.exception(
                    "Failed to set %s master: %s" % (vetht, brt_id)
                )
        if vetht_output[0]["operstate"] != "UP":
            try:
                command = ["ip", "link", "set", vetht, "up"]
                LOG.info("IP Configuration: %s" % (" ".join(command)))
                utils.execute(
                    command,
                    check_exit_code=True,
                    run_as_root=True
                )
            except RuntimeError:
                LOG.exception("Failed to set %s up" % vetht)
        if vetht_output[0]["mtu"] != 8950:
            try:
                command = ["ip", "link", "set", vetht, "mtu", "8950"]
                LOG.info("IP Configuration: %s" % (" ".join(command)))
                utils.execute(
                    command,
                    check_exit_code=True,
                    run_as_root=True
                )
            except RuntimeError:
                LOG.exception("Failed to set %s mtu" % vetht)

    # If one or both of the veth peers do not exist,
    # create them
    if not vethq_output or not vetht_output:
        try:
            command = [
                "ip",
                "link",
                "add",
                vethq,
                "type",
                "veth",
                "peer",
                "name",
                vetht
            ]
            LOG.info("IP Configuration: %s" % (" ".join(command)))
            utils.execute(command, check_exit_code=True, run_as_root=True)
        except RuntimeError:
            LOG.exception(
                "Failed to create a vwire: %s peer %s" % (vethq, vetht)
            )
        try:
            command = ["ip", "link", "set", "dev", vethq, "mtu", "8950"]
            LOG.info("IP Configuration: %s" % (" ".join(command)))
            utils.execute(command, check_exit_code=True, run_as_root=True)
        except RuntimeError:
            LOG.exception("Failed to set mtu on veth: %s" % vethq)
        try:
            command = ["ip", "link", "set", "dev", vetht, "mtu", "8950"]
            LOG.info("IP Configuration: %s" % (" ".join(command)))
            utils.execute(command, check_exit_code=True, run_as_root=True)
        except RuntimeError:
            LOG.exception("Failed to set mtu on veth: %s" % vetht)
        try:
            command = ["ip", "link", "set", "dev", vethq, "master", brq_id]
            LOG.info("IP Configuration: %s" % (" ".join(command)))
            utils.execute(command, check_exit_code=True, run_as_root=True)
        except RuntimeError:
            LOG.exception("Failed to set master on %s master %s" % (vethq, brq_id))
        try:
            command = ["ip", "link", "set", "dev", vetht, "master", brt_id]
            LOG.info("IP Configuration: %s" % (" ".join(command)))
            utils.execute(command, check_exit_code=True, run_as_root=True)
        except RuntimeError:
            LOG.exception("Failed to set master on %s master %s" % (vetht, brt_id))
        try:
            command = ["ip", "link", "set", "dev", vethq, "up"]
            LOG.info("IP Configuration: %s" % (" ".join(command)))
            utils.execute(command, check_exit_code=True, run_as_root=True)
        except RuntimeError:
            LOG.exception("Failed to set veth up: %s" % vethq)
        try:
            command = ["ip", "link", "set", "dev", vetht, "up"]
            LOG.info("IP Configuration: %s" % (" ".join(command)))
            utils.execute(command, check_exit_code=True, run_as_root=True)
        except RuntimeError:
            LOG.exception("Failed to set veth up: %s" % vetht)


def ensure_frr_config(vrf_id, vni, vtysh_config, asn, bgp_id, router_networks):
    bgp_pass = get_bgp_password()
    output = re.search("""
route-map QROUTER_OUT deny 1
exit
""", vtysh_config)

    if not output:
        try:
            command = [
                "vtysh",
                "-c",
                "conf t",
                "-c",
                "route-map QROUTER_OUT deny 1",
            ]
            LOG.info("VTYSH Configuration: %s" % (" ".join(command)))
            utils.execute(command, check_exit_code=True, run_as_root=True)
        except RuntimeError:
            LOG.exception(
                "Failed to configure qrouter route-map: %s vni: %s asn: %s"
                % (vrf_id, vni, asn)
            )

    output = re.search(r"""router bgp %s vrf %s
 no bgp ebgp-requires-policy
 no bgp network import-check
 neighbor QROUTER peer-group
 neighbor QROUTER remote-as internal
 neighbor QROUTER bfd
 neighbor QROUTER password %s
 .*
 address-family ipv4 unicast
  redistribute connected
  neighbor QROUTER soft-reconfiguration inbound
  neighbor QROUTER route-map QROUTER_OUT out
 exit-address-family
 !
 address-family l2vpn evpn
  flooding disable
  advertise ipv4 unicast
 exit-address-family
exit
!""" % (asn, vrf_id, bgp_pass), vtysh_config, re.DOTALL)

    if not output:
        try:
            command = [
                "vtysh",
                "-c",
                "conf t",
                "-c",
                "vrf %s" % (vrf_id),
                "-c",
                " vni %s" % (vni),
                "-c",
                " exit-vrf",
                "-c",
                "router bgp %s vrf %s" % (asn, vrf_id),
                "-c",
                " no bgp ebgp-requires-policy",
                "-c",
                " no bgp network import-check",
                "-c",
                " neighbor QROUTER peer-group",
                "-c",
                " neighbor QROUTER remote-as internal",
                "-c",
                " neighbor QROUTER bfd",
                "-c",
                " neighbor QROUTER password %s" % get_bgp_password(),
                "-c",
                " address-family ipv4 unicast",
                "-c",
                "  redistribute connected",
                "-c",
                "  neighbor QROUTER soft-reconfiguration inbound",
                "-c",
                "  neighbor QROUTER route-map QROUTER_OUT out",
                "-c",
                " exit-address-family",
                "-c",
                " address-family l2vpn evpn",
                "-c",
                "  advertise ipv4 unicast",
                "-c",
                "  flooding disable",
                "-c",
                " exit-address-family",
            ]
            LOG.info("VTYSH Configuration: %s" % (" ".join(command)))
            utils.execute(command, check_exit_code=True, run_as_root=True)
        except RuntimeError:
            LOG.exception(
                "Failed to configure frr for vrf: %s vni: %s asn: %s"
                % (vrf_id, vni, asn)
            )

    if not bgp_id or not router_networks:
        return

    output = re.search(r"""router bgp %s vrf %s
 .*
 neighbor %s peer-group QROUTER
 .*
!""" % (asn, vrf_id, bgp_id), vtysh_config, re.DOTALL)

    if not output:
        try:
            command = [
                "vtysh",
                "-c",
                "conf t",
                "-c",
                "router bgp %s vrf %s" % (asn, vrf_id),
                "-c",
                " neighbor %s peer-group QROUTER" % bgp_id,
            ]
            LOG.info("VTYSH Configuration: %s" % (" ".join(command)))
            utils.execute(command, check_exit_code=True, run_as_root=True)
        except RuntimeError:
            LOG.exception(
                "Failed to configure bgp peer for vrf: %s vni: %s asn: %s"
                % (vrf_id, vni, asn)
            )


def get_frr_version():
    try:
        command = ["vtysh", "-c", "show version"]
        LOG.info("VTYSH Show: %s" % (" ".join(command)))
        output = utils.execute(command, run_as_root=True)
        version_regex = re.compile(r"\d\.\d\.\d")
        return version_regex.findall(output)[0]
    except RuntimeError:
        LOG.exception("Failed to get frr version!")
        return False


def render_template(
    template, frr_version='', hostname='', asn='', bgp_id='', bgp_pass='',
    peer_ip='', namespace='', router_networks=[], vrf_id=''
):
    try:
        env = Environment(loader=FileSystemLoader('./'),)
        unrendered = env.get_template(template)
        rendered = unrendered.render(
            frr_version=frr_version,
            hostname=hostname,
            asn=asn,
            bgp_id=bgp_id,
            bgp_pass=bgp_pass,
            peer_ip=peer_ip,
            namespace=namespace,
            router_networks=router_networks,
            vrf_id=vrf_id
        )
        LOG.info("%s template rendered successfully!" % template)
        return rendered
    except TemplateNotFound:
        LOG.exception("Requested template not found: %s" % template)
        return False
    except exceptions.TemplateSyntaxError as e:
        LOG.exception("Syntax error in template: %s\nError: %s" % (template, e))
        return False


def ensure_frr_ns_dir(ns):
    try:
        path = "/etc/frr/%s/" % ns
        command = ["stat", path]
        LOG.info("STAT: %s" % (" ".join(command)))
        path_exists = utils.execute(command, extra_ok_codes=[1], run_as_root=True)
        if path_exists:
            return True
        command = ["mkdir", path]
        LOG.info("MKDIR: %s" % (" ".join(command)))
        utils.execute(command, check_exit_code=True, run_as_root=True)
        return True
    except RuntimeError:
        LOG.exception(
            """Failed to create the frr namespace directory.
            Namespace path was %s""" % dir
        )
        return False


def ensure_frr_ns_daemons(ns, router_id):
    daemons = "/etc/neutron/frr_ns_daemons"
    ns_daemons = "/etc/frr/%s/daemons" % ns
    service = "frr-%s.service" % router_id
    cp = ["cp", daemons, ns_daemons]
    try:
        command = ["stat", ns_daemons]
        LOG.info("STAT: %s" % (" ".join(command)))
        file_exists = utils.execute(command, extra_ok_codes=[1], run_as_root=True)
        if not file_exists:
            LOG.info("COPY: %s" % (" ".join(cp)))
            utils.execute(cp, check_exit_code=True, run_as_root=True)
        else:
            command = ["diff", daemons, ns_daemons]
            LOG.info("DIFF: %s" % (" ".join(command)))
            diff = utils.execute(command, extra_ok_codes=[1], run_as_root=True)
            if diff:
                LOG.info("COPY: %s" % (" ".join(cp)))
                utils.execute(cp, check_exit_code=True, run_as_root=True)
                command = ["systemctl", "restart", service]
                LOG.info("SYSTEMCTL: %s" % (" ".join(command)))
                utils.execute(
                    command,
                    extra_ok_codes=[1, 2],
                    run_as_root=True
                )
        return True
    except (RuntimeError, FileNotFoundError):
        LOG.exception(
            """Failed to find the requested frr daemons files.
            Namespace lookup was %s""" % ns
        )
    return False


def ensure_frr_ns_unit(ns, router_id):
    try:
        unit_conf = render_template("/etc/neutron/frr_ns_service.j2", namespace=ns)
        if not unit_conf:
            return False

        service = "frr-%s.service" % router_id
        filename = "/etc/neutron/frr-%s.service" % router_id
        candidate = "%s.candidate" % filename

        with open(candidate, "w") as f:
            f.write(unit_conf)

        command = ["stat", filename]
        LOG.info("STAT: %s" % (" ".join(command)))
        file_exists = utils.execute(command, extra_ok_codes=[1], run_as_root=True)
        diff = False

        if file_exists:
            command = ["diff", candidate, filename]
            LOG.info("DIFF: %s" % (" ".join(command)))
            diff = utils.execute(command, extra_ok_codes=[1], run_as_root=True)
        if diff or not file_exists:
            LOG.info("WRITE: %s" % filename)
            with open(filename, "w") as f:
                f.write(unit_conf)
            command = ["systemctl", "daemon-reload"]
            LOG.info("SYSTEMCTL: %s" % (" ".join(command)))
            utils.execute(command, check_exit_code=False, run_as_root=True)

        command = ["systemctl", "is-enabled", service]
        LOG.info("SYSTEMCTL: %s" % (" ".join(command)))
        enabled = utils.execute(command, extra_ok_codes=[1, 5], run_as_root=True)

        if "enabled" not in enabled:
            command = ["systemctl", "enable", filename]
            LOG.info("SYSTEMCTL: %s" % (" ".join(command)))
            utils.execute(command, check_exit_code=False, run_as_root=True)

        command = ["systemctl", "is-active", service]
        LOG.info("SYSTEMCTL: %s" % (" ".join(command)))
        active = utils.execute(command, extra_ok_codes=[1, 3], run_as_root=True)

        if "inactive" in active:
            command = ["systemctl", "start", service]
            LOG.info("SYSTEMCTL: %s" % (" ".join(command)))
            utils.execute(command, check_exit_code=False, run_as_root=True)

        # Cleanup temporary files
        cleanup_file(candidate)

        return True

    except FileNotFoundError:
        LOG.exception(
            """Failed to find the requested frr unit files.
            Namespace lookup was %s""" % ns
        )
        return False


def get_frr_ns_runconf(ns):
    try:
        command = [
            "vtysh",
            "-N",
            ns,
            "-c",
            "show running-config no-header",
        ]
        LOG.info("IP Command: %s" % (" ".join(command)))
        return utils.execute(command, extra_ok_codes=[1], run_as_root=True)
    except RuntimeError:
        LOG.info("No FRR running configuration for namespace %s" % ns)
        return False


def ensure_frr_ns_conf(ns, router_id, running, generated):
    try:
        filename = "/etc/frr/%s/frr.conf" % ns
        candidate = "/etc/neutron/%s.frr.conf.candidate" % ns

        # FRR complains about vtysh.conf not existing, so we
        # just ignore it here. Get the two configs as lists
        # for comparison. Any difference yields a complete
        # overwrite and restart
        if "vtysh.conf" in running:
            runconf = running.split()[1:]
        else:
            runconf = running.split()
        genconf = generated.split()
        if runconf == genconf:
            cleanup_file(candidate)
            return "NOCHANGE"

        with open(candidate, "w") as f:
            f.write(generated)

        command = ["cp", candidate, filename]
        LOG.info("COPY: %s" % (" ".join(command)))
        utils.execute(command, check_exit_code=True, run_as_root=True)

        command = ["systemctl", "restart", "frr-%s" % router_id]
        LOG.info("SYSTEMCTL: %s" % (" ".join(command)))
        utils.execute(command, check_exit_code=False, run_as_root=True)

    except FileNotFoundError:
        LOG.exception("Failed to update frr configuration for %s" % ns)
        return False

    finally:
        cleanup_file(candidate)

    return True


def disable_frr_ns_service(service):
    try:
        command = ["systemctl", "stop", service]
        LOG.info("SYSTEMCTL: %s" % (" ".join(command)))
        utils.execute(
            command,
            extra_ok_codes=[5],
            run_as_root=True
        )
        command = ["systemctl", "disable", service]
        LOG.info("SYSTEMCTL: %s" % (" ".join(command)))
        utils.execute(
            command,
            extra_ok_codes=[1],
            run_as_root=True
        )
        return True
    except RuntimeError:
        return False


def ensure_frr_namespace(router_id, bgp_id, bgp_peer, router_networks, asn, vrf_id):
    ns = "qrouter-%s" % router_id

    if not router_networks:
        return disable_frr_ns_service("frr-%s" % router_id)

    if not ensure_frr_ns_dir(ns):
        return False

    if not ensure_frr_ns_daemons(ns, router_id):
        return False

    if not ensure_frr_ns_unit(ns, router_id):
        return False

    get_hostname = utils.execute(["hostname"], check_exit_code=False, run_as_root=True)
    if get_hostname:
        hostname = get_hostname.strip()
    else:
        hostname = "no-hostname"
    frr_version = get_frr_version()
    if False in (asn, frr_version, bgp_peer):
        return False

    # FRR sorts network statements in frr.conf
    # Do that here before generating the configuration
    if len(router_networks) > 1:
        router_networks.sort()
    genconf = render_template(
        "/etc/neutron/frr_ns_conf.j2",
        frr_version=frr_version,
        hostname=hostname,
        asn=asn,
        bgp_id=bgp_id,
        bgp_pass=get_bgp_password(),
        peer_ip=bgp_peer,
        router_networks=router_networks,
        vrf_id=vrf_id
    )

    runconf = get_frr_ns_runconf(ns)
    result = ensure_frr_ns_conf(ns, router_id, runconf, genconf)
    if not result:
        return False

    return True


def get_vtysh_config():
    try:
        output = utils.execute(["vtysh", "-c", "show run"], run_as_root=True)
        return output
    except RuntimeError:
        LOG.exception("Failed to get vtysh configuration!")
        return None


def get_vrf_from_if(ifname):
    try:
        result = re.search(r"qr\-(.*)\-(.*)", ifname)
        id = result.group(1)
    except IndexError:
        LOG.exception("Invalid interface name: %s" % ifname)
        return False

    try:
        interfaceJson = json.loads(utils.execute(["ip", "-j", "link"]))
    except RuntimeError:
        LOG.exception("Failed to get ip link details!")
        return False

    for interface in interfaceJson:
        if interface["ifname"].startswith("tap") and id in interface["ifname"]:
            try:
                command = ["ip", "-j", "link", "show", "dev", interface["master"]]
            except KeyError:
                LOG.warning("No bridge master for %s" % interface["ifname"])
                continue
            try:
                brJson = json.loads(utils.execute(command))
            except RuntimeError:
                LOG.exception(
                    "Failed to fetch link details for %s" % interface["master"]
                )
                continue
            try:
                master = brJson[0]["master"]
                return master
            except (IndexError, KeyError):
                LOG.warning("No vrf master for %s" % interface["master"])

    return False


def remove_host_route(vrf_id):
    # Remove host route from bridge
    try:
        ip_output = json.loads(
            utils.execute(
                [
                    "ip",
                    "-j",
                    "route",
                    "show",
                    "type",
                    "unicast",
                    "proto",
                    "boot",
                    "scope",
                    "global",
                    "vrf",
                    vrf_id,
                ],
                extra_ok_codes=[1],
            )
        )
    except RuntimeError:
        LOG.exception("Failed to get host routes for vrf: %s" % vrf_id)

    if ip_output:
        try:
            bridgeJson = json.loads(
                utils.execute(
                    ["ip", "-j", "link", "show", "type", "bridge", "master", vrf_id]
                )
            )
        except RuntimeError:
            LOG.exception("Failed to get bridges for vrf: %s" % vrf_id)

        for r in ip_output:
            # Here we assume we should delete the route. This covers all cases
            # where there is not a bridge interface with the Transit MAC and a
            # valid ARP entry on the bridge.
            delete_route = True
            for bridge in bridgeJson:
                if r["dev"] == bridge["ifname"] and bridge["address"] == conf.TRANSIT_MAC:
                    try:
                        delete_route = False
                        # Excecute an arping to refresh the arp entry
                        # Wait for the arp entry to update
                        arping(bridge["ifname"], r["gateway"])
                        time.sleep(2)
                        arp_output = json.loads(
                            utils.execute(
                                [
                                    "ip",
                                    "-j",
                                    "neigh",
                                    "show",
                                    "nud",
                                    "reachable",
                                    "dev",
                                    bridge["ifname"],
                                ]
                            )
                        )
                        if not arp_output:
                            delete_route = True
                            break
                        else:
                            # Iterate over the reachable entries and check for the gateway IP
                            # If it is not present, mark the route for deletion
                            gw_found = False
                            for arp in arp_output:
                                if arp["dst"] == r["gateway"]:
                                    gw_found = True
                                    break
                            if not gw_found:
                                delete_route = True
                                break
                    except RuntimeError:
                        LOG.exception(
                            "Failed to get arp entries for bridge: %s"
                            % bridge["ifname"]
                        )
            if delete_route:
                try:
                    # Remove the static host route
                    command = [
                        "ip",
                        "route",
                        "delete",
                        "vrf",
                        vrf_id,
                        r["dst"],
                        "via",
                        r["gateway"],
                    ]
                    LOG.info("IP Configuration: %s" % (" ".join(command)))
                    utils.execute(command, check_exit_code=True, run_as_root=True)
                except RuntimeError:
                    LOG.exception(
                        "Failed to delete host route for vrf: %s via: %s"
                        % (vrf_id, r["gateway"])
                    )
                # Remove host route advertisement
                vtysh_config = get_vtysh_config()
                asn = get_asn(vtysh_config)
                output = False
                for line in vtysh_config:
                    if re.search("router bgp %s vrf %s" % (asn, vrf_id), line):
                        output = True
                        break
                if output:
                    try:
                        command = [
                            "vtysh",
                            "-c",
                            "conf t",
                            "-c",
                            "router bgp %s vrf %s" % (asn, vrf_id),
                            "-c",
                            " address-family l2vpn evpn",
                        ]
                        if r["dst"] == "default":
                            command.append("-c")
                            command.append("  no default-originate ipv4")
                        else:
                            command.append("-c")
                            command.append("  no network %s" % r["dst"])
                        LOG.info("VTYSH Configuration: %s" % (" ".join(command)))
                        utils.execute(command, check_exit_code=True, run_as_root=True)
                    except RuntimeError:
                        LOG.exception(
                            "Failed to remove network advertisement for vrf: %s asn: %s"
                            % (vrf_id, asn)
                        )


def arping(iface, ip):
    try:
        command = ["arping", "-c", "1", "-I", iface, ip]
        LOG.info("Neighbor Manager: %s" % (" ".join(command)))
        utils.execute(command, extra_ok_codes=[1, 2])
    except RuntimeError as e:
        LOG.exception(
            "Failed to arping for interface: %s ip: %s error: %s" % (iface, ip, e)
        )


def get_arp_table():
    try:
        return utils.execute(["ip", "-stats", "-j", "neighbor"])
    except RuntimeError as e:
        LOG.exception("Failed to get neighbor table: %s" % e)


def disable_ipv6(iface):
    try:
        command = ["sysctl", "-w", "net.ipv6.conf.%s.disable_ipv6=1" % iface]
        LOG.info("Sysctl Configuration: %s" % (" ".join(command)))
        utils.execute(command, run_as_root=True)
    except RuntimeError as e:
        LOG.exception(
            "Failed to disable ipv6 on interface %s: %s" % (iface, e)
        )


def delete_link_address(link, address):
    try:
        command = ["ip", "address", "del", address, "dev", link]
        LOG.info("IP Configuration: %s" % (" ".join(command)))
        utils.execute(command, run_as_root=True)
    except RuntimeError:
        LOG.exception("Failed to delete %s from %s" % (address, link))


def delete_service_unit(unit):
    try:
        utils.execute(
            ["systemctl", "stop", unit],
            extra_ok_codes=[5],
            run_as_root=True
        )
        utils.execute(
            ["systemctl", "disable", unit],
            extra_ok_codes=[1],
            run_as_root=True
        )
        cleanup_file("/etc/neutron/%s" % unit)
        cleanup_file("/etc/neutron/%s.candidate" % unit)
        utils.execute(
            ["systemctl", "daemon-reload"],
            check_exit_code=False,
            run_as_root=True
        )
        return True
    except RuntimeError as e:
        LOG.exception("Failed to delete %s: %s" % (unit, e))
        return False


def delete_frr_ns_dir(ns):
    try:
        utils.execute(
            ["rm", "-rf", "/etc/frr/%s" % ns],
            extra_ok_codes=[1],
            run_as_root=True
        )
    except FileNotFoundError:
        pass
    except PermissionError:
        LOG.warning("Permission error trying to remove /etc/frr/%s" % ns)


def delete_orphaned_frr_services():
    try:
        command = ["systemctl", "list-unit-files", "frr-*", "--all"]
        frr = utils.execute(command, run_as_root=True)
        if re.search(r"^0 loaded units", frr, re.DOTALL):
            return
        command = ["ip", "-j", "netns"]
        netns = utils.execute(command, run_as_root=True)
        pattern = re.compile(r'frr\-.+\.service')
        for service in re.findall(pattern, frr):
            chopped = re.sub(".service", "", service)
            qrouter_ns = re.sub("^frr", "qrouter", chopped)
            if not re.search(qrouter_ns, netns, re.DOTALL):
                delete_service_unit(service)
                delete_frr_ns_dir(qrouter_ns)
    except RuntimeError as e:
        LOG.exception("Failed to cleanup legacy frr services: %s" % e)


def delete_peer(asn, vrf, ip):
    command = [
        "vtysh",
        "-c",
        "conf t",
        "-c",
        "router bgp %s vrf %s" % (asn, vrf),
        "-c",
        "no neighbor %s" % ip,
    ]
    try:
        LOG.info("Orphan Manager: %s" % (" ".join(command)))
        utils.execute(command, run_as_root=True)
        return True
    except RuntimeError as e:
        LOG.exception("Failed to cleanup legacy peer: %s" % e)
    return False


def delete_orphaned_peers():
    # Skip all peer deletions if the configured timer is disabled
    if conf.BGP_PEER_DELETE <= 0:
        return
    command = ["vtysh", "-c", "show vrf vni json"]
    vrf_vni = json.loads(utils.execute(command, run_as_root=True))
    if not vrf_vni:
        return
    vrfs = [x["vrf"] for x in vrf_vni["vrfs"]]
    for vrf in vrfs:
        command = ["vtysh", "-c", "show ip bgp vrf %s neighbors json" % vrf]
        neighbors = json.loads(utils.execute(command, run_as_root=True))
        if not neighbors:
            continue
        for n in neighbors:
            # Only delete peers that have been down for more than 24 hours
            # The bgpTimerLatRead is in milliseconds
            if int(neighbors[n]["bgpTimerLastRead"]) > (conf.BGP_PEER_DELETE * 1000):
                delete_peer(neighbors[n]["localAs"], vrf, n)


def delete_orphaned_gateways(iface, gateways):
    try:
        ip_output = json.loads(utils.execute(["ip", "-j", "addr", "show", "dev", iface]))
    except RuntimeError:
        LOG.exception("Failed to get ip details for %s!" % iface)

    if not ip_output:
        return None

    for addr in ip_output[0]["addr_info"]:
        gw = str(addr["local"]) + "/" + str(addr["prefixlen"])
        if gw not in gateways:
            delete_link_address(iface, gw)


def delete_orphaned_links(links):
    asn = ""
    # It's possible there are no links passed here
    # Return to avoid an exception
    if not links:
        return
    for link in links:
        try:
            ip_output = utils.execute(
                ["ip", "-j", "link", "show", "dev", link], extra_ok_codes=[1]
            )
            # Don't try to delete links that do not exist
            if not ip_output:
                continue
        except RuntimeError:
            LOG.exception("Failed to check link existence: %s" % link)
        try:
            command = ["ip", "link", "del", link]
            LOG.info("Orphan Manager: %s" % (" ".join(command)))
            utils.execute(command, run_as_root=True)
        except RuntimeError:
            LOG.exception("Failed to delete link: %s" % link)
        try:
            if link.startswith("vrf"):
                if not asn:
                    vtysh_config = get_vtysh_config()
                    asn = get_asn(vtysh_config)
                command = [
                    "vtysh",
                    "-c",
                    "conf t",
                    "-c",
                    "no router bgp %s vrf %s" % (asn, link),
                    "-c",
                    "vrf %s" % (link),
                    "-c",
                    "no vni %s" % (link.replace("vrf", "")),
                    "-c",
                    "no vrf %s" % (link),
                ]
                LOG.info("Orphan Manager: %s" % (" ".join(command)))
                utils.execute(command, run_as_root=True)
        except RuntimeError:
            LOG.error(
                "Error in vtysh configuration cleanup for link: %s asn: %s"
                % (link, asn)
            )


def get_orphaned_links():
    bridges = set()
    vrfs = set()
    links_to_delete = set()
    vetht_dicts = []
    veths = set()
    try:
        # Gather required output in json format
        veth_json = json.loads(utils.execute(["ip", "-j", "link", "show", "type", "veth"]))
        vrf_json = json.loads(utils.execute(["ip", "-j", "vrf"]))
        bridge_json = json.loads(utils.execute(["ip", "-j", "link", "show", "type", "bridge"]))
        vxlan_json = json.loads(utils.execute(["ip", "-j", "link", "show", "type", "vxlan"]))
        dummy_json = json.loads(utils.execute(["ip", "-j", "link", "show", "type", "dummy"]))
        for veth in veth_json:
            if not veth:
                continue
            if veth["ifname"].startswith("vetht") and "master" in veth and "link" in veth:
                vetht_dicts.append(
                    {"ifname": veth["ifname"], "master": veth["master"], "link": veth["link"]}
                )
        for vetht in vetht_dicts:
            for veth in veth_json:
                if veth["ifname"].startswith("vethq") and "master" in veth and "link" in veth:
                    if veth["link"] == vetht["ifname"]:
                        bridges.add(vetht["master"])
                        veths.add(vetht["ifname"])
                        veths.add(vetht["link"])
        for bridge in bridge_json:
            if "master" in bridge and bridge["ifname"] in bridges:
                vrfs.add(bridge["master"])

        # Orphaned brt interfaces
        for bridge in bridge_json:
            if "master" in bridge:
                if re.search("^vrf[0-9]*$", bridge["master"]):
                    vrf_regex = re.search(r"(\d+)", bridge["ifname"])
                    vrf_id = vrf_regex.group()
                    if "vrf%s" % vrf_id in vrfs:
                        continue
                    elif (
                        bridge["ifname"] not in conf.EXCLUDE_BRIDGE and
                        bridge["ifname"] not in bridges
                    ):
                        links_to_delete.add(bridge["ifname"])
        # Orphaned vxlan interfaces
        for vxlan in vxlan_json:
            if not vxlan:
                continue
            if (
                vxlan["ifname"] == "vxlan1"
                or vxlan["ifname"].startswith("vxlan-")
                or vxlan["ifname"].startswith("vx-")
            ):
                continue
            elif "master" in vxlan:
                if re.search("^brt[0-9]*$", vxlan["master"]):
                    vrf_regex = re.search(r"(\d+)", vxlan["master"])
                    vrf_id = vrf_regex.group()
                    if "vrf%s" % vrf_id in vrfs:
                        continue
                elif vxlan["master"] not in vrfs or vxlan["master"] not in bridges:
                    if vxlan["ifname"] not in conf.EXCLUDE_VXLAN:
                        links_to_delete.add(vxlan["ifname"])
            # Catch l2vx interfaces with no bridge master
            elif "master" not in vxlan:
                if re.search("^l2vx[0-9]*$", vxlan["ifname"]):
                    brt_regex = re.search(r"(\d+)", vxlan["ifname"])
                    brt_id = brt_regex.group()
                    if "brt%s" % brt_id not in bridges:
                        links_to_delete.add(vxlan["ifname"])
        # Orphaned vrf interfaces
        for vrf in vrf_json:
            if not vrf:
                continue
            if vrf["name"] not in vrfs:
                if vrf["name"] not in conf.EXCLUDE_VRF:
                    links_to_delete.add(vrf["name"])
        # Orphaned dummy interfaces
        for dummy in dummy_json:
            if not dummy:
                continue
            if (
                dummy["ifname"].startswith("vxlan-") and
                dummy["operstate"] == "UNKNOWN" and
                "master" not in dummy
            ):
                links_to_delete.add(dummy["ifname"])
        # Orphaned veth interfaces
        for veth in veth_json:
            if not veth:
                continue
            if (
                re.search("^veth[tq]*$", veth["ifname"]) and
                veth["ifname"] not in veths
            ):
                links_to_delete.add(veth["ifname"])
        # Return the set of orphaned links to be deleted
        return links_to_delete
    except Exception as e:
        LOG.error("Unable to get orphaned links: %s" % e)
        return None
