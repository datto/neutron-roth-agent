# Copyright 2012 Cisco Systems, Inc.
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

import sys

import oslo_messaging
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import service
from oslo_concurrency import lockutils

from neutron.common import config as common_config
from neutron.common import profiler as setup_profiler
from neutron.conf.agent import common as agent_config
from neutron.conf import service as service_config
import neutron_roth_agent.roth_agent_manager as dam
import neutron_roth_agent.roth_agent as da
import neutron_roth_agent.helpers as helpers

LOG = logging.getLogger(__name__)


@lockutils.synchronized("setup_tenant_vrf", external=True)
def setup_tenant_vrf(
    vni, bridge_id, gateways, transit, segment_id, router_id,
    bgp_id, bgp_peer, router_networks
):
    # Get vtysh running configuration
    vtysh_config = helpers.get_vtysh_config()
    asn = helpers.get_asn(vtysh_config)
    if not asn:
        LOG.warning("No BGP ASN found! Aborting...")
        return "FAILURE: No BGP ASN found!"

    # Get the loopback IP address
    loopback_ip = helpers.get_ip("lo")

    # Create tenant l3 vni bridge
    ten_l3bridge_id = "brt%s" % vni
    helpers.ensure_bridge(ten_l3bridge_id)

    # Create tenant l3 vni vxlan interface
    l3vxlan = "vxlan%s" % vni
    helpers.ensure_vxlan(ten_l3bridge_id, l3vxlan, vni, loopback_ip)

    # Create vrf
    vrf_id = "vrf%s" % vni
    helpers.ensure_vrf(vrf_id, vni)

    # Create tenant l2 vni bridge
    ten_l2bridge_id = "brt%s" % segment_id
    helpers.ensure_bridge(ten_l2bridge_id)

    # Delete the linuxbridge-agent l2 vlxan and replace with a dummy
    dummy = "vxlan-%s" % segment_id
    helpers.ensure_dummy(dummy, bridge_id, segment_id)

    # Create tenant l2 vni vxlan interface
    l2vxlan = "l2vx%s" % segment_id
    helpers.ensure_vxlan(ten_l2bridge_id, l2vxlan, segment_id, loopback_ip)

    # Add tenant bridges to tenant vrf
    helpers.add_bridge_to_vrf(vrf_id, ten_l3bridge_id)
    helpers.add_bridge_to_vrf(vrf_id, ten_l2bridge_id)

    # Add gateways to tenant l2 bridge
    helpers.delete_orphaned_gateways(ten_l2bridge_id, gateways)
    for gateway in gateways:
        (gateway, prefix) = gateway.split("/")
        helpers.ensure_gateway(ten_l2bridge_id, gateway, prefix)

    # Enable neighbor suppression on the l2 tenant bridge
    helpers.ensure_neigh_suppress(ten_l2bridge_id)

    # Link the tap bridge to the l2 tenant bridge
    vethq = "vethq%s" % segment_id
    vetht = "vetht%s" % segment_id
    helpers.ensure_vwire(bridge_id, ten_l2bridge_id, vethq, vetht)

    # Configure FRR on the hypervisor
    helpers.ensure_frr_config(vrf_id, vni, vtysh_config, asn, bgp_id, router_networks)

    # Configure FRR in the router namespace
    if router_id:
        helpers.ensure_frr_namespace(
            router_id, bgp_id, bgp_peer, router_networks, asn, vrf_id
        )

    # Add host route for transit subnet
    if transit:
        for gateway in gateways:
            helpers.ensure_host_route(
                vrf_id, asn, transit, gateways
            )

    # Add MAC address to bridge
    helpers.ensure_mac_address(ten_l2bridge_id, transit)

    return "SUCCESS: setup_tenant_vrf ran successfully!"


class RotHManager(dam.RotHAgentManager):
    def __init__(self):
        super(RotHManager, self).__init__()
        LOG.info("Initializing roth manager...")

    def get_agent_configurations(self):
        configurations = {"Agent": "roth_agent"}  # Placeholder
        return configurations

    def get_rpc_callbacks(self, context, agent):
        return RotHRpcCallbacks(context, agent)


class RotHRpcCallbacks(dam.RotHAgentManagerRpcCallBack):

    target = oslo_messaging.Target(version="1.0")

    def call_setup_tenant_vrf(self, context, **kwargs):
        try:
            vni = str(kwargs.get("vni"))
            bridge_id = kwargs.get("bridge_id")
            gateways = kwargs.get("gateways")
            transit = kwargs.get("transit")
            segment_id = str(kwargs.get("segment_id"))
            router_id = kwargs.get("router_id")
            bgp_id = kwargs.get("bgp_id")
            bgp_peer = kwargs.get("bgp_peer")
            router_networks = kwargs.get("router_networks")
            LOG.info("""Client Request: call_setup_tenant_vrf:vni=%s,
                bridge_id=%s, gateways=%s, transit=%s, segment_id=%s,
                router_id=%s, bgp_id=%s, bgp_peer=%s, router_networks=%s""" % (
                    vni, bridge_id, gateways, transit, segment_id,
                    router_id, bgp_id, bgp_peer, router_networks
                )
            )
            result = setup_tenant_vrf(
                vni, bridge_id, gateways, transit, segment_id, router_id,
                bgp_id, bgp_peer, router_networks
            )
            return result
        except Exception as e:
            LOG.error("setup_tenant_vrf: %s" % e)
            return "FAILURE: setup_tenant_vrf encountered an error: %s" % e

    def call_delete_tenant_vrf(self, context, **kwargs):
        try:
            segment_id = str(kwargs.get("segment_id"))
            LOG.info(
                """
                Client Request: call_delete_tenant_vrf for segment %s"""
                % segment_id
            )
            # First delete the l2vxlan config for the specific network
            # that was deleted. Then run a full sweep to cleanup any
            # remaining configuration, including orphaned vrfs.
            # Linuxbridgeagent will delete the veths and dummy interface
            helpers.delete_orphaned_links({"brt%s" % segment_id, "l2vx%s" % segment_id})
            helpers.delete_orphaned_links(helpers.get_orphaned_links())
        except Exception as e:
            LOG.error("delete_tenant_vrf: %s" % e)


def main():
    common_config.init(sys.argv[1:])

    common_config.setup_logging()
    agent_config.setup_privsep()

    manager = RotHManager()

    service_config.register_service_opts(service_config.RPC_EXTRA_OPTS, cfg.CONF)

    polling_interval = cfg.CONF.AGENT.polling_interval
    quitting_rpc_timeout = cfg.CONF.AGENT.quitting_rpc_timeout
    agent = da.RotHAgentLoop(
        manager,
        polling_interval,
        quitting_rpc_timeout,
        "RotH agent",
        "neutron-roth-agent",
    )
    setup_profiler.setup("neutron-roth-agent", cfg.CONF.host)
    LOG.info("RotH neutron agent initialized successfully, now running...")
    launcher = service.launch(cfg.CONF, agent, restart_method="mutate")
    launcher.wait()
