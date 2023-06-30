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
import time
import json
import ipaddress
import concurrent.futures

from neutron.agent.linux import utils  # TODO: replace run_as_root
from neutron_lib.agent import topics
from neutron_lib import context
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import loopingcall
from oslo_service import service
from osprofiler import profiler
from oslo_concurrency import lockutils

from neutron.agent import rpc as agent_rpc
from neutron.api.rpc.callbacks import resources
from neutron.common import config as common_config
import neutron_roth_agent.roth_agent_manager as dam
from neutron.plugins.ml2.drivers.agent import capabilities
from neutron.plugins.ml2.drivers.agent import config as cagt_config  # noqa
import neutron_roth_agent.parseconfig as conf
import neutron_roth_agent.helpers as helpers

import oslo_messaging
import socket


LOG = logging.getLogger(__name__)


@profiler.trace_cls("rpc")
class RotHAgentLoop(service.Service):
    def __init__(
        self, manager, polling_interval, quitting_rpc_timeout, agent_type, agent_binary
    ):
        """Constructor.

        :param manager: the manager object containing the impl specifics
        :param polling_interval: interval (secs) to poll DB.
        :param quitting_rpc_timeout: timeout in seconds for rpc calls after
               stop is called.
        :param agent_type: Specifies the type of the agent
        :param agent_binary: The agent binary string
        """
        super(RotHAgentLoop, self).__init__()
        self.mgr = manager
        self._validate_manager_class()
        self.polling_interval = polling_interval
        self.quitting_rpc_timeout = quitting_rpc_timeout
        self.agent_type = agent_type
        self.agent_binary = agent_binary

    def _validate_manager_class(self):
        if not isinstance(self.mgr, dam.RotHAgentManager):
            LOG.error(
                "Manager class must inherit from "
                "RotHAgentManager to ensure RotHAgent "
                "works properly."
            )
            sys.exit(1)

    def start(self):
        LOG.info(f"Neighbor Manager executes every {conf.NBR_MGR_INTERVAL} seconds")
        LOG.info(f"Orphan Manager executes every {conf.ORPHAN_MGR_INTERVAL} seconds")
        LOG.info(f"Route Manager executes every {conf.ROUTE_MGR_INTERVAL} seconds")
        if conf.BGP_PEER_DELETE > 0:
            LOG.info(f"Non-established BGP peers deleted every {conf.BGP_PEER_DELETE} seconds")
        else:
            LOG.info("Non-established BGP peers are never deleted")
        LOG.info(f"Anycast Gateway MAC address is {conf.OS_BRIDGE_MAC}")
        LOG.info(f"Transit Bridge MAC address is {conf.TRANSIT_MAC}")
        if conf.EXCLUDE_BRIDGE:
            LOG.info(f"Excluding bridges from orphan manager: {conf.EXCLUDE_BRIDGE}")
        if conf.EXCLUDE_VRF:
            LOG.info(f"Excluding VRFs from orphan manager: {conf.EXCLUDE_VRF}")
        if conf.EXCLUDE_VXLAN:
            LOG.info(f"Excluding VXLANs from orphan manager: {conf.EXCLUDE_VXLAN}")
        self.context = context.get_admin_context_without_session()
        self.setup_rpc()

        configurations = {}
        configurations.update(self.mgr.get_agent_configurations())

        self.failed_report_state = False

        self.agent_state = {
            "binary": self.agent_binary,
            "host": cfg.CONF.host,
            "topic": "roth_agent",
            "configurations": configurations,
            "agent_type": self.agent_type,
            "resource_versions": resources.LOCAL_RESOURCE_VERSIONS,
            "start_flag": True,
        }

        report_interval = cfg.CONF.AGENT.report_interval
        if report_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(self._report_state)
            heartbeat.start(interval=report_interval)

        # Host route manager
        route_mgr = loopingcall.FixedIntervalLoopingCall(self._host_route)
        route_mgr.start(interval=conf.ROUTE_MGR_INTERVAL)

        # Neighbor manager
        nbr_mgr = loopingcall.FixedIntervalLoopingCall(self._neighbor_manager)
        nbr_mgr.start(interval=conf.NBR_MGR_INTERVAL)

        # Cleanup orphaned links
        orphan_mgr = loopingcall.FixedIntervalLoopingCall(self._orphan_manager)
        orphan_mgr.start(interval=conf.ORPHAN_MGR_INTERVAL)

        capabilities.notify_init_event(self.agent_type, self)

        self.daemon_loop()

    def stop(self, graceful=True):
        LOG.info("Stopping %s agent.", self.agent_type)
        super(RotHAgentLoop, self).stop(graceful)

    def reset(self):
        common_config.setup_logging()

    def _report_state(self):
        try:
            self.agent_state.get("configurations")
            agent_status = self.state_rpc.report_state(
                self.context, self.agent_state, True
            )
            LOG.info("Agent status report: %s", agent_status)
        except Exception:
            self.failed_report_state = True
            LOG.exception("Failed reporting state!")
            return
        if self.failed_report_state:
            self.failed_report_state = False
            LOG.info("Successfully reported state after a previous failure.")

    @lockutils.synchronized("_host_route", external=True)
    def _host_route(self):
        # Get list of vrfs
        vrfJson = json.loads(utils.execute(["ip", "-j", "vrf", "show"]))
        # Remove legacy host routes per vrf
        for vrf in vrfJson:
            helpers.remove_host_route(vrf["name"])

    def _neighbor_worker(self, arp):
        try:
            if (
                "REACHABLE" in arp["state"]
                and ipaddress.IPv4Address(arp["dst"])
                and arp["dev"].startswith("brt")
            ):
                helpers.arping(arp["dev"], arp["dst"])
        except ipaddress.AddressValueError:
            pass

    def _neighbor_manager(self):
        try:
            arp_json = json.loads(helpers.get_arp_table())
            with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
                futures = [executor.submit(self._neighbor_worker, arp) for arp in arp_json]
                concurrent.futures.wait(futures)
        except Exception as e:
            LOG.error("Neighbor Manager: %s", e)

    @lockutils.synchronized("_orphan_manager", external=True)
    def _orphan_manager(self):
        helpers.delete_orphaned_links(helpers.get_orphaned_links())
        helpers.delete_orphaned_frr_services()
        helpers.delete_orphaned_peers()

    def _validate_rpc_endpoints(self):
        if not isinstance(self.endpoints[0], dam.RotHAgentManagerRpcCallBack):
            LOG.error(
                "RPC Callback class must inherit from "
                "RotHAgentManagerRpcCallBack to ensure "
                "RotHAgent works properly."
            )
            sys.exit(1)

    def setup_rpc(self):
        self.agent_id = self.mgr.get_agent_id()
        self.topic = "roth_agent"
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.REPORTS)
        self.rpc_callbacks = self.mgr.get_rpc_callbacks(self.context, self)
        self.endpoints = [self.rpc_callbacks]
        self._validate_rpc_endpoints()

        transport = oslo_messaging.get_rpc_transport(cfg.CONF)
        target = oslo_messaging.Target(topic="roth_agent", server=socket.gethostname())
        self.server = oslo_messaging.get_rpc_server(
            transport, target, self.endpoints, executor="eventlet"
        )
        self.server.start()

    def daemon_loop(self):
        LOG.info("%s RPC Daemon Started!", self.agent_type)
        LOG.info("RotH agent state: %s ", self.agent_state)
        for endpoint in self.endpoints:
            LOG.info("RotH agent endpoint: %s ", endpoint.__dict__)

        while True:
            start = time.time()
            elapsed = time.time() - start
            if elapsed < self.polling_interval:
                time.sleep(self.polling_interval - elapsed)
            else:
                LOG.debug(
                    "Loop iteration exceeded interval "
                    "(%(polling_interval)s vs. %(elapsed)s)!",
                    {"polling_interval": self.polling_interval, "elapsed": elapsed},
                )
