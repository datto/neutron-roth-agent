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

import configparser
from oslo_log import log as logging

LOG = logging.getLogger(__name__)

config = configparser.ConfigParser()

try:
    config.read('/etc/neutron/roth_agent.ini')
except (FileNotFoundError, OSError):
    LOG.warning(
        '''No configuration file readable at /etc/neutron/roth_agent.ini!
        Using default configuration options.'''
    )

# BGP
BGP_PEER_DELETE = config.getint('BGP', 'BGP_PEER_DELETE', fallback=86400)
# Since roth_startup needs the BGP password independently of this file,
# do not set that value here. Instead, roth_startup handles this.
# BGP_PASSWORD = NULL

# EXCLUDE
# Expects comma seperated strings
EXCLUDE_BRIDGE = config.get('EXCLUDE', 'EXCLUDE_BRIDGE', fallback=[])
if len(EXCLUDE_BRIDGE) > 0:
    EXCLUDE_BRIDGE = EXCLUDE_BRIDGE.split(',')
EXCLUDE_VXLAN = config.get('EXCLUDE', 'EXCLUDE_VXLAN', fallback=[])
if len(EXCLUDE_VXLAN) > 0:
    EXCLUDE_VXLAN = EXCLUDE_VXLAN.split(',')
EXCLUDE_VRF = config.get('EXCLUDE', 'EXCLUDE_VRF', fallback=[])
if len(EXCLUDE_VRF) > 0:
    EXCLUDE_VRF = EXCLUDE_VRF.split(',')

# MAC
OS_BRIDGE_MAC = config.get('MAC', 'OS_BRIDGE_MAC', fallback='e4:4e:09:02:e7:26')
TRANSIT_MAC = config.get('MAC', 'TRANSIT_MAC', fallback='e4:4e:09:02:e7:27')

# MANAGER
ROUTE_MGR_INTERVAL = config.getfloat('MANAGER', 'ROUTE_MGR_INTERVAL', fallback=30.0)
NBR_MGR_INTERVAL = config.getfloat('MANAGER', 'NBR_MGR_INTERVAL', fallback=60.0)
ORPHAN_MGR_INTERVAL = config.getfloat('MANAGER', 'ORPHAN_MGR_INTERVAL', fallback=60.0)
