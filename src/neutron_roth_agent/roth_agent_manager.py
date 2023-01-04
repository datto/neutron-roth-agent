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

import abc
import six
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class RotHAgentManagerRpcCallBack(object):
    """RotH class for managers RPC callbacks.

    This class must be inherited by a RPC callback class that is used
    in combination with the roth agent.
    """

    def __init__(self, context, agent):
        LOG.info("Initializing RotHAgentManagerRpcCallBack...")
        self.context = context
        self.agent = agent


@six.add_metaclass(abc.ABCMeta)
class RotHAgentManager(object):
    """RotH class for managers that are used with the roth agent loop.

    This class must be inherited by a manager class that is used
    in combination with the roth agent.
    """

    def get_agent_configurations(self):
        """Establishes the agent configuration map.

        The content of this map is part of the agent state reports to the
        neutron server.

        :return: map -- the map containing the configuration values
        :rtype: dict
        """
        pass

    def get_agent_id(self):
        """Calculate the agent id that should be used on this host

        :return: str -- agent identifier
        """
        pass

    def get_extension_driver_type(self):
        """Get the agent extension driver type.

        :return: str -- The String defining the agent extension type
        """
        pass

    def get_rpc_callbacks(self, context, agent, roth_agent):
        """Returns the class containing all the agent rpc callback methods

        :return: class - the class containing the agent rpc callback methods.
            It must reflect the RotHAgentManagerRpcCallBack Interface.
        """
        pass

    def get_agent_api(self, **kwargs):
        """Get L2 extensions drivers API interface class.

        :return: instance of the class containing Agent Extension API
        """
        pass
