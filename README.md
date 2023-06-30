# neutron_roth_agent

## Contents

- [neutron\_roth\_agent](#neutron_roth_agent)
  - [Contents](#contents)
  - [Neutron Routing on the Host Plugin](#neutron-routing-on-the-host-plugin)
    - [Overview](#overview)
    - [Prerequisites](#prerequisites)
    - [Transit Networks](#transit-networks)
    - [Driver Operation](#driver-operation)
    - [Neutron Security](#neutron-security)
      - [Problem](#problem)
      - [Requirements](#requirements)
      - [Solution](#solution)
    - [Agent Operation](#agent-operation)
    - [Agent Loop](#agent-loop)
      - [Route Manager](#route-manager)
      - [Orphan Manager](#orphan-manager)
      - [Neighbor Manager](#neighbor-manager)
      - [Reporting](#reporting)
  - [Development](#development)
    - [Setup](#setup)
    - [Deployment](#deployment)
    - [Install neutron-roth-agent](#install-neutron-roth-agent)
    - [Run neutron-roth-agent](#run-neutron-roth-agent)

## Neutron Routing on the Host Plugin

### Overview

The Neutron Routing on the Host (RotH) Plugin facilitates BGP EVPN VXLAN datacenter networking in which each Openstack compute node participates in EVPN. The compute nodes run Free Range Routing (FRR), and host both L2VNIs and L3VNIs, separated into different VRFs (each VRF having a dedicated L3VNI). A /32 host route is installed for every desintation, thus providing optimal routing between instances, without the need of a neutron router. Neutron RotH is comprised of a driver and an agent.

[neutron-roth-driver](https://github.com/datto/neutron-roth-driver)

[neutron-roth-agent](https://github.com/datto/neutron-roth-agent)

Together, the driver and agent faciliate the dynamic creation/deletion of VRFs and VXLAN interfaces, as well as FRR configuration. The driver listens for port commit messages, and using RPC on a dedicated topic, calls an agent function on the relevant compute node to execute the required configuration.

### Prerequisites

VNIs are assigned to projects by leveraging the `network segment range` service plugin in OpenStack. The driver will only use the VNI that it finds in the `minimum` field. To prevent openstack from using these ranges for L2VNI allocation, a dedicated project should be created, and each range should be assigned to that project. The range `name` must be the project_id of the project that will use the allocation.

```bash
[example]$ openstack project create l3vni_allocation --property protected=True --property owner=admin
+-------------+----------------------------------+
| Field       | Value                            |
+-------------+----------------------------------+
| description |                                  |
| domain_id   | default                          |
| enabled     | True                             |
| id          | 5bc2b51d30f744d59fbbaa96f75a1b0d |
| is_domain   | False                            |
| name        | l3vni_allocation                 |
| options     | {}                               |
| owner       | admin                            |
| parent_id   | default                          |
| protected   | True                             |
| tags        | []                               |
+-------------+----------------------------------+
[example]$ openstack network segment range create --network-type vxlan --minimum 1100 --maximum 1100 --private --project l3vni_allocation 8880f09699b8401f91fb87aa4498064a
[example]$ openstack network segment range list
+--------------------------------------+----------------------------------+---------+--------+----------------------------------+--------------+------------------+------------+------------+
| ID                                   | Name                             | Default | Shared | Project ID                       | Network Type | Physical Network | Minimum ID | Maximum ID |
+--------------------------------------+----------------------------------+---------+--------+----------------------------------+--------------+------------------+------------+------------+
| 2ea20ec1-fac9-419c-96f8-08eecdfde4b1 | 9f4b30be642a493e876e3aa25cf2cd50 | False   | False  | 5bc2b51d30f744d59fbbaa96f75a1b0d | vxlan        | None             |       1005 |       1005 |
| 7525e1a8-dbca-43c4-af4d-225aef5cf953 | 8880f09699b8401f91fb87aa4498064a | False   | False  | 5bc2b51d30f744d59fbbaa96f75a1b0d | vxlan        | None             |       1100 |       1100 |
| d5695df8-b4c3-4752-823d-e08b367d8d6e | cf24c265b7a748008452df3c7c78771b | False   | False  | 5bc2b51d30f744d59fbbaa96f75a1b0d | vxlan        | None             |       1002 |       1002 |
| e0e9036a-f0a0-444c-99a6-7610519e4e10 |                                  | True    | True   | None                             | vxlan        | None             |         50 |       1000 |
+--------------------------------------+----------------------------------+---------+--------+----------------------------------+--------------+------------------+------------+------------+
[example]$ openstack network segment range show 8880f09699b8401f91fb87aa4498064a
+------------------+-------------------------------------------------------------------------------------------------------------------------------------------------+
| Field            | Value                                                                                                                                           |
+------------------+-------------------------------------------------------------------------------------------------------------------------------------------------+
| available        | ['1100']                                                                                                                                        |
| default          | False                                                                                                                                           |
| id               | 7525e1a8-dbca-43c4-af4d-225aef5cf953                                                                                                            |
| location         | cloud='', project.domain_id=, project.domain_name=, project.id='5bc2b51d30f744d59fbbaa96f75a1b0d', project.name=, region_name='EX1', zone=      |
| maximum          | 1100                                                                                                                                            |
| minimum          | 1100                                                                                                                                            |
| name             | 8880f09699b8401f91fb87aa4498064a                                                                                                                |
| network_type     | vxlan                                                                                                                                           |
| physical_network | None                                                                                                                                            |
| project_id       | 5bc2b51d30f744d59fbbaa96f75a1b0d                                                                                                                |
| shared           | False                                                                                                                                           |
| used             | {}                                                                                                                                              |
+------------------+-------------------------------------------------------------------------------------------------------------------------------------------------+
```

Neutron-roth supports directly routable tenant subnets by deploying FRR to neutron router namespaces. Directly routable tenant subnets must be part of
a subnet pool, and that subnet pool must be part of the same __shared address scope__ as the provider subnet attached to the router. This prevents
prefix overlap, and also is in line with how neutron routers NAT traffic. An attached tenant subnet that is in the same address scope as the provider
subnet will not be NATed.

```bash
MariaDB [neutron]> select name,address_scope_id from subnetpools;
+--------------------+--------------------------------------+
| name               | address_scope_id                     |
+--------------------+--------------------------------------+
| test1-lab-external | fd749b6d-c7f3-4d14-b161-1cd08355da14 |
| test1-lab-internal | fd749b6d-c7f3-4d14-b161-1cd08355da14 |
+--------------------+--------------------------------------+
1 row in set (0.000 sec)

MariaDB [neutron]> select id,name from address_scopes;
+--------------------------------------+-----------+
| id                                   | name      |
+--------------------------------------+-----------+
| fd749b6d-c7f3-4d14-b161-1cd08355da14 | TEST      |
+--------------------------------------+-----------+
1 row in set (0.000 sec)

MariaDB [neutron]> select object_id,target_tenant,action from addressscoperbacs;
+--------------------------------------+---------------+------------------+
| object_id                            | target_tenant | action           |
+--------------------------------------+---------------+------------------+
| fd749b6d-c7f3-4d14-b161-1cd08355da14 | *             | access_as_shared |
+--------------------------------------+---------------+------------------+
1 row in set (0.001 sec)
```

### Transit Networks

> <span style="color:yellow">OPTIONAL<span>

>There is a unique network type, defined by starting a network name with 'transit.' The transit network is used to route traffic for a network environment to a NAT gateway device. The LAN, or internal interface of the NAT gateway is assigned to the transit network. A transit subnet, gateway, and host-route must be configured for the agent to correctly deploy the configuration to the compute node.
>
>The WAN, or external interface of the openstack router should be assigned to the public network. The RotH agent, when handling a transit network, will configure a default route to the internal IP address of the router. Default traffic for the relevant network environment will then route through the openstack router to reach the Internet (or other external network environments).
>
>The use of transit networks is entirely optional.

```bash
openstack network create --project example-dmz3 --provider-network-type vxlan --disable-port-security transit-gw-network
openstack subnet create --project example-dmz3 --subnet-range 172.16.1.0/30 --network transit-gw-network --no-dhcp \
  --gateway 172.16.1.2 --host-route destination=0.0.0.0/0,gateway=172.16.1.1 transit-gw-subnet
openstack port create --project example-dmz3 --network transit-gw-network \
  --fixed-ip subnet=transit-gw-subnet,ip-address=172.16.1.1 transit-gw-port
openstack router add port example-dmz3-router transit-gw-port
```

### Driver Operation

When an *update_port_postcommit* message is received by the neutron server, the RotH mechanism driver will analyze the message. If the port is not DOWN, the driver will retrieve certain details from the neutron database:

- __network__
- __subnet__
- __project_vni__
  
Using this information, the driver defines the following variables:

- __transit__: contains the static route to configure if one is present, otherwise False
- __bridge_id__: the network bridge id, determined by adding the 'brq' prefix to the network id
- __vni__: the project VNI. For router ports, the project VNI of the provider network is used
- __gateways__: the network gateways with subnet mask
- __host__: the compute node where the port has been created
- __router_id__: the router_id that the port connects to, otherwise False
- __bgp_id__: the IP address to use for the neutron router bgp router id, otherwise False
- __bgp_peer__: the IP address for the neutron router to peer with (the provider network gateway address)
- __router_networks__: the list of cidrs for the neutron router to advertise outbound

An RPC client request is sent using the topic *roth_agent* and is directed at the relevant *host*. This request is for the RPC callback function, *call_setup_tenant_vrf*.

### Neutron Security

---

#### Problem

When configuring an Anycast Gateway on an OpenStack created network bridge, routed traffic to VMs is not matched by any security group created iptables rules.

---

#### Requirements

- The L2 VXLAN interface must be attached to the bridge that has the Anycast Gateway
- The Anycast Gateway bridge must be attached to the VRF that EVPN is using
- All traffic to that bridge must be switched

---

#### Solution

Create the Anycast Gateway on a new bridge and link that bridge to the bridge that OpenStack creates. Delete the L2 VXLAN interface created by OpenStack. Create a new L2 VXLAN interface and bind it to the new bridge. To prevent linuxbridge-agent from recreating the deleted L2 VXLAN interface, create a dummy interface by the same name.

---

### Agent Operation

*neutron-roth-agent* running on the relevant compute node receives the driver request from a controller node. After parsing the provided arguments, the *setup_tenant_vrf* function is called. This function ensures that all the necessary network components are configured as they relate to the port in the *update_port_postcommit* message that was received by the roth driver. Recall that this port connects an instance to the appropriate network bridge configured on the compute node.

- Create tenant L3 bridge
- Create tenant L3 VXLAN interface
- Create tenant VRF
- Add tenant L3 bridge to the tenant VRF
- Add gateway to the tenant bridge
- Enable neighbor suppression on the L2VXLAN interface
- Deploy the L2VXLAN solution described [here](#neutron-security)
- Configure FRR for the tenant VRF
- Configure FRR for the neutron router (if needed)
- Add a static route to the transit subnet (if needed)
- Return "SUCCESS" or "FAILURE" back to roth driver

### Agent Loop

RotH agent will execute certain tasks on configurable time intervals.

---

#### Route Manager

A static route is added to a vrf when a transit subnet is attached to a NAT gateway device. This manager will periodically (default: every 30 seconds) check to determine if any static route is still required. It does this by checking if there is a local ARP entry present for the gateway IP address in the static route. If one is not present, an arping is sent, and the condition is checked again. If there is still no entry, the route is deleted. Any related VTYSH configurations are also deleted.

<span style="color:red">
Further testing is required to ensure there is no case were a route could be deleted by mistake, or if there is an unavoidable case, that we have a reliable mechanism to re-add the route. Note that disabling/enabling the port that attaches the transit network to the router will trigger the roth-agent to ensure the host-route exists.
</span>

---

#### Orphan Manager

If instances are deleted from a compute node, it's possible that the network configurations applied by the agent to service those instances are no longer required. This agent will determine if there are no longer any instances present for each configured vrf. If that's the case, the relevant network configurations will be removed:

- Bridge interfaces
- L3 VXLAN interfaces
- VRFs
- FRR configuration

---

#### Neighbor Manager

This manager will periodically arping every active unicast IP address for each tenant bridge local to the oscomp node. Doing so refreshes the arp timers, and prevents the neighbor entries from transitioning to a stale state. If the IP address does not respond, the timer is not updated, and the entry will timeout as intended.

<span style="color:red">
If a neighbor entry does reach a stale state, and needs to be revived, the relevant instance will need to initiate network traffic to restore a valid neighbor entry.
</span>

---

#### Reporting

Typical of agent plugins, there is a built-in reporting function to track the state of the agent. The interval is determined by the cfg variables, common to all agents. Example states include:

- __New__: The agent was started for the first time
- __Alive__: The agent is running
- __Revived__: The agent has transitioned from a failed to a running state

---

## Development

### Setup

```bash
# Setup virtual environment
pyenv virtualenv 3.7.4 neutron-roth
pyenv local neutron-roth
pyenv activate

# Install dependencies
poetry install

# You may need to close and re-open your shell before running the following
# Install git hooks, pre-commits should have been installed with poetry above
pre-commit install
```

### Deployment

```bash
# Build a source distribution as follows
python3 -m build --sdist
# SCP to the destination
scp dist/neutron-roth-agent-0.0.5.tar.gz root@192.168.1.100:
```

### Install neutron-roth-agent

```bash
# In the relevant python venv
cd /openstack/venvs/neutron-23.4.3/
source bin/activate
pip install /root/neutron-roth-agent-0.0.5.tar.gz
```

### Run neutron-roth-agent

```bash
neutron_roth_agent
```
