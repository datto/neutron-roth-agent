#!/usr/bin/env python
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

import shutil
import sys
import os
import site
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from subprocess import run

_ROOT = os.path.abspath(os.path.dirname(__file__))
_VENV_PATH = sys.exec_prefix
_VENV_NAME = os.path.basename(_VENV_PATH)
_PACKAGES = site.getsitepackages()[0]


def get_data(path):
    return os.path.join(_ROOT, 'data', path)


def get_bin():
    return os.path.join(_VENV_PATH, 'bin')


def copy_data(source, destination):
    try:
        overwrite = True
        filename = os.path.basename(source)
        if filename in {'roth_agent.ini'}:
            conf_path = Path(destination)
            if conf_path.is_file():
                overwrite = False
                print(
                    "SKIPPED: %s already exists in %s"
                    % (filename, destination)
                )
        if overwrite:
            if any(x in destination for x in ['frr.service', '/var/lib/neutron/roth/']):
                Path(destination).mkdir(parents=True, exist_ok=True)
            shutil.copy(source, destination)
            print("SUCCESS: Copied %s to %s" % (source, destination))
    except shutil.SameFileError:
        print("Source and destination represents the same file.")
    except PermissionError:
        print("Permission denied.")
    except Exception as E:
        print(E)
        print("FAILURE: Error occurred while copying file.")


def write_data(source, destination):
    try:
        with open(destination, "w") as fh:
            fh.write(source)
        print("SUCCESS: Wrote data to %s" % (destination))
    except PermissionError:
        print("Permission denied.")
    except Exception as E:
        print(E)
        print("FAILURE: Error occurred while writing file.")


def create_service(name):
    service = os.path.splitext(name)[0]
    env = Environment(loader=FileSystemLoader(get_data("")))
    template = env.get_template(name)
    output = template.render(venv=_VENV_NAME)
    write_data(
        output,
        '/etc/systemd/system/%s' % service
    )
    reload_daemons()
    enable_service(service)
    restart_service(service)
    print("SUCCESS: Enabled & restarted %s" % service)


def enable_service(name):
    run(["systemctl", "enable", name])


def restart_service(name):
    run(["systemctl", "restart", name])


def reload_daemons():
    run(["systemctl", "daemon-reload"])


def create_filters(name):
    copy_data(
        get_data(
            name
        ),
        '/etc/neutron/rootwrap.d/'
    )


def create_bin(name):
    bin = os.path.splitext(name)[0]
    env = Environment(loader=FileSystemLoader(get_data("")))
    template = env.get_template(name)
    output = template.render(venv=_VENV_NAME)
    dest = os.path.join(get_bin(), bin)
    write_data(output, dest)
    os.chmod(dest, 0o755)


def create_eventlet(name):
    destination = os.path.join(
        _PACKAGES,
        'neutron/cmd/eventlet/plugins/'
    )
    copy_data(get_data(name), destination)


def create_override(name):
    copy_data(
        get_data(
            name
        ),
        '/etc/systemd/system/frr.service.d/'
    )


def create_startup(name):
    copy_data(
        get_data(
            name
        ),
        '/etc/frr/roth_startup.py'
    )


def create_ini(name):
    copy_data(
        get_data(
            name
        ),
        '/etc/neutron/roth_agent.ini'
    )


def create_frr_ns_conf(name):
    copy_data(
        get_data(
            name
        ),
        '/var/lib/neutron/roth/'
    )


def create_frr_ns_daemons(name):
    copy_data(
        get_data(
            name
        ),
        '/var/lib/neutron/roth/'
    )


def create_frr_ns_service(name):
    copy_data(
        get_data(
            name
        ),
        '/var/lib/neutron/roth/'
    )


def main():
    try:
        create_eventlet('roth_neutron_agent.py')
        create_filters('roth-agent.filters')
        create_bin('neutron-roth-agent.j2')
        create_override('override.conf')
        create_startup('roth_startup.py')
        create_ini('roth_agent.ini')
        create_frr_ns_conf('frr_ns_conf.j2')
        create_frr_ns_daemons('frr_ns_daemons')
        create_frr_ns_service('frr_ns_service.j2')
        create_service('neutron-roth-agent.service.j2')
    except Exception:
        print("ERROR: neutron-roth-agent failed to install.")
