# Copyright 2017-present Barefoot Networks, Inc.
# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import os
import tempfile
from time import sleep

from mininet.node import Switch
from mininet.moduledeps import pathCheck
from mininet.log import info, error, debug

from p4_mininet import P4Switch, SWITCH_START_TIMEOUT
from netstat import check_listening_on_port

class P4RuntimeSwitch(P4Switch):
    "BMv2 switch with gRPC support"

    next_grpc_port = 50051

    def __init__(self,
                 name,
                 sw_path = None,
                 json_path = None,
                 grpc_port = None,
                 pcap_dump = False,
                 log_console = False,
                 verbose = False,
                 device_id = None,
                 enable_debugger = False,
                 **kwargs):

        Switch.__init__(self, name, **kwargs)
        assert (sw_path)
        self.sw_path = sw_path

        # make sure that the provided sw_path is valid
        pathCheck(sw_path)

        if json_path is not None:
            # make sure that the provided JSON file exists
            if not os.path.isfile(json_path):
                error("Invalid JSON file.\n")
                exit(1)
            self.json_path = json_path
        else:
            self.json_path = None

        if grpc_port is not None:
            self.grpc_port = grpc_port
        else:
            self.grpc_port = P4RuntimeSwitch.next_grpc_port
            P4RuntimeSwitch.next_grpc_port += 1

        if check_listening_on_port(self.grpc_port):
            error('%s cannot bind port %d because it is bound by another process\n' % (self.name, self.grpc_port))
            exit(1)

        self.verbose = verbose
        logfile = "/tmp/p4s.{}.log".format(self.name)
        self.output = open(logfile, 'w')
        self.pcap_dump = pcap_dump
        self.enable_debugger = enable_debugger
        self.log_console = log_console

        if device_id is not None:
            self.device_id = device_id
            P4Switch.device_id = max(P4Switch.device_id, device_id)
        else:
            self.device_id = P4Switch.device_id
            P4Switch.device_id += 1

        self.nanomsg = "ipc:///tmp/bm-{}-log.ipc".format(self.device_id)


    def check_switch_started(self, pid):

        for _ in range(SWITCH_START_TIMEOUT * 2):

            if not os.path.exists(os.path.join("/proc", str(pid))):
                return False

            if check_listening_on_port(self.grpc_port):
                return True

            sleep(0.5)


    def start(self, controllers):

        info("Starting P4 switch {}.\n".format(self.name))
        args = [self.sw_path]

        for port, intf in self.intfs.items():
            if not intf.IP():
                args.extend(['-i', str(port) + "@" + intf.name])

        if self.pcap_dump:
            args.append("--pcap")

        if self.nanomsg:
            args.extend(['--nanolog', self.nanomsg])

        args.extend(['--device-id', str(self.device_id)])

        P4Switch.device_id += 1

        if self.json_path:
            args.append(self.json_path)
        else:
            args.append("--no-p4")

        if self.enable_debugger:
            args.append("--debugger")

        if self.log_console:
            args.append("--log-console")

        if self.grpc_port:
            args.append("-- --grpc-server-addr 0.0.0.0:" + str(self.grpc_port))

        cmd = ' '.join(args)
        info(cmd + "\n")

        logfile = "/tmp/p4s.{}.log".format(self.name)
        pid = None

        with tempfile.NamedTemporaryFile() as f:
            self.cmd(cmd + ' >' + logfile + ' 2>&1 & echo $! >> ' + f.name)
            pid = int(f.read())

        debug("P4 switch {} PID is {}.\n".format(self.name, pid))

        if not self.check_switch_started(pid):
            error("P4 switch {} did not start correctly.\n".format(self.name))
            exit(1)

        info("P4 switch {} has been started.\n".format(self.name))