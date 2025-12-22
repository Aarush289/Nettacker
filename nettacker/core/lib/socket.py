#!/usr/bin/env python

import copy
import logging
import os
import re
import select
import socket
import ssl
import struct
import time
import random

from nettacker.core.lib.base import BaseEngine, BaseLibrary
from nettacker.core.utils.common import reverse_and_regex_condition, replace_dependent_response

log = logging.getLogger(__name__)
IP_VERSION = 4
IP_IHL = 5
IP_TOS = 0
IP_TTL = 64
IP_PROTO_ICMP = 1
IP_DF = 0x4000     # Don't Fragment

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0

def checksum(data):
        if len(data) % 2:
            data += b'\x00'

        s = 0
        for i in range(0, len(data), 2):
            s += (data[i] << 8) + data[i + 1]
            s &= 0xffffffff

        s = (s >> 16) + (s & 0xffff)
        s += (s >> 16)
        return (~s) & 0xffff

def build_ip(src, dst, payload_len, ipid=None):
    if ipid is None:
        ipid = random.randint(0, 65535)

    ver_ihl = (IP_VERSION << 4) + IP_IHL
    total_len = IP_IHL * 4 + payload_len

    header = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl,
        IP_TOS,
        total_len,
        ipid,
        IP_DF,
        IP_TTL,
        IP_PROTO_ICMP,
        0,  # checksum placeholder
        socket.inet_aton(src),
        socket.inet_aton(dst)
    )

    chksum = checksum(header)

    header = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl,
        IP_TOS,
        total_len,
        ipid,
        IP_DF,
        IP_TTL,
        IP_PROTO_ICMP,
        chksum,
        socket.inet_aton(src),
        socket.inet_aton(dst)
    )

    return header

def build_icmp(id, seq=1):
        payload = b'\x00' * 32  # Nmap default-ish

        header = struct.pack(
            "!BBHHH",
            ICMP_ECHO_REQUEST,
            0,
            0,
            id,
            seq
        )

        chksum = checksum(header + payload)

        header = struct.pack(
            "!BBHHH",
            ICMP_ECHO_REQUEST,
            0,
            chksum,
            id,
            seq
        )

        return header + payload


def create_tcp_socket(host, port, timeout):
    try:
        socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_connection.settimeout(timeout)
        socket_connection.connect((host, port))
        ssl_flag = False
    except ConnectionRefusedError:
        return None

    try:
        socket_connection = ssl.wrap_socket(socket_connection)
        ssl_flag = True
    except Exception:
        socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_connection.settimeout(timeout)
        socket_connection.connect((host, port))
    # finally:
    #     socket_connection.shutdown()

    return socket_connection, ssl_flag


class SocketLibrary(BaseLibrary):
    def tcp_connect_only(self, host, port, timeout):
        tcp_socket = create_tcp_socket(host, port, timeout)
        if tcp_socket is None:
            return None

        socket_connection, ssl_flag = tcp_socket
        peer_name = socket_connection.getpeername()
        socket_connection.close()

        try:
            service = socket.getservbyport(port)
        except OSError:
            service = "unknown"

        return {
            "peer_name": peer_name,
            "service": service,
            "ssl_flag": ssl_flag,
        }

    def tcp_connect_send_and_receive(self, host, port, timeout):
        tcp_socket = create_tcp_socket(host, port, timeout)
        if tcp_socket is None:
            return None

        socket_connection, ssl_flag = tcp_socket
        peer_name = socket_connection.getpeername()
        try:
            socket_connection.send(b"ABC\x00\r\n\r\n\r\n" * 10)
            response = socket_connection.recv(1024 * 1024 * 10)
            socket_connection.close()
        # except ConnectionRefusedError:
        #     return None
        except Exception:
            try:
                socket_connection.close()
                response = b""
            except Exception:
                response = b""

        try:
            service = socket.getservbyport(port)
        except OSError:
            service = "unknown"

        return {
            "peer_name": peer_name,
            "response": response.decode(errors="ignore"),
            "service": service,
            "ssl_flag": ssl_flag,
        }            

    def socket_icmp(self, host, timeout):
        """
        A pure python ping implementation using raw socket.
        Note that ICMP messages can only be sent from processes running as root.
        Derived from ping.c distributed in Linux's netkit. That code is
        copyright (c) 1989 by The Regents of the University of California.
        That code is in turn derived from code written by Mike Muuss of the
        US Army Ballistic Research Laboratory in December, 1983 and
        placed in the public domain. They have my thanks.
        Bugs are naturally mine. I'd be glad to hear about them. There are
        certainly word - size dependenceies here.
        Copyright (c) Matthew Dixon Cowles, <http://www.visi.com/~mdc/>.
        Distributable under the terms of the GNU General Public License
        version 2. Provided with no warranties of any sort.
        Original Version from Matthew Dixon Cowles:
          -> ftp://ftp.visi.com/users/mdc/ping.py
        Rewrite by Jens Diemer:
          -> http://www.python-forum.de/post-69122.html#69122
        Rewrite by George Notaras:
          -> http://www.g-loaded.eu/2009/10/30/python-ping/
        Fork by Pierre Bourdon:
          -> http://bitbucket.org/delroth/python-ping/
        Revision history
        ~~~~~~~~~~~~~~~~
        November 22, 1997
        -----------------
        Initial hack. Doesn't do much, but rather than try to guess
        what features I (or others) will want in the future, I've only
        put in what I need now.
        December 16, 1997
        -----------------
        For some reason, the checksum bytes are in the wrong order when
        this is run under Solaris 2.X for SPARC but it works right under
        Linux x86. Since I don't know just what's wrong, I'll swap the
        bytes always and then do an htons().
        December 4, 2000
        ----------------
        Changed the struct.pack() calls to pack the checksum and ID as
        unsigned. My thanks to Jerome Poincheval for the fix.
        May 30, 2007
        ------------
        little rewrite by Jens Diemer:
         -  change socket asterisk import to a normal import
         -  replace time.time() with time.clock()
         -  delete "return None" (or change to "return" only)
         -  in checksum() rename "str" to "source_string"
        November 8, 2009
        ----------------
        Improved compatibility with GNU/Linux systems.
        Fixes by:
         * George Notaras -- http://www.g-loaded.eu
        Reported by:
         * Chris Hallman -- http://cdhallman.blogspot.com
        Changes in this release:
         - Re-use time.time() instead of time.clock(). The 2007 implementation
           worked only under Microsoft Windows. Failed on GNU/Linux.
           time.clock() behaves differently under the two OSes[1].
        [1] http://docs.python.org/library/time.html#time.clock
        September 25, 2010
        ------------------
        Little modifications by Georgi Kolev:
         -  Added quiet_ping function.
         -  returns percent lost packages, max round trip time, avrg round trip
            time
         -  Added packet size to verbose_ping & quiet_ping functions.
         -  Bump up version to 0.2
        ------------------
        5 Aug 2021 - Modified by Ali Razmjoo Qalaei (Reformat the code and more human readable)
        """
        host = socket.getaddrinfo(host,None , socket.AF_INET)[0][4][0]
        source_ip = socket.gethostbyname(socket.getfqdn())
        random_integer = os.getpid() & 0xffff
        icmp = build_icmp(random_integer)
        ip = build_ip(source_ip, host, len(icmp))
        packet = ip + icmp
        transfer_buffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        receiver_buffer = socket.socket(socket.AF_INET , socket.SOCK_RAW , socket.IPPROTO_ICMP)
        # sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        receiver_buffer.setblocking(0)
        transfer_buffer.sendto(packet, (host, 0))

        start = time.time()
        timeout = 3
        delay = None
        received_packet=None
        packet_type = None
        packet_code = None
        icmp_header = None
        while True:
            started_select = time.time()
            what_ready = select.select([receiver_buffer], [], [], timeout)
            how_long_in_select = time.time() - started_select
            if not what_ready[0]:  # Timeout
                break
            time_received = time.time()
            received_packet, _ = receiver_buffer.recvfrom(1024)
            ip_header_len = (received_packet[0] & 0x0F) * 4
            icmp_header = received_packet[ip_header_len : ip_header_len + 8]

            packet_type, packet_code, _, packet_id, _ = struct.unpack("!BBHHH", icmp_header)
            
            if packet_type!=0:
                continue
            if packet_id == random_integer :
                icmp_data_offset = ip_header_len + 8
                time_sent = struct.unpack(
                    "d", received_packet[icmp_data_offset : icmp_data_offset + 8]
                )[0]
                delay = time_received - time_sent
                break                    
            timeout = timeout - how_long_in_select
            if timeout <= 0:
                break
        receiver_buffer.close()
        transfer_buffer.close()
        if delay is None:
            return {"host": host,"response_time":None, "ssl_flag": False , "log":"open|filtered"}
        if packet_type == 0:
            return {"host": host ,"response_time":delay , "ssl_flag":False , "log":"open"}
        
        return {"host":host,"response_time":delay,"ssl_flag":False , "log":"filtered"}
        

    
class SocketEngine(BaseEngine):
    library = SocketLibrary

    def response_conditions_matched(self, sub_step, response):
        conditions = sub_step["response"]["conditions"].get(
            "service", sub_step["response"]["conditions"]
        )
        condition_type = sub_step["response"]["condition_type"]
        condition_results = {}
        if sub_step["method"] == "tcp_connect_only":
            return response
        if sub_step["method"] == "tcp_connect_send_and_receive":
            if response:
                for condition in conditions:
                    regex = re.findall(
                        re.compile(conditions[condition]["regex"]),
                        response["response"]
                        if condition != "open_port"
                        else str(response["peer_name"][1]),
                    )
                    reverse = conditions[condition]["reverse"]
                    condition_results[condition] = reverse_and_regex_condition(regex, reverse)

                    if condition_results[condition]:
                        default_service = response["service"]
                        ssl_flag = response["ssl_flag"]
                        matched_regex = condition_results[condition]

                        log_response = {
                            "running_service": condition,
                            "matched_regex": matched_regex,
                            "default_service": default_service,
                            "ssl_flag": ssl_flag,
                        }
                        condition_results["service"] = [str(log_response)]
                for condition in copy.deepcopy(condition_results):
                    if not condition_results[condition]:
                        del condition_results[condition]

                if "open_port" in condition_results and len(condition_results) > 1:
                    del condition_results["open_port"]
                    del conditions["open_port"]
                if condition_type.lower() == "and":
                    return condition_results if len(condition_results) == len(conditions) else []
                if condition_type.lower() == "or":
                    if sub_step["response"].get("log", False):
                        condition_results["log"] = sub_step["response"]["log"]
                        if "response_dependent" in condition_results["log"]:
                            condition_results["log"] = replace_dependent_response(
                                condition_results["log"], condition_results
                            )
                    return condition_results if condition_results else []
                return []
        if sub_step["method"] == "socket_icmp":
            return response
        return []

    def apply_extra_data(self, sub_step, response):
        sub_step["response"]["ssl_flag"] = (
            response["ssl_flag"] if isinstance(response, dict) else False
        )
        sub_step["response"]["conditions_results"] = self.response_conditions_matched(
            sub_step, response
        )
