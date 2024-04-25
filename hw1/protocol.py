import random
import socket
import struct
import math
from time import sleep
import threading

class Logger:
    log_file = 'log.txt'
    @classmethod
    def log(cls, msg):
        with open(cls.log_file, 'a') as f:
            f.write('In thread: ' + str(threading.get_ident()) + ' ' + msg + '\n')

class UDPBasedProtocol:
    def __init__(self, *, local_addr, remote_addr):
        self.udp_socket = socket.socket(
            family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.remote_addr = remote_addr
        self.udp_socket.bind(local_addr)

    def sendto(self, data):
        return self.udp_socket.sendto(data, self.remote_addr)

    def recvfrom(self, n):
        msg = None
        try:
            msg, _ = self.udp_socket.recvfrom(n)
        except:
            pass
        return msg

    def close(self):
        self.udp_socket.close()

MYTCP_DEF = 0
MYTCP_ACK = 1
MYTCP_MSG = 2
MYTCP_FIN = 4

ACK_CONT = 0
ACK_STOP = 1
ACK_SUCC = 2

SEND_STATE = 0
RECV_STATE = 1

MYTCP_HEADER_LEN = len(struct.pack("BQ", 0, 0))
UDP_PACKAGE_MAX_SIZE = MYTCP_HEADER_LEN + 60000
ASSURANCE_LIMIT = 3

"""
MyTCP package structure:
package     := header msg?
header      := type ack seq 
type        := <BYTE>
ack         := <ULEB128>
seq         := <ULEB128>
msg         := <STRING>
"""

class Package:
    def __init__(self, type: int, uid: int, data: bytes = None):
        self.__validate_header(type, uid)

        self.type = type
        self.data = data
        self.uid = uid

    def __bytes__(self):
        header = struct.pack("BQ", self.type, self.uid)
        return header + self.data if self.data else header

    def __str__(self):
        types = {MYTCP_ACK : "ACK", MYTCP_FIN : "FIN", MYTCP_MSG : "MSG"}
        return "package {} uid: {} data: {} size: {}".format(types[self.type], str(self.uid), str(self.data) if self.data is not None else "None", len(self))

    def __len__(self):
        return len(bytes(self))

    @classmethod
    def __validate_header(cls, type, uid):
        if type != MYTCP_ACK and type != MYTCP_MSG and type != MYTCP_FIN and type != MYTCP_DEF:
            raise ValueError
        if uid < 0 :
            raise ValueError

    @classmethod
    def from_bytes(cls, data):
        type, uid = struct.unpack("BQ", data[:MYTCP_HEADER_LEN])
        cls.__validate_header(type, uid)
        
        body = None
        if len(data) > MYTCP_HEADER_LEN:
            body = data[MYTCP_HEADER_LEN:]
        return cls(type, uid, body)


class MyTCPProtocol(UDPBasedProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sack = set()
        self.sseq = set()
        self.rack = set()
        self.uid = 0
        self.udp_socket.settimeout(0.01)
        self.state = SEND_STATE

    def __data_to_packages(self, data: bytes) -> list[Package]:
        packages = []
        while len(data) + MYTCP_HEADER_LEN > UDP_PACKAGE_MAX_SIZE:
            self.uid += 1
            body = data[:UDP_PACKAGE_MAX_SIZE - MYTCP_HEADER_LEN]
            package = Package(MYTCP_MSG, self.uid, body)
            packages.append(package)
            data = data[UDP_PACKAGE_MAX_SIZE - MYTCP_HEADER_LEN:]

        self.uid += 1 
        package = Package(MYTCP_MSG, self.uid, data)
        packages.append(package)

        return packages

    def __send_ack_package(self, package: Package):
        ack_package = Package(MYTCP_ACK, package.uid)
        self.sendto(bytes(ack_package))
          
    def __handle_package(self, n: int) -> str:
        if self.state == RECV_STATE:
            response = self.recvfrom(UDP_PACKAGE_MAX_SIZE)
            while response is None:
                # Logger.log('No package, waiting')
                response = self.recvfrom(UDP_PACKAGE_MAX_SIZE)
            package = Package.from_bytes(response)

            if package.type == MYTCP_MSG:
                self.__send_ack_package(package)
                if package.uid not in self.rack:
                    self.rack.add(package.uid)
                    return package.data
                return b''
            else:
                return b''

        elif self.state == SEND_STATE:
            response = self.recvfrom(UDP_PACKAGE_MAX_SIZE)
            if response is None:
                return 'None'
            package = Package.from_bytes(response)
            if package.type == MYTCP_MSG:
                if package.uid in self.rack:
                    self.__send_ack_package(package)
                    return 'None'
                else:
                    self.state = RECV_STATE
                    return 'Recv'
            elif package.type == MYTCP_ACK:
                if package.uid not in self.sseq:
                    raise ValueError
                self.sack.add(package.uid)
                return 'True'
    
    def __send_package(self, package: Package):
        self.sseq.add(package.uid)
        self.sendto(bytes(package))

    def __resend_package(self, package: Package):
        self.sendto(bytes(package))
        
    def send(self, data: bytes):
        self.state = SEND_STATE
        packages = self.__data_to_packages(data) 
        
        for package in packages:
            self.__send_package(package)
            #Logger.log('Sent ' + str(package))

            response = self.__handle_package(MYTCP_HEADER_LEN)
            while response == 'None':
                self.__resend_package(package)
                #Logger.log('Resent ' + str(package))
                response = self.__handle_package(MYTCP_HEADER_LEN)
            if response == 'Recv':
                break

        return len(data)

    def recv(self, n: int):
        self.state = RECV_STATE
        data = b''
        recieved = 0

        while recieved != n:
            result = self.__handle_package(UDP_PACKAGE_MAX_SIZE)
            recieved += len(result)
            data += result
            #Logger.log('Recieved ' + str(recieved))
        #Logger.log('Collected ' + str(data))
        return data
    
    def close(self):
        super().close()
