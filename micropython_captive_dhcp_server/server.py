import usocket as socket
import uasyncio as asyncio

try:
    from micropython_captive_dhcp_server.packet import (
        Header,
        DhcpDiscover,
        DhcpRequest,
        DhcpOffer,
        DhcpAck,
        Ip,
    )
except Exception:
    from packet import Header, DhcpDiscover, DhcpRequest, DhcpOffer, DhcpAck, Ip
import gc
import time


class CaptiveDhcpServer:
    def __init__(self):
        self.ips = {}
        self.macs = {}

    def get_free_ip(self, server_ip: str, mac: str):
        next_ip = Ip.next_ip(server_ip)
        while next_ip in self.ips:
            next_ip = Ip.next_ip(next_ip)

        self.ips[next_ip] = int(time.time())
        self.macs[mac] = next_ip

        return next_ip

    def send_broadcast_reply(self, reply):
        udpb = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            udpb.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # As of micropython 1.20.0, SO_BROADCAST is not defined. Using defined value of 0x20
            # see: https://github.com/micropython/micropython/issues/8729
            # udpb.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            udpb.setsockopt(socket.SOL_SOCKET, 0x20, 1)

            udpb.setblocking(False)
            broadcast_addr = socket.getaddrinfo(
                "255.255.255.255", 68, socket.AF_INET, socket.SOCK_DGRAM
            )[0][4]
            print(f"Broadcasting Response: {reply}")
            udpb.sendto(reply, broadcast_addr)
        except Exception as e:
            print(f"Failed to broadcast reply {e}")
        finally:
            udpb.close()

    async def run(self, server_ip: str, netmask: str):
        udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udps.setblocking(False)
        udps.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        bound = False
        while not bound:
            try:
                gc.collect()
                addr = socket.getaddrinfo(
                    "0.0.0.0", 67, socket.AF_INET, socket.SOCK_DGRAM
                )[0][-1]
                udps.bind(addr)
                print("Starting server on port 67")
                bound = True
            except Exception as e:
                print(f"Failed to bind to port {e}")
                time.sleep(0.5)

        while True:
            try:
                gc.collect()

                data, addr = udps.recvfrom(2048)
                print("Incoming data...")
                print(data)

                request = Header.parse(data)
                print(request)

                if isinstance(request, DhcpDiscover):
                    print("Creating Offer for Discover")
                    response = DhcpOffer()
                    client_ip = self.get_free_ip(server_ip, request.header.chaddr)
                    print("Found new ip: " + client_ip)
                    reply = response.answer(request, client_ip, server_ip, netmask)
                    print(response)

                    self.send_broadcast_reply(reply)

                elif isinstance(request, DhcpRequest):
                    print("Creating Ack for Request")
                    response = DhcpAck()
                    reply = response.answer(request, server_ip, netmask)
                    print(response)

                    self.send_broadcast_reply(reply)

                await asyncio.sleep_ms(100)

            except OSError:
                await asyncio.sleep_ms(500)

            except Exception as e:
                print(f"Exception {e}")
                await asyncio.sleep_ms(500)

        udps.close()
