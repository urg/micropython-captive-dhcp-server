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
import traceback


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
        udpb.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udpb.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        udpb.setblocking(False)
        broadcast_addr = socket.getaddrinfo(
            "255.255.255.255", 68, socket.AF_INET, socket.SOCK_DGRAM
        )[0][4]
        print(f"Broadcasting Response: {reply}")
        udpb.sendto(reply, broadcast_addr)
        udpb.close()

    async def run(self, server_ip: str, netmask: str):
        try:
            udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # set non-blocking otherwise execution will stop at 'recvfrom'
            # until a connection is received and this will prevent the other
            # async threads from running
            udps.setblocking(False)

            addr = socket.getaddrinfo("0.0.0.0", 67, socket.AF_INET, socket.SOCK_DGRAM)[
                0
            ][4]
            udps.bind(addr)
            print("Starting server on port 67")
        except Exception:
            print("Failed to bind to port")
            return

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

            except Exception:
                traceback.print_exc()
                await asyncio.sleep_ms(500)

        udps.close()


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    server = CaptiveDhcpServer()
    loop.create_task(server.run("192.168.4.1", "255.255.255.0"))
    loop.run_forever()
    loop.close()
