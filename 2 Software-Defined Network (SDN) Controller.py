#!/usr/bin/env python3
"""
Simple SDN Controller Implementation with OpenFlow Support
Features: Dynamic Routing, Load Balancing, Security, Monitoring
"""

import socket
import struct
import threading
import time
import json
import hashlib
from collections import defaultdict
from datetime import datetime


class OpenFlowMessage:
    """OpenFlow message structure"""

    def __init__(self, version=0x04, msg_type=0, length=8, xid=0):
        self.version = version  # OpenFlow 1.3
        self.type = msg_type
        self.length = length
        self.xid = xid

    def pack(self):
        return struct.pack('!BBHI', self.version, self.type, self.length, self.xid)


class FlowEntry:
    """Reprezentarea unei intrări în flow table"""

    def __init__(self, match, actions, priority=0, timeout=0):
        self.match = match  # Condiții de matching
        self.actions = actions  # Acțiuni de executat
        self.priority = priority
        self.timeout = timeout
        self.packet_count = 0
        self.byte_count = 0
        self.timestamp = time.time()

    def matches(self, packet_info):
        """Verifică dacă pachetul se potrivește cu această intrare"""
        for key, value in self.match.items():
            if key in packet_info and packet_info[key] != value:
                return False
        return True


class Switch:
    """Reprezentarea unui switch în rețea"""

    def __init__(self, dpid, ip, port):
        self.dpid = dpid  # Datapath ID
        self.ip = ip
        self.port = port
        self.flow_table = []
        self.ports = {}  # Port info
        self.stats = {
            'packets_in': 0,
            'packets_out': 0,
            'bytes_in': 0,
            'bytes_out': 0
        }
        self.last_seen = time.time()

    def add_flow(self, flow_entry):
        """Adaugă o intrare în flow table"""
        # Sortează după prioritate
        self.flow_table.append(flow_entry)
        self.flow_table.sort(key=lambda x: x.priority, reverse=True)

    def find_matching_flow(self, packet_info):
        """Găsește prima intrare care se potrivește"""
        for flow in self.flow_table:
            if flow.matches(packet_info):
                return flow
        return None


class LoadBalancer:
    """Load balancer pentru distribuirea traficului"""

    def __init__(self):
        self.servers = []
        self.current = 0

    def add_server(self, server_ip, server_port):
        self.servers.append({'ip': server_ip, 'port': server_port, 'connections': 0})

    def get_next_server(self, algorithm='round_robin'):
        if not self.servers:
            return None

        if algorithm == 'round_robin':
            server = self.servers[self.current]
            self.current = (self.current + 1) % len(self.servers)
            return server
        elif algorithm == 'least_connections':
            return min(self.servers, key=lambda x: x['connections'])

    def update_connections(self, server_ip, delta):
        for server in self.servers:
            if server['ip'] == server_ip:
                server['connections'] += delta
                break


class SecurityModule:
    """Modul de securitate pentru detectarea amenințărilor"""

    def __init__(self):
        self.blocked_ips = set()
        self.suspicious_activities = defaultdict(int)
        self.ddos_threshold = 1000  # pachete/secundă
        self.packet_rates = defaultdict(list)

    def analyze_packet(self, src_ip, dst_ip, packet_size):
        """Analizează pachetul pentru amenințări"""
        current_time = time.time()

        # Detectare DDoS
        self.packet_rates[src_ip].append(current_time)
        # Păstrează doar ultimele 60 secunde
        self.packet_rates[src_ip] = [t for t in self.packet_rates[src_ip]
                                     if current_time - t < 60]

        if len(self.packet_rates[src_ip]) > self.ddos_threshold:
            self.block_ip(src_ip, "DDoS detected")
            return False

        # Detectare port scanning
        if dst_ip not in self.suspicious_activities:
            self.suspicious_activities[dst_ip] = 0
        self.suspicious_activities[dst_ip] += 1

        return src_ip not in self.blocked_ips

    def block_ip(self, ip, reason):
        self.blocked_ips.add(ip)
        print(f"[SECURITY] Blocked IP {ip}: {reason}")

    def unblock_ip(self, ip):
        self.blocked_ips.discard(ip)


class NetworkTopology:
    """Gestionarea topologiei rețelei"""

    def __init__(self):
        self.nodes = {}  # switch_id -> Switch
        self.links = defaultdict(list)  # switch_id -> [connected_switches]
        self.shortest_paths = {}

    def add_switch(self, switch):
        self.nodes[switch.dpid] = switch

    def add_link(self, switch1_id, switch2_id, port1, port2):
        self.links[switch1_id].append({'switch': switch2_id, 'port': port1})
        self.links[switch2_id].append({'switch': switch1_id, 'port': port2})
        self._update_shortest_paths()

    def _update_shortest_paths(self):
        """Calculează cel mai scurt drum între toate perechile de switch-uri"""
        # Implementare simplificată Floyd-Warshall
        nodes = list(self.nodes.keys())
        dist = defaultdict(lambda: defaultdict(lambda: float('inf')))
        next_hop = defaultdict(dict)

        # Inițializare
        for node in nodes:
            dist[node][node] = 0

        for node, connections in self.links.items():
            for conn in connections:
                dist[node][conn['switch']] = 1
                next_hop[node][conn['switch']] = conn['switch']

        # Floyd-Warshall
        for k in nodes:
            for i in nodes:
                for j in nodes:
                    if dist[i][k] + dist[k][j] < dist[i][j]:
                        dist[i][j] = dist[i][k] + dist[k][j]
                        next_hop[i][j] = next_hop[i][k]

        self.shortest_paths = next_hop

    def get_path(self, src_switch, dst_switch):
        """Returnează calea între două switch-uri"""
        if src_switch not in self.shortest_paths or dst_switch not in self.shortest_paths[src_switch]:
            return []

        path = [src_switch]
        current = src_switch
        while current != dst_switch:
            current = self.shortest_paths[current][dst_switch]
            path.append(current)
        return path


class MonitoringModule:
    """Modul de monitorizare și statistici"""

    def __init__(self):
        self.stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'flows_installed': 0,
            'switches_connected': 0
        }
        self.switch_stats = defaultdict(dict)
        self.flow_stats = []

    def update_stats(self, switch_id, packet_count, byte_count):
        self.stats['total_packets'] += packet_count
        self.stats['total_bytes'] += byte_count

        if switch_id not in self.switch_stats:
            self.switch_stats[switch_id] = {
                'packets': 0,
                'bytes': 0,
                'flows': 0
            }

        self.switch_stats[switch_id]['packets'] += packet_count
        self.switch_stats[switch_id]['bytes'] += byte_count

    def get_statistics(self):
        return {
            'global': self.stats,
            'switches': dict(self.switch_stats),
            'timestamp': datetime.now().isoformat()
        }


class SDNController:
    """Controller SDN principal"""

    def __init__(self, host='0.0.0.0', port=6633):
        self.host = host
        self.port = port
        self.switches = {}
        self.topology = NetworkTopology()
        self.load_balancer = LoadBalancer()
        self.security = SecurityModule()
        self.monitoring = MonitoringModule()
        self.running = False
        self.server_socket = None

        # Configurare load balancer cu servere de test
        self.load_balancer.add_server('192.168.1.100', 80)
        self.load_balancer.add_server('192.168.1.101', 80)
        self.load_balancer.add_server('192.168.1.102', 80)

    def start(self):
        """Pornește controllerul"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(10)

        self.running = True
        print(f"[CONTROLLER] Started on {self.host}:{self.port}")

        # Start monitoring thread
        monitor_thread = threading.Thread(target=self._monitoring_loop)
        monitor_thread.daemon = True
        monitor_thread.start()

        try:
            while self.running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    print(f"[CONTROLLER] New connection from {addr}")

                    # Handle connection in separate thread
                    client_thread = threading.Thread(
                        target=self._handle_switch_connection,
                        args=(client_socket, addr)
                    )
                    client_thread.daemon = True
                    client_thread.start()

                except socket.error as e:
                    if self.running:
                        print(f"[ERROR] Socket error: {e}")

        except KeyboardInterrupt:
            print("\n[CONTROLLER] Shutting down...")
        finally:
            self.stop()

    def stop(self):
        """Oprește controllerul"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()

    def _handle_switch_connection(self, client_socket, addr):
        """Gestionează conexiunea cu un switch"""
        try:
            # Simulare handshake OpenFlow
            hello_msg = OpenFlowMessage(msg_type=0)  # OFPT_HELLO
            client_socket.send(hello_msg.pack())

            # Creare switch nou
            switch_id = f"sw_{addr[0]}_{addr[1]}"
            switch = Switch(switch_id, addr[0], addr[1])
            self.switches[switch_id] = switch
            self.topology.add_switch(switch)
            self.monitoring.stats['switches_connected'] += 1

            print(f"[CONTROLLER] Switch {switch_id} connected")

            # Simulare mesaje de la switch
            self._simulate_switch_messages(client_socket, switch)

        except Exception as e:
            print(f"[ERROR] Switch connection error: {e}")
        finally:
            client_socket.close()

    def _simulate_switch_messages(self, client_socket, switch):
        """Simulează mesaje de la switch pentru demonstrație"""
        import random

        while self.running:
            try:
                # Simulare PACKET_IN
                packet_info = {
                    'src_ip': f"192.168.1.{random.randint(1, 254)}",
                    'dst_ip': f"192.168.1.{random.randint(1, 254)}",
                    'src_port': random.randint(1024, 65535),
                    'dst_port': random.choice([80, 443, 22, 21]),
                    'protocol': random.choice(['TCP', 'UDP']),
                    'size': random.randint(64, 1500)
                }

                self._handle_packet_in(switch, packet_info)
                time.sleep(random.uniform(0.1, 2.0))

            except Exception as e:
                print(f"[ERROR] Switch simulation error: {e}")
                break

    def _handle_packet_in(self, switch, packet_info):
        """Gestionează mesajele PACKET_IN de la switch-uri"""
        src_ip = packet_info['src_ip']
        dst_ip = packet_info['dst_ip']
        dst_port = packet_info['dst_port']

        # Verificare securitate
        if not self.security.analyze_packet(src_ip, dst_ip, packet_info['size']):
            print(f"[SECURITY] Packet blocked from {src_ip}")
            return

        # Update statistics
        self.monitoring.update_stats(switch.dpid, 1, packet_info['size'])

        # Căutare flow existent
        existing_flow = switch.find_matching_flow(packet_info)
        if existing_flow:
            existing_flow.packet_count += 1
            existing_flow.byte_count += packet_info['size']
            return

        # Determinare acțiuni
        actions = self._determine_actions(packet_info)

        # Creare flow nou
        match = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'dst_port': dst_port
        }

        flow_entry = FlowEntry(match, actions, priority=100, timeout=30)
        switch.add_flow(flow_entry)
        self.monitoring.stats['flows_installed'] += 1

        print(f"[FLOW] Installed flow: {src_ip} -> {dst_ip}:{dst_port} | Actions: {actions}")

    def _determine_actions(self, packet_info):
        """Determină acțiunile pentru un pachet"""
        dst_port = packet_info['dst_port']
        actions = []

        # Load balancing pentru traficul web
        if dst_port in [80, 443]:
            server = self.load_balancer.get_next_server()
            if server:
                actions.append(f"SET_DST_IP:{server['ip']}")
                actions.append(f"SET_DST_PORT:{server['port']}")
                self.load_balancer.update_connections(server['ip'], 1)

        # Rutare normală
        actions.append("OUTPUT:NORMAL")

        return actions

    def _monitoring_loop(self):
        """Loop de monitorizare pentru statistici periodice"""
        while self.running:
            try:
                time.sleep(10)  # Raportare la fiecare 10 secunde
                stats = self.monitoring.get_statistics()
                print(f"\n[MONITORING] Statistics: {json.dumps(stats, indent=2)}")

                # Cleanup expired flows
                self._cleanup_expired_flows()

            except Exception as e:
                print(f"[ERROR] Monitoring error: {e}")

    def _cleanup_expired_flows(self):
        """Curăță flow-urile expirate"""
        current_time = time.time()
        for switch in self.switches.values():
            switch.flow_table = [
                flow for flow in switch.flow_table
                if flow.timeout == 0 or (current_time - flow.timestamp) < flow.timeout
            ]

    def get_network_status(self):
        """Returnează statusul complet al rețelei"""
        return {
            'controller': {
                'running': self.running,
                'switches_connected': len(self.switches)
            },
            'topology': {
                'switches': list(self.switches.keys()),
                'links': dict(self.topology.links)
            },
            'security': {
                'blocked_ips': list(self.security.blocked_ips),
                'suspicious_activities': dict(self.security.suspicious_activities)
            },
            'load_balancer': {
                'servers': self.load_balancer.servers
            },
            'monitoring': self.monitoring.get_statistics()
        }


# Management Interface
class ControllerAPI:
    """API pentru managementul controllerului"""

    def __init__(self, controller):
        self.controller = controller

    def add_flow_rule(self, switch_id, match, actions, priority=100):
        """Adaugă o regulă de flow"""
        if switch_id in self.controller.switches:
            switch = self.controller.switches[switch_id]
            flow = FlowEntry(match, actions, priority)
            switch.add_flow(flow)
            return True
        return False

    def block_ip(self, ip, reason="Manual block"):
        """Blochează o adresă IP"""
        self.controller.security.block_ip(ip, reason)

    def get_statistics(self):
        """Obține statistici complete"""
        return self.controller.get_network_status()


def main():
    """Funcția principală pentru testare"""
    controller = SDNController()
    api = ControllerAPI(controller)

    try:
        print("Starting SDN Controller...")
        print("Features enabled:")
        print("- OpenFlow support")
        print("- Dynamic routing")
        print("- Load balancing")
        print("- Security monitoring")
        print("- Network topology management")
        print("- Flow statistics")
        print("\nPress Ctrl+C to stop")

        controller.start()

    except KeyboardInterrupt:
        print("\nShutting down controller...")
        controller.stop()


if __name__ == "__main__":
    main()