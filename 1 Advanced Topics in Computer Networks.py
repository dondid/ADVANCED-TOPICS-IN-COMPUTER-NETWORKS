import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import networkx as nx
import numpy as np
import threading
import time
import random
import socket
import struct
from collections import defaultdict, deque
import json


class NetworkSimulator:
    def __init__(self):
        self.nodes = {}
        self.edges = {}
        self.routing_tables = {}
        self.traffic_flows = []

    def add_node(self, node_id, node_type="router"):
        self.nodes[node_id] = {
            'type': node_type,
            'active': True,
            'load': 0,
            'buffer_size': 100,
            'queue': deque()
        }
        self.routing_tables[node_id] = {}

    def add_edge(self, node1, node2, weight=1, bandwidth=100):
        edge_id = f"{node1}-{node2}"
        self.edges[edge_id] = {
            'nodes': (node1, node2),
            'weight': weight,
            'bandwidth': bandwidth,
            'utilization': 0,
            'active': True
        }

    def dijkstra(self, start, end):
        if start not in self.nodes or end not in self.nodes:
            return None, float('inf')

        distances = {node: float('inf') for node in self.nodes}
        distances[start] = 0
        previous = {}
        unvisited = set(self.nodes.keys())

        while unvisited:
            current = min(unvisited, key=lambda x: distances[x])
            if distances[current] == float('inf'):
                break

            unvisited.remove(current)

            if current == end:
                path = []
                while current in previous:
                    path.insert(0, current)
                    current = previous[current]
                path.insert(0, start)
                return path, distances[end]

            for edge_id, edge in self.edges.items():
                if not edge['active']:
                    continue

                neighbor = None
                if edge['nodes'][0] == current:
                    neighbor = edge['nodes'][1]
                elif edge['nodes'][1] == current:
                    neighbor = edge['nodes'][0]

                if neighbor and neighbor in unvisited:
                    alt = distances[current] + edge['weight']
                    if alt < distances[neighbor]:
                        distances[neighbor] = alt
                        previous[neighbor] = current

        return None, float('inf')


class AdvancedNetworksApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Topics in Computer Networks - Aplicație Completă")
        self.root.geometry("1400x900")
        self.root.configure(bg='#2c3e50')

        self.simulator = NetworkSimulator()
        self.current_simulation = None
        self.simulation_running = False

        self.setup_ui()
        self.setup_default_network()

    def setup_ui(self):
        # Notebook principal pentru taburi
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)

        # Tab-uri pentru diferite module
        self.create_routing_tab()
        self.create_qos_tab()
        self.create_security_tab()

    def create_routing_tab(self):
        # Tab pentru Routing Algorithms
        routing_frame = ttk.Frame(self.notebook)
        self.notebook.add(routing_frame, text="Routing & Switching")

        # Left panel pentru controale
        left_panel = ttk.Frame(routing_frame)
        left_panel.pack(side='left', fill='y', padx=10, pady=10)

        ttk.Label(left_panel, text="Algoritmi de Routing", font=('Arial', 14, 'bold')).pack(pady=10)

        # Algoritmi disponibili
        algorithms_frame = ttk.LabelFrame(left_panel, text="Algoritmi")
        algorithms_frame.pack(fill='x', pady=5)

        self.routing_var = tk.StringVar(value="dijkstra")
        ttk.Radiobutton(algorithms_frame, text="Dijkstra (Shortest Path)",
                        variable=self.routing_var, value="dijkstra").pack(anchor='w')
        ttk.Radiobutton(algorithms_frame, text="Bellman-Ford",
                        variable=self.routing_var, value="bellman_ford").pack(anchor='w')
        ttk.Radiobutton(algorithms_frame, text="Floyd-Warshall",
                        variable=self.routing_var, value="floyd_warshall").pack(anchor='w')
        ttk.Radiobutton(algorithms_frame, text="OSPF Link State",
                        variable=self.routing_var, value="ospf").pack(anchor='w')
        ttk.Radiobutton(algorithms_frame, text="BGP Path Vector",
                        variable=self.routing_var, value="bgp").pack(anchor='w')

        # Controale pentru simulare
        controls_frame = ttk.LabelFrame(left_panel, text="Controale Simulare")
        controls_frame.pack(fill='x', pady=5)

        ttk.Button(controls_frame, text="Rulează Algoritm",
                   command=self.run_routing_algorithm).pack(fill='x', pady=2)
        ttk.Button(controls_frame, text="Adaugă Nod",
                   command=self.add_network_node).pack(fill='x', pady=2)
        ttk.Button(controls_frame, text="Adaugă Legătură",
                   command=self.add_network_edge).pack(fill='x', pady=2)
        ttk.Button(controls_frame, text="Simulează Trafic",
                   command=self.simulate_traffic).pack(fill='x', pady=2)

        # Configurare rută
        route_frame = ttk.LabelFrame(left_panel, text="Testare Rută")
        route_frame.pack(fill='x', pady=5)

        ttk.Label(route_frame, text="De la:").pack()
        self.source_entry = ttk.Entry(route_frame)
        self.source_entry.pack(fill='x', pady=2)

        ttk.Label(route_frame, text="La:").pack()
        self.dest_entry = ttk.Entry(route_frame)
        self.dest_entry.pack(fill='x', pady=2)

        ttk.Button(route_frame, text="Găsește Rută",
                   command=self.find_route).pack(fill='x', pady=2)

        # Right panel pentru vizualizare
        right_panel = ttk.Frame(routing_frame)
        right_panel.pack(side='right', fill='both', expand=True, padx=10, pady=10)

        # Canvas pentru network graph
        self.routing_fig, self.routing_ax = plt.subplots(figsize=(10, 8))
        self.routing_canvas = FigureCanvasTkAgg(self.routing_fig, right_panel)
        self.routing_canvas.get_tk_widget().pack(fill='both', expand=True)

        # Text widget pentru rezultate
        self.routing_results = scrolledtext.ScrolledText(right_panel, height=12, width=80)
        self.routing_results.pack(fill='x', pady=5)

    def create_qos_tab(self):
        # Tab pentru Quality of Service
        qos_frame = ttk.Frame(self.notebook)
        self.notebook.add(qos_frame, text="Quality of Service")

        # Left panel pentru QoS controls
        left_panel = ttk.Frame(qos_frame)
        left_panel.pack(side='left', fill='y', padx=10, pady=10)

        ttk.Label(left_panel, text="Quality of Service", font=('Arial', 14, 'bold')).pack(pady=10)

        # QoS Mechanisms
        qos_mechanisms = ttk.LabelFrame(left_panel, text="Mecanisme QoS")
        qos_mechanisms.pack(fill='x', pady=5)

        self.qos_mechanism = tk.StringVar(value="fifo")
        ttk.Radiobutton(qos_mechanisms, text="FIFO (First In First Out)",
                        variable=self.qos_mechanism, value="fifo").pack(anchor='w')
        ttk.Radiobutton(qos_mechanisms, text="Priority Queuing",
                        variable=self.qos_mechanism, value="priority").pack(anchor='w')
        ttk.Radiobutton(qos_mechanisms, text="Weighted Fair Queuing",
                        variable=self.qos_mechanism, value="wfq").pack(anchor='w')
        ttk.Radiobutton(qos_mechanisms, text="Token Bucket",
                        variable=self.qos_mechanism, value="token_bucket").pack(anchor='w')
        ttk.Radiobutton(qos_mechanisms, text="Leaky Bucket",
                        variable=self.qos_mechanism, value="leaky_bucket").pack(anchor='w')

        # Traffic Classes
        traffic_frame = ttk.LabelFrame(left_panel, text="Clase de Trafic")
        traffic_frame.pack(fill='x', pady=5)

        ttk.Label(traffic_frame, text="Voice (VoIP):").pack(anchor='w')
        self.voice_priority = ttk.Scale(traffic_frame, from_=1, to=5, orient='horizontal')
        self.voice_priority.set(5)
        self.voice_priority.pack(fill='x')

        ttk.Label(traffic_frame, text="Video:").pack(anchor='w')
        self.video_priority = ttk.Scale(traffic_frame, from_=1, to=5, orient='horizontal')
        self.video_priority.set(4)
        self.video_priority.pack(fill='x')

        ttk.Label(traffic_frame, text="Data:").pack(anchor='w')
        self.data_priority = ttk.Scale(traffic_frame, from_=1, to=5, orient='horizontal')
        self.data_priority.set(2)
        self.data_priority.pack(fill='x')

        # QoS Controls
        controls_frame = ttk.LabelFrame(left_panel, text="Controale QoS")
        controls_frame.pack(fill='x', pady=5)

        ttk.Button(controls_frame, text="Simulează QoS",
                   command=self.simulate_qos).pack(fill='x', pady=2)
        ttk.Button(controls_frame, text="Analizează Latența",
                   command=self.analyze_latency).pack(fill='x', pady=2)
        ttk.Button(controls_frame, text="Testează Bandwidth",
                   command=self.test_bandwidth).pack(fill='x', pady=2)

        # Right panel pentru QoS visualization
        right_panel = ttk.Frame(qos_frame)
        right_panel.pack(side='right', fill='both', expand=True, padx=10, pady=10)

        # Canvas pentru QoS graphs
        self.qos_fig, (self.qos_ax1, self.qos_ax2) = plt.subplots(2, 1, figsize=(10, 8))
        self.qos_canvas = FigureCanvasTkAgg(self.qos_fig, right_panel)
        self.qos_canvas.get_tk_widget().pack(fill='both', expand=True)

        # QoS Results
        self.qos_results = scrolledtext.ScrolledText(right_panel, height=12, width=80)
        self.qos_results.pack(fill='x', pady=5)

    def create_security_tab(self):
        # Tab pentru Network Security
        security_frame = ttk.Frame(self.notebook)
        self.notebook.add(security_frame, text="Network Security")

        # Left panel pentru security controls
        left_panel = ttk.Frame(security_frame)
        left_panel.pack(side='left', fill='y', padx=10, pady=10)

        ttk.Label(left_panel, text="Securitatea Rețelei", font=('Arial', 14, 'bold')).pack(pady=10)

        # Security Protocols
        protocols_frame = ttk.LabelFrame(left_panel, text="Protocoale de Securitate")
        protocols_frame.pack(fill='x', pady=5)

        security_protocols = ["IPSec", "SSL/TLS", "VPN", "Firewall", "IDS/IPS", "WPA/WPA2"]
        for protocol in security_protocols:
            ttk.Checkbutton(protocols_frame, text=protocol).pack(anchor='w')

        # Encryption Methods
        encryption_frame = ttk.LabelFrame(left_panel, text="Metode de Criptare")
        encryption_frame.pack(fill='x', pady=5)

        self.encryption_method = tk.StringVar(value="aes")
        ttk.Radiobutton(encryption_frame, text="AES (Advanced Encryption Standard)",
                        variable=self.encryption_method, value="aes").pack(anchor='w')
        ttk.Radiobutton(encryption_frame, text="RSA (Public Key)",
                        variable=self.encryption_method, value="rsa").pack(anchor='w')
        ttk.Radiobutton(encryption_frame, text="DES (Data Encryption Standard)",
                        variable=self.encryption_method, value="des").pack(anchor='w')

        # Security Tools
        tools_frame = ttk.LabelFrame(left_panel, text="Instrumente Securitate")
        tools_frame.pack(fill='x', pady=5)

        ttk.Button(tools_frame, text="Simulează Atac",
                   command=self.simulate_attack).pack(fill='x', pady=2)
        ttk.Button(tools_frame, text="Testează Firewall",
                   command=self.test_firewall).pack(fill='x', pady=2)
        ttk.Button(tools_frame, text="Analizează Vulnerabilități",
                   command=self.vulnerability_scan).pack(fill='x', pady=2)
        ttk.Button(tools_frame, text="Demonstrează Criptare",
                   command=self.demonstrate_encryption).pack(fill='x', pady=2)

        # Right panel pentru security visualization
        right_panel = ttk.Frame(security_frame)
        right_panel.pack(side='right', fill='both', expand=True, padx=10, pady=10)

        # Security Results
        self.security_results = scrolledtext.ScrolledText(right_panel, height=30, width=100)
        self.security_results.pack(fill='both', expand=True)

        # Security Metrics
        metrics_frame = ttk.Frame(right_panel)
        metrics_frame.pack(fill='x', pady=5)

        ttk.Label(metrics_frame, text="Metrici de Securitate:").pack(anchor='w')
        self.security_metrics = tk.Text(metrics_frame, height=6)
        self.security_metrics.pack(fill='x')

    def create_protocols_tab(self):
        # Tab pentru Network Protocols
        protocols_frame = ttk.Frame(self.notebook)
        self.notebook.add(protocols_frame, text="Network Protocols")

        # Left panel pentru protocol controls
        left_panel = ttk.Frame(protocols_frame)
        left_panel.pack(side='left', fill='y', padx=10, pady=10)

        ttk.Label(left_panel, text="Protocoale de Rețea", font=('Arial', 14, 'bold')).pack(pady=10)

        # Protocol Layers
        layers_frame = ttk.LabelFrame(left_panel, text="Straturi Protocoale")
        layers_frame.pack(fill='x', pady=5)

        layers = [
            ("Application Layer", ["HTTP/HTTPS", "FTP", "SMTP", "DNS", "DHCP"]),
            ("Transport Layer", ["TCP", "UDP", "SCTP"]),
            ("Network Layer", ["IP", "ICMP", "OSPF", "BGP"]),
            ("Data Link Layer", ["Ethernet", "WiFi", "PPP"]),
            ("Physical Layer", ["Fiber", "Copper", "Wireless"])
        ]

        for layer_name, protocols in layers:
            layer_frame = ttk.LabelFrame(layers_frame, text=layer_name)
            layer_frame.pack(fill='x', pady=2)
            for protocol in protocols:
                ttk.Checkbutton(layer_frame, text=protocol).pack(anchor='w')

        # Protocol Analysis Tools
        analysis_frame = ttk.LabelFrame(left_panel, text="Analiză Protocoale")
        analysis_frame.pack(fill='x', pady=5)

        ttk.Button(analysis_frame, text="Packet Capture",
                   command=self.packet_capture).pack(fill='x', pady=2)
        ttk.Button(analysis_frame, text="Protocol Decoder",
                   command=self.protocol_decode).pack(fill='x', pady=2)
        ttk.Button(analysis_frame, text="Flow Analysis",
                   command=self.flow_analysis).pack(fill='x', pady=2)

        # Right panel pentru protocol visualization
        right_panel = ttk.Frame(protocols_frame)
        right_panel.pack(side='right', fill='both', expand=True, padx=10, pady=10)

        # Protocol Stack Visualization
        self.protocol_fig, self.protocol_ax = plt.subplots(figsize=(10, 6))
        self.protocol_canvas = FigureCanvasTkAgg(self.protocol_fig, right_panel)
        self.protocol_canvas.get_tk_widget().pack(fill='both', expand=True)

        # Protocol Details
        self.protocol_details = scrolledtext.ScrolledText(right_panel, height=15, width=90)
        self.protocol_details.pack(fill='x', pady=5)

    def create_performance_tab(self):
        # Tab pentru Network Performance
        performance_frame = ttk.Frame(self.notebook)
        self.notebook.add(performance_frame, text="Performance Analysis")

        # Left panel pentru performance controls
        left_panel = ttk.Frame(performance_frame)
        left_panel.pack(side='left', fill='y', padx=10, pady=10)

        ttk.Label(left_panel, text="Analiza Performanței", font=('Arial', 14, 'bold')).pack(pady=10)

        # Performance Metrics
        metrics_frame = ttk.LabelFrame(left_panel, text="Metrici de Performanță")
        metrics_frame.pack(fill='x', pady=5)

        performance_metrics = ["Throughput", "Latency", "Jitter", "Packet Loss",
                               "Bandwidth Utilization", "CPU Usage", "Memory Usage"]
        for metric in performance_metrics:
            ttk.Checkbutton(metrics_frame, text=metric).pack(anchor='w')

        # Monitoring Tools
        monitoring_frame = ttk.LabelFrame(left_panel, text="Instrumente Monitorizare")
        monitoring_frame.pack(fill='x', pady=5)

        ttk.Button(monitoring_frame, text="Start Monitoring",
                   command=self.start_monitoring).pack(fill='x', pady=2)
        ttk.Button(monitoring_frame, text="Bandwidth Test",
                   command=self.bandwidth_test).pack(fill='x', pady=2)
        ttk.Button(monitoring_frame, text="Latency Test",
                   command=self.latency_test).pack(fill='x', pady=2)
        ttk.Button(monitoring_frame, text="Generate Report",
                   command=self.generate_performance_report).pack(fill='x', pady=2)

        # Right panel pentru performance graphs
        right_panel = ttk.Frame(performance_frame)
        right_panel.pack(side='right', fill='both', expand=True, padx=10, pady=10)

        # Performance Charts
        self.perf_fig, ((self.perf_ax1, self.perf_ax2),
                        (self.perf_ax3, self.perf_ax4)) = plt.subplots(2, 2, figsize=(12, 8))
        self.perf_canvas = FigureCanvasTkAgg(self.perf_fig, right_panel)
        self.perf_canvas.get_tk_widget().pack(fill='both', expand=True)

        # Performance Summary
        self.perf_summary = scrolledtext.ScrolledText(right_panel, height=6)
        self.perf_summary.pack(fill='x', pady=5)

    def create_sdn_tab(self):
        # Tab pentru Software Defined Networking
        sdn_frame = ttk.Frame(self.notebook)
        self.notebook.add(sdn_frame, text="SDN & NFV")

        # Left panel pentru SDN controls
        left_panel = ttk.Frame(sdn_frame)
        left_panel.pack(side='left', fill='y', padx=10, pady=10)

        ttk.Label(left_panel, text="Software Defined Networking",
                  font=('Arial', 14, 'bold')).pack(pady=10)

        # SDN Components
        components_frame = ttk.LabelFrame(left_panel, text="Componente SDN")
        components_frame.pack(fill='x', pady=5)

        sdn_components = ["OpenFlow Controller", "OpenFlow Switch",
                          "Northbound API", "Southbound API", "Network Apps"]
        for component in sdn_components:
            ttk.Checkbutton(components_frame, text=component).pack(anchor='w')

        # SDN Operations
        operations_frame = ttk.LabelFrame(left_panel, text="Operații SDN")
        operations_frame.pack(fill='x', pady=5)

        ttk.Button(operations_frame, text="Simulează Controller",
                   command=self.simulate_sdn_controller).pack(fill='x', pady=2)
        ttk.Button(operations_frame, text="Flow Table Management",
                   command=self.manage_flow_tables).pack(fill='x', pady=2)
        ttk.Button(operations_frame, text="Network Slicing",
                   command=self.network_slicing).pack(fill='x', pady=2)
        ttk.Button(operations_frame, text="NFV Orchestration",
                   command=self.nfv_orchestration).pack(fill='x', pady=2)

        # Right panel pentru SDN visualization
        right_panel = ttk.Frame(sdn_frame)
        right_panel.pack(side='right', fill='both', expand=True, padx=10, pady=10)

        # SDN Architecture
        self.sdn_fig, self.sdn_ax = plt.subplots(figsize=(10, 8))
        self.sdn_canvas = FigureCanvasTkAgg(self.sdn_fig, right_panel)
        self.sdn_canvas.get_tk_widget().pack(fill='both', expand=True)

        # SDN Logs
        self.sdn_logs = scrolledtext.ScrolledText(right_panel, height=8)
        self.sdn_logs.pack(fill='x', pady=5)

    def create_network_design_tab(self):
        # Tab pentru Network Design
        design_frame = ttk.Frame(self.notebook)
        self.notebook.add(design_frame, text="Network Design")

        # Left panel pentru design tools
        left_panel = ttk.Frame(design_frame)
        left_panel.pack(side='left', fill='y', padx=10, pady=10)

        ttk.Label(left_panel, text="Proiectarea Rețelelor",
                  font=('Arial', 14, 'bold')).pack(pady=10)

        # Design Patterns
        patterns_frame = ttk.LabelFrame(left_panel, text="Tipologii de Rețea")
        patterns_frame.pack(fill='x', pady=5)

        self.topology_var = tk.StringVar(value="hierarchical")
        topologies = [("Hierarchical", "hierarchical"), ("Mesh", "mesh"),
                      ("Star", "star"), ("Ring", "ring"), ("Hybrid", "hybrid")]
        for name, value in topologies:
            ttk.Radiobutton(patterns_frame, text=name,
                            variable=self.topology_var, value=value).pack(anchor='w')

        # Design Tools
        tools_frame = ttk.LabelFrame(left_panel, text="Instrumente Design")
        tools_frame.pack(fill='x', pady=5)

        ttk.Button(tools_frame, text="Generează Topologie",
                   command=self.generate_topology).pack(fill='x', pady=2)
        ttk.Button(tools_frame, text="Calculează Redundanță",
                   command=self.calculate_redundancy).pack(fill='x', pady=2)
        ttk.Button(tools_frame, text="Optimizează Design",
                   command=self.optimize_design).pack(fill='x', pady=2)
        ttk.Button(tools_frame, text="Cost Analysis",
                   command=self.cost_analysis).pack(fill='x', pady=2)

        # Right panel pentru design visualization
        right_panel = ttk.Frame(design_frame)
        right_panel.pack(side='right', fill='both', expand=True, padx=10, pady=10)

        # Design Canvas
        self.design_fig, self.design_ax = plt.subplots(figsize=(10, 8))
        self.design_canvas = FigureCanvasTkAgg(self.design_fig, right_panel)
        self.design_canvas.get_tk_widget().pack(fill='both', expand=True)

        # Design Report
        self.design_report = scrolledtext.ScrolledText(right_panel, height=8)
        self.design_report.pack(fill='x', pady=5)

    def create_troubleshooting_tab(self):
        # Tab pentru Network Troubleshooting
        trouble_frame = ttk.Frame(self.notebook)
        self.notebook.add(trouble_frame, text="Troubleshooting")

        # Left panel pentru troubleshooting tools
        left_panel = ttk.Frame(trouble_frame)
        left_panel.pack(side='left', fill='y', padx=10, pady=10)

        ttk.Label(left_panel, text="Depanarea Rețelelor",
                  font=('Arial', 14, 'bold')).pack(pady=10)

        # Diagnostic Tools
        diag_frame = ttk.LabelFrame(left_panel, text="Instrumente Diagnostic")
        diag_frame.pack(fill='x', pady=5)

        diagnostic_tools = ["Ping", "Traceroute", "Netstat", "Nslookup",
                            "Wireshark", "SNMP Monitor"]
        for tool in diagnostic_tools:
            ttk.Button(diag_frame, text=tool,
                       command=lambda t=tool: self.run_diagnostic_tool(t)).pack(fill='x', pady=1)

        # Problem Categories
        problems_frame = ttk.LabelFrame(left_panel, text="Categorii Probleme")
        problems_frame.pack(fill='x', pady=5)

        problem_types = ["Connectivity Issues", "Performance Problems",
                         "Security Breaches", "Configuration Errors", "Hardware Failures"]
        for problem in problem_types:
            ttk.Checkbutton(problems_frame, text=problem).pack(anchor='w')

        # Troubleshooting Actions
        actions_frame = ttk.LabelFrame(left_panel, text="Acțiuni Depanare")
        actions_frame.pack(fill='x', pady=5)

        ttk.Button(actions_frame, text="Simulează Problemă",
                   command=self.simulate_problem).pack(fill='x', pady=2)
        ttk.Button(actions_frame, text="Rulează Diagnostic",
                   command=self.run_full_diagnostic).pack(fill='x', pady=2)
        ttk.Button(actions_frame, text="Generează Soluții",
                   command=self.generate_solutions).pack(fill='x', pady=2)

        # Right panel pentru troubleshooting results
        right_panel = ttk.Frame(trouble_frame)
        right_panel.pack(side='right', fill='both', expand=True, padx=10, pady=10)

        # Troubleshooting Console
        self.trouble_console = scrolledtext.ScrolledText(right_panel, height=25)
        self.trouble_console.pack(fill='both', expand=True)

        # Status Bar
        self.status_frame = ttk.Frame(right_panel)
        self.status_frame.pack(fill='x', pady=5)
        self.status_label = ttk.Label(self.status_frame, text="Ready")
        self.status_label.pack(side='left')

    def setup_default_network(self):
        # Configurează o rețea default pentru demonstrații
        nodes = ['A', 'B', 'C', 'D', 'E', 'F']
        for node in nodes:
            self.simulator.add_node(node)

        # Adaugă legături cu diferite ponderi
        connections = [
            ('A', 'B', 2), ('A', 'C', 4), ('B', 'C', 1),
            ('B', 'D', 7), ('C', 'D', 3), ('C', 'E', 5),
            ('D', 'E', 1), ('D', 'F', 2), ('E', 'F', 3)
        ]

        for node1, node2, weight in connections:
            self.simulator.add_edge(node1, node2, weight, bandwidth=100)

        self.update_routing_visualization()

    def run_routing_algorithm(self):
        algorithm = self.routing_var.get()
        self.routing_results.delete(1.0, tk.END)

        if algorithm == "dijkstra":
            self.run_dijkstra()
        elif algorithm == "bellman_ford":
            self.run_bellman_ford()
        elif algorithm == "floyd_warshall":
            self.run_floyd_warshall()
        elif algorithm == "ospf":
            self.run_ospf()
        elif algorithm == "bgp":
            self.run_bgp()

    def run_dijkstra(self):
        self.routing_results.insert(tk.END, "=== Algoritmul Dijkstra ===\n")
        self.routing_results.insert(tk.END, "Calculând cea mai scurtă cale între toate nodurile...\n\n")

        nodes = list(self.simulator.nodes.keys())
        for source in nodes:
            self.routing_results.insert(tk.END, f"De la nodul {source}:\n")
            for dest in nodes:
                if source != dest:
                    path, distance = self.simulator.dijkstra(source, dest)
                    if path:
                        path_str = " -> ".join(path)
                        self.routing_results.insert(tk.END, f"  La {dest}: {path_str} (cost: {distance})\n")
                    else:
                        self.routing_results.insert(tk.END, f"  La {dest}: Nu există cale\n")
            self.routing_results.insert(tk.END, "\n")

        self.update_routing_visualization()

    def run_bellman_ford(self):
        self.routing_results.insert(tk.END, "=== Algoritmul Bellman-Ford ===\n")
        self.routing_results.insert(tk.END,
                                    "Algoritmul Bellman-Ford detectează cicluri negative și calculează distanțe.\n")
        self.routing_results.insert(tk.END, "Avantaje: Detectează cicluri negative, funcționează cu ponderi negative\n")
        self.routing_results.insert(tk.END, "Dezavantaje: Mai lent decât Dijkstra (O(VE) vs O(V²))\n\n")

        # Simulare Bellman-Ford
        nodes = list(self.simulator.nodes.keys())
        if nodes:
            source = nodes[0]
            distances = self.bellman_ford_implementation(source)

            self.routing_results.insert(tk.END, f"Distanțe de la nodul {source}:\n")
            for node, dist in distances.items():
                if dist == float('inf'):
                    self.routing_results.insert(tk.END, f"  La {node}: ∞\n")
                else:
                    self.routing_results.insert(tk.END, f"  La {node}: {dist}\n")

    def bellman_ford_implementation(self, source):
        distances = {node: float('inf') for node in self.simulator.nodes}
        distances[source] = 0

        # Relaxare pentru V-1 iterații
        for _ in range(len(self.simulator.nodes) - 1):
            for edge_id, edge in self.simulator.edges.items():
                if not edge['active']:
                    continue

                u, v = edge['nodes']
                weight = edge['weight']

                if distances[u] != float('inf') and distances[u] + weight < distances[v]:
                    distances[v] = distances[u] + weight
                if distances[v] != float('inf') and distances[v] + weight < distances[u]:
                    distances[u] = distances[v] + weight

        return distances

    def run_floyd_warshall(self):
        self.routing_results.insert(tk.END, "=== Algoritmul Floyd-Warshall ===\n")
        self.routing_results.insert(tk.END, "Calculând toate perechile de căi cele mai scurte...\n\n")

        nodes = list(self.simulator.nodes.keys())
        n = len(nodes)

        # Inițializare matrice distanțe
        dist = [[float('inf')] * n for _ in range(n)]

        # Distanța de la un nod la el însuși este 0
        for i in range(n):
            dist[i][i] = 0

        # Completează matricea cu distanțele directe
        for edge_id, edge in self.simulator.edges.items():
            if edge['active']:
                u, v = edge['nodes']
                i, j = nodes.index(u), nodes.index(v)
                dist[i][j] = min(dist[i][j], edge['weight'])
                dist[j][i] = min(dist[j][i], edge['weight'])

        # Algoritmul Floyd-Warshall
        for k in range(n):
            for i in range(n):
                for j in range(n):
                    if dist[i][k] + dist[k][j] < dist[i][j]:
                        dist[i][j] = dist[i][k] + dist[k][j]

        # Afișează rezultatele
        self.routing_results.insert(tk.END, "Matricea distanțelor minime:\n")
        header = "    " + "  ".join(f"{node:>4}" for node in nodes) + "\n"
        self.routing_results.insert(tk.END, header)

        for i, node in enumerate(nodes):
            row = f"{node:>2}: "
            for j in range(n):
                if dist[i][j] == float('inf'):
                    row += "  ∞ "
                else:
                    row += f"{dist[i][j]:>4.0f}"
            self.routing_results.insert(tk.END, row + "\n")

    def run_ospf(self):
        self.routing_results.insert(tk.END, "=== Protocolul OSPF (Open Shortest Path First) ===\n")
        self.routing_results.insert(tk.END, "OSPF este un protocol de routing de tip Link State.\n\n")

        self.routing_results.insert(tk.END, "Caracteristici OSPF:\n")
        self.routing_results.insert(tk.END, "• Folosește algoritmul Dijkstra\n")
        self.routing_results.insert(tk.END, "• Suportă autentificare\n")
        self.routing_results.insert(tk.END, "• Organizare ierarhică în areas\n")
        self.routing_results.insert(tk.END, "• Convergență rapidă\n")
        self.routing_results.insert(tk.END, "• Load balancing pe căi egale\n\n")

        # Simulare OSPF LSA (Link State Advertisement)
        self.routing_results.insert(tk.END, "Simulare LSA Database:\n")
        for node in self.simulator.nodes:
            self.routing_results.insert(tk.END, f"\nRouter {node} LSA:\n")
            for edge_id, edge in self.simulator.edges.items():
                if node in edge['nodes']:
                    neighbor = edge['nodes'][1] if edge['nodes'][0] == node else edge['nodes'][0]
                    self.routing_results.insert(tk.END, f"  Link to {neighbor}: cost {edge['weight']}\n")

    def run_bgp(self):
        self.routing_results.insert(tk.END, "=== Protocolul BGP (Border Gateway Protocol) ===\n")
        self.routing_results.insert(tk.END, "BGP este protocolul de routing pentru internetul global.\n\n")

        self.routing_results.insert(tk.END, "Caracteristici BGP:\n")
        self.routing_results.insert(tk.END, "• Protocol de tip Path Vector\n")
        self.routing_results.insert(tk.END, "• Previne bucle prin AS Path\n")
        self.routing_results.insert(tk.END, "• Politici de routing complexe\n")
        self.routing_results.insert(tk.END, "• eBGP și iBGP\n")
        self.routing_results.insert(tk.END, "• Atribute: AS Path, Next Hop, Local Preference\n\n")

        # Simulare BGP AS Path
        as_numbers = {"A": 65001, "B": 65002, "C": 65003, "D": 65004, "E": 65005, "F": 65006}

        self.routing_results.insert(tk.END, "Simulare AS Path pentru anunțurile BGP:\n")
        for node in self.simulator.nodes:
            as_num = as_numbers.get(node, 65000)
            self.routing_results.insert(tk.END, f"\nAS {as_num} (Router {node}) anunțuri:\n")

            # Simulare anunțuri de rețele
            networks = [f"192.168.{ord(node) - 64}.0/24"]
            for network in networks:
                self.routing_results.insert(tk.END, f"  Network: {network}\n")
                self.routing_results.insert(tk.END, f"  AS Path: {as_num}\n")
                self.routing_results.insert(tk.END, f"  Next Hop: {node}\n")

    def find_route(self):
        source = self.source_entry.get().strip().upper()
        dest = self.dest_entry.get().strip().upper()

        if not source or not dest:
            messagebox.showwarning("Atenție", "Introduceți nodurile sursă și destinație")
            return

        if source not in self.simulator.nodes or dest not in self.simulator.nodes:
            messagebox.showerror("Eroare", "Nodurile specificate nu există în rețea")
            return

        path, distance = self.simulator.dijkstra(source, dest)

        self.routing_results.delete(1.0, tk.END)
        self.routing_results.insert(tk.END, f"=== Ruta de la {source} la {dest} ===\n\n")

        if path:
            path_str = " -> ".join(path)
            self.routing_results.insert(tk.END, f"Cea mai scurtă cale: {path_str}\n")
            self.routing_results.insert(tk.END, f"Costul total: {distance}\n\n")

            # Detalii despre fiecare hop
            self.routing_results.insert(tk.END, "Detalii rută:\n")
            for i in range(len(path) - 1):
                current = path[i]
                next_node = path[i + 1]

                # Găsește edge-ul între noduri
                for edge_id, edge in self.simulator.edges.items():
                    if (current in edge['nodes'] and next_node in edge['nodes']):
                        self.routing_results.insert(tk.END,
                                                    f"  {current} -> {next_node}: cost {edge['weight']}, "
                                                    f"bandwidth {edge['bandwidth']} Mbps\n")
                        break
        else:
            self.routing_results.insert(tk.END, "Nu există cale între nodurile specificate!\n")

        self.highlight_path_on_graph(path if path else [])

    def add_network_node(self):
        node_id = tk.simpledialog.askstring("Adaugă Nod", "Introduceți ID-ul nodului:")
        if node_id:
            node_id = node_id.strip().upper()
            if node_id not in self.simulator.nodes:
                self.simulator.add_node(node_id)
                self.update_routing_visualization()
                messagebox.showinfo("Succes", f"Nodul {node_id} a fost adăugat")
            else:
                messagebox.showwarning("Atenție", "Nodul există deja")

    def add_network_edge(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Adaugă Legătură")
        dialog.geometry("300x200")

        ttk.Label(dialog, text="Primul nod:").pack(pady=5)
        node1_entry = ttk.Entry(dialog)
        node1_entry.pack(pady=5)

        ttk.Label(dialog, text="Al doilea nod:").pack(pady=5)
        node2_entry = ttk.Entry(dialog)
        node2_entry.pack(pady=5)

        ttk.Label(dialog, text="Cost/Greutate:").pack(pady=5)
        weight_entry = ttk.Entry(dialog)
        weight_entry.pack(pady=5)
        weight_entry.insert(0, "1")

        def add_edge():
            node1 = node1_entry.get().strip().upper()
            node2 = node2_entry.get().strip().upper()
            try:
                weight = int(weight_entry.get())
                if node1 in self.simulator.nodes and node2 in self.simulator.nodes:
                    self.simulator.add_edge(node1, node2, weight)
                    self.update_routing_visualization()
                    messagebox.showinfo("Succes", f"Legătura {node1}-{node2} a fost adăugată")
                    dialog.destroy()
                else:
                    messagebox.showerror("Eroare", "Unul sau ambele noduri nu există")
            except ValueError:
                messagebox.showerror("Eroare", "Greutatea trebuie să fie un număr întreg")

        ttk.Button(dialog, text="Adaugă", command=add_edge).pack(pady=10)

    def simulate_traffic(self):
        if not self.simulation_running:
            self.simulation_running = True
            self.traffic_thread = threading.Thread(target=self.traffic_simulation_worker)
            self.traffic_thread.daemon = True
            self.traffic_thread.start()
        else:
            self.simulation_running = False

    def traffic_simulation_worker(self):
        while self.simulation_running:
            # Simulare trafic aleator
            nodes = list(self.simulator.nodes.keys())
            if len(nodes) >= 2:
                source = random.choice(nodes)
                dest = random.choice([n for n in nodes if n != source])

                # Generare pachete
                packet_size = random.randint(64, 1500)  # bytes
                priority = random.choice(['high', 'medium', 'low'])

                # Actualizare utilizare legături
                path, _ = self.simulator.dijkstra(source, dest)
                if path:
                    for i in range(len(path) - 1):
                        current = path[i]
                        next_node = path[i + 1]

                        for edge_id, edge in self.simulator.edges.items():
                            if (current in edge['nodes'] and next_node in edge['nodes']):
                                edge['utilization'] = min(edge['utilization'] +
                                                          packet_size / edge['bandwidth'], 100)
                                break

                # Update vizualizare
                self.root.after(0, self.update_routing_visualization)

            time.sleep(0.5)

    def update_routing_visualization(self):
        self.routing_ax.clear()

        if not self.simulator.nodes:
            self.routing_canvas.draw()
            return

        # Creează graful NetworkX
        G = nx.Graph()

        # Adaugă noduri
        for node_id in self.simulator.nodes:
            G.add_node(node_id)

        # Adaugă muchii
        for edge_id, edge in self.simulator.edges.items():
            if edge['active']:
                u, v = edge['nodes']
                G.add_edge(u, v, weight=edge['weight'])

        # Poziționare noduri
        pos = nx.spring_layout(G, k=2, iterations=50)

        # Desenează noduri
        nx.draw_networkx_nodes(G, pos, ax=self.routing_ax,
                               node_color='lightblue',
                               node_size=1000,
                               alpha=0.8)

        # Desenează muchii cu culori diferite bazate pe utilizare
        edge_colors = []
        for edge_id, edge in self.simulator.edges.items():
            if edge['active']:
                utilization = edge.get('utilization', 0)
                if utilization < 30:
                    edge_colors.append('green')
                elif utilization < 70:
                    edge_colors.append('orange')
                else:
                    edge_colors.append('red')

        nx.draw_networkx_edges(G, pos, ax=self.routing_ax,
                               edge_color=edge_colors,
                               width=2, alpha=0.7)

        # Etichete noduri
        nx.draw_networkx_labels(G, pos, ax=self.routing_ax,
                                font_size=12, font_weight='bold')

        # Etichete muchii (greutăți)
        edge_labels = {}
        for edge_id, edge in self.simulator.edges.items():
            if edge['active']:
                u, v = edge['nodes']
                edge_labels[(u, v)] = str(edge['weight'])

        nx.draw_networkx_edge_labels(G, pos, edge_labels, ax=self.routing_ax, font_size=8)

        self.routing_ax.set_title("Topologia Rețelei și Rutarea", fontsize=14, fontweight='bold')
        self.routing_ax.axis('off')
        self.routing_canvas.draw()

    def highlight_path_on_graph(self, path):
        if not path or len(path) < 2:
            self.update_routing_visualization()
            return

        self.routing_ax.clear()

        # Creează graful NetworkX
        G = nx.Graph()

        # Adaugă noduri
        for node_id in self.simulator.nodes:
            G.add_node(node_id)

        # Adaugă muchii
        for edge_id, edge in self.simulator.edges.items():
            if edge['active']:
                u, v = edge['nodes']
                G.add_edge(u, v, weight=edge['weight'])

        # Poziționare noduri
        pos = nx.spring_layout(G, k=2, iterations=50)

        # Desenează toate nodurile
        node_colors = ['red' if node in path else 'lightblue' for node in G.nodes()]
        nx.draw_networkx_nodes(G, pos, ax=self.routing_ax,
                               node_color=node_colors,
                               node_size=1000,
                               alpha=0.8)

        # Desenează toate muchiile
        nx.draw_networkx_edges(G, pos, ax=self.routing_ax,
                               edge_color='gray',
                               width=1, alpha=0.5)

        # Evidențiază calea
        path_edges = [(path[i], path[i + 1]) for i in range(len(path) - 1)]
        nx.draw_networkx_edges(G, pos, edgelist=path_edges, ax=self.routing_ax,
                               edge_color='red', width=4, alpha=0.8)

        # Etichete noduri
        nx.draw_networkx_labels(G, pos, ax=self.routing_ax,
                                font_size=12, font_weight='bold')

        self.routing_ax.set_title(f"Ruta evidențiată: {' -> '.join(path)}",
                                  fontsize=14, fontweight='bold')
        self.routing_ax.axis('off')
        self.routing_canvas.draw()

    def simulate_qos(self):
        self.qos_results.delete(1.0, tk.END)
        mechanism = self.qos_mechanism.get()

        self.qos_results.insert(tk.END, f"=== Simulare QoS - {mechanism.upper()} ===\n\n")

        # Generare date pentru simulare
        voice_priority = int(self.voice_priority.get())
        video_priority = int(self.video_priority.get())
        data_priority = int(self.data_priority.get())

        # Simulare pachete cu diferite priorități
        packets = []
        for i in range(20):
            packet_type = random.choice(['voice', 'video', 'data'])
            if packet_type == 'voice':
                priority = voice_priority
                size = random.randint(64, 160)  # Pachete VoIP mici
            elif packet_type == 'video':
                priority = video_priority
                size = random.randint(500, 1500)  # Pachete video mari
            else:
                priority = data_priority
                size = random.randint(64, 1500)  # Pachete data variate

            packets.append({
                'id': i,
                'type': packet_type,
                'priority': priority,
                'size': size,
                'arrival_time': i * 0.1
            })

        if mechanism == "fifo":
            self.simulate_fifo(packets)
        elif mechanism == "priority":
            self.simulate_priority_queuing(packets)
        elif mechanism == "wfq":
            self.simulate_wfq(packets)
        elif mechanism == "token_bucket":
            self.simulate_token_bucket(packets)
        elif mechanism == "leaky_bucket":
            self.simulate_leaky_bucket(packets)

        self.update_qos_visualization(packets, mechanism)

    def simulate_fifo(self, packets):
        self.qos_results.insert(tk.END, "FIFO (First In First Out) - Primul intrat, primul ieșit\n")
        self.qos_results.insert(tk.END, "Avantaje: Simplu de implementat, echitabil\n")
        self.qos_results.insert(tk.END, "Dezavantaje: Nu oferă diferențiere de servicii\n\n")

        total_delay = 0
        for i, packet in enumerate(packets):
            service_time = packet['size'] / 1000  # Simulare timp de servire
            delay = total_delay + service_time
            total_delay += service_time

            self.qos_results.insert(tk.END,
                                    f"Packet {packet['id']} ({packet['type']}): "
                                    f"delay={delay:.2f}ms, size={packet['size']}B\n")

    def simulate_priority_queuing(self, packets):
        self.qos_results.insert(tk.END, "Priority Queuing - Coadă cu priorități\n")
        self.qos_results.insert(tk.END, "Avantaje: Servește întâi pachetele cu prioritate înaltă\n")
        self.qos_results.insert(tk.END, "Dezavantaje: Posibilitatea înfometării pentru prioritate scăzută\n\n")

        # Sortează pachetele după prioritate (desc) și timp de sosire (asc)
        sorted_packets = sorted(packets, key=lambda x: (-x['priority'], x['arrival_time']))

        total_delay = 0
        for packet in sorted_packets:
            service_time = packet['size'] / 1000
            delay = total_delay + service_time
            total_delay += service_time

            self.qos_results.insert(tk.END,
                                    f"Packet {packet['id']} ({packet['type']}, priority={packet['priority']}): "
                                    f"delay={delay:.2f}ms\n")

    def simulate_wfq(self, packets):
        self.qos_results.insert(tk.END, "Weighted Fair Queuing - Coadă echitabilă ponderată\n")
        self.qos_results.insert(tk.END, "Avantaje: Garantează bandwidth pentru fiecare flux\n")
        self.qos_results.insert(tk.END, "Dezavantaje: Complexitate mai mare de implementare\n\n")

        # Calculează ponderi bazate pe prioritate
        weights = {'voice': 5, 'video': 3, 'data': 1}
        total_weight = sum(weights.values())

        # Grupează pachetele pe tipuri
        queues = {'voice': [], 'video': [], 'data': []}
        for packet in packets:
            queues[packet['type']].append(packet)

        # Simulare servire proporțională
        served_packets = []
        while any(queues.values()):
            for packet_type, queue in queues.items():
                if queue:
                    # Servește pachete proporțional cu ponderea
                    packets_to_serve = max(1, int(len(queue) * weights[packet_type] / total_weight))
                    for _ in range(min(packets_to_serve, len(queue))):
                        packet = queue.pop(0)
                        served_packets.append(packet)

        total_delay = 0
        for packet in served_packets:
            service_time = packet['size'] / 1000
            delay = total_delay + service_time
            total_delay += service_time

            self.qos_results.insert(tk.END,
                                    f"Packet {packet['id']} ({packet['type']}): delay={delay:.2f}ms\n")

    def simulate_token_bucket(self, packets):
        self.qos_results.insert(tk.END, "Token Bucket - Găleată cu jetoane\n")
        self.qos_results.insert(tk.END, "Avantaje: Permite burst-uri controlate\n")
        self.qos_results.insert(tk.END, "Dezavantaje: Pachete mari pot fi întârziate\n\n")

        bucket_size = 10  # Numărul maxim de jetoane
        token_rate = 2  # Jetoane generate pe secundă
        tokens = bucket_size

        for packet in packets:
            tokens_needed = packet['size'] // 100  # Jetoane necesare pentru packet

            # Generare jetoane
            tokens = min(bucket_size, tokens + token_rate * packet['arrival_time'])

            if tokens >= tokens_needed:
                tokens -= tokens_needed
                status = "Acceptat"
            else:
                status = "Respins/Întârziat"

            self.qos_results.insert(tk.END,
                                    f"Packet {packet['id']}: {status}, tokens={tokens:.1f}\n")

    def simulate_leaky_bucket(self, packets):
        self.qos_results.insert(tk.END, "Leaky Bucket - Găleată cu scurgere\n")
        self.qos_results.insert(tk.END, "Avantaje: Netezește traficul, elimină burst-urile\n")
        self.qos_results.insert(tk.END, "Dezavantaje: Introduce întârzieri pentru burst-uri\n\n")

        bucket_size = 1500  # Dimensiunea găleții în bytes
        leak_rate = 200  # Rata de scurgere în bytes/ms
        bucket_level = 0

        for packet in packets:
            # Scurgere
            bucket_level = max(0, bucket_level - leak_rate * packet['arrival_time'])

            if bucket_level + packet['size'] <= bucket_size:
                bucket_level += packet['size']
                status = "Acceptat"
            else:
                status = "Overflow - Respins"

            self.qos_results.insert(tk.END,
                                    f"Packet {packet['id']}: {status}, level={bucket_level}B\n")

    def update_qos_visualization(self, packets, mechanism):
        self.qos_ax1.clear()
        self.qos_ax2.clear()

        # Grafic 1: Distribuția tipurilor de pachete
        types = [p['type'] for p in packets]
        type_counts = {t: types.count(t) for t in set(types)}

        self.qos_ax1.pie(type_counts.values(), labels=type_counts.keys(), autopct='%1.1f%%')
        self.qos_ax1.set_title('Distribuția Tipurilor de Trafic')

        # Grafic 2: Latența pentru fiecare tip de trafic
        voice_delays = [i * 0.1 for i, p in enumerate(packets) if p['type'] == 'voice']
        video_delays = [i * 0.2 for i, p in enumerate(packets) if p['type'] == 'video']
        data_delays = [i * 0.05 for i, p in enumerate(packets) if p['type'] == 'data']

        if voice_delays:
            self.qos_ax2.plot(voice_delays, 'r-', label='Voice', marker='o')
        if video_delays:
            self.qos_ax2.plot(video_delays, 'b-', label='Video', marker='s')
        if data_delays:
            self.qos_ax2.plot(data_delays, 'g-', label='Data', marker='^')

        self.qos_ax2.set_xlabel('Packet Index')
        self.qos_ax2.set_ylabel('Delay (ms)')
        self.qos_ax2.set_title(f'Latența Pachetelor - {mechanism.upper()}')
        self.qos_ax2.legend()
        self.qos_ax2.grid(True)

        self.qos_fig.tight_layout()
        self.qos_canvas.draw()

    def analyze_latency(self):
        self.qos_results.insert(tk.END, "\n=== Analiză Latență ===\n")

        # Simulare latență în rețea
        nodes = list(self.simulator.nodes.keys())
        if len(nodes) < 2:
            self.qos_results.insert(tk.END, "Rețeaua are prea puține noduri pentru analiză\n")
            return

        # Calculează latența între noduri
        latency_matrix = defaultdict(dict)
        for i, node1 in enumerate(nodes):
            for node2 in nodes[i + 1:]:
                # Latența bazată pe distanța și utilizarea legăturilor
                path, distance = self.simulator.dijkstra(node1, node2)
                if path:
                    latency = distance * 2  # ms per hop
                    for i in range(len(path) - 1):
                        edge_id = f"{path[i]}-{path[i + 1]}" if f"{path[i]}-{path[i + 1]}" in self.simulator.edges else f"{path[i + 1]}-{path[i]}"
                        edge = self.simulator.edges[edge_id]
                        latency += edge.get('utilization', 0) * 0.1  # Additional latency based on utilization
                    latency_matrix[node1][node2] = latency
                    latency_matrix[node2][node1] = latency

        # Afișează matricea de latență
        self.qos_results.insert(tk.END, "Matricea de latență (ms):\n")
        header = "     " + "  ".join(f"{n:>5}" for n in nodes) + "\n"
        self.qos_results.insert(tk.END, header)

        for node1 in nodes:
            row = f"{node1:>3}: "
            for node2 in nodes:
                if node1 == node2:
                    row += "    0"
                else:
                    row += f"{latency_matrix[node1].get(node2, 'N/A'):>5}"
            self.qos_results.insert(tk.END, row + "\n")

        # Actualizează vizualizarea
        self.update_latency_visualization(latency_matrix)

    def update_latency_visualization(self, latency_matrix):
        self.qos_ax1.clear()
        self.qos_ax2.clear()

        # Grafic 1: Heatmap latență
        nodes = list(latency_matrix.keys())
        data = []
        for node1 in nodes:
            row = []
            for node2 in nodes:
                if node1 == node2:
                    row.append(0)
                else:
                    row.append(latency_matrix[node1].get(node2, 0))
            data.append(row)

        im = self.qos_ax1.imshow(data, cmap='viridis')
        self.qos_ax1.set_xticks(range(len(nodes)))
        self.qos_ax1.set_yticks(range(len(nodes)))
        self.qos_ax1.set_xticklabels(nodes)
        self.qos_ax1.set_yticklabels(nodes)
        self.qos_ax1.set_title('Matricea de Latență (ms)')
        plt.colorbar(im, ax=self.qos_ax1)

        # Grafic 2: Distribuția latenței
        all_latencies = []
        for node1 in latency_matrix:
            for node2 in latency_matrix[node1]:
                all_latencies.append(latency_matrix[node1][node2])

        if all_latencies:
            self.qos_ax2.hist(all_latencies, bins=10, color='skyblue', edgecolor='black')
            self.qos_ax2.set_xlabel('Latență (ms)')
            self.qos_ax2.set_ylabel('Frecvență')
            self.qos_ax2.set_title('Distribuția Latenței în Rețea')

        self.qos_fig.tight_layout()
        self.qos_canvas.draw()

    def test_bandwidth(self):
        self.qos_results.insert(tk.END, "\n=== Test Bandwidth ===\n")

        # Simulare test de bandwidth între noduri
        nodes = list(self.simulator.nodes.keys())
        if len(nodes) < 2:
            self.qos_results.insert(tk.END, "Rețeaua are prea puține noduri pentru test\n")
            return

        # Alege două noduri aleatorii
        source, dest = random.sample(nodes, 2)
        path, _ = self.simulator.dijkstra(source, dest)

        if not path:
            self.qos_results.insert(tk.END, f"Nu există cale între {source} și {dest}\n")
            return

        # Calculează bandwidth-ul minim de-a lungul căii
        bandwidth = float('inf')
        for i in range(len(path) - 1):
            edge_id = f"{path[i]}-{path[i + 1]}" if f"{path[i]}-{path[i + 1]}" in self.simulator.edges else f"{path[i + 1]}-{path[i]}"
            edge = self.simulator.edges[edge_id]
            bandwidth = min(bandwidth, edge['bandwidth'] * (1 - edge.get('utilization', 0) / 100))

        self.qos_results.insert(tk.END, f"Bandwidth între {source} și {dest}: {bandwidth:.2f} Mbps\n")
        self.qos_results.insert(tk.END, f"Calea: {' -> '.join(path)}\n")

        # Actualizează vizualizarea
        self.update_bandwidth_visualization(source, dest, bandwidth)

    def update_bandwidth_visualization(self, source, dest, bandwidth):
        self.qos_ax1.clear()
        self.qos_ax2.clear()

        # Grafic 1: Bandwidth pe cale
        path, _ = self.simulator.dijkstra(source, dest)
        if not path:
            return

        edge_bandwidths = []
        edge_labels = []
        for i in range(len(path) - 1):
            edge_id = f"{path[i]}-{path[i + 1]}" if f"{path[i]}-{path[i + 1]}" in self.simulator.edges else f"{path[i + 1]}-{path[i]}"
            edge = self.simulator.edges[edge_id]
            edge_bandwidths.append(edge['bandwidth'] * (1 - edge.get('utilization', 0) / 100))
            edge_labels.append(f"{path[i]}-{path[i + 1]}")

        self.qos_ax1.bar(edge_labels, edge_bandwidths, color='lightgreen')
        self.qos_ax1.axhline(y=bandwidth, color='r', linestyle='--', label='Bottleneck')
        self.qos_ax1.set_ylabel('Bandwidth (Mbps)')
        self.qos_ax1.set_title('Bandwidth pe Legături')
        self.qos_ax1.legend()
        self.qos_ax1.tick_params(axis='x', rotation=45)

        # Grafic 2: Utilizare bandwidth
        utilizations = [edge.get('utilization', 0) for edge in self.simulator.edges.values()]
        if utilizations:
            self.qos_ax2.hist(utilizations, bins=10, color='orange', edgecolor='black')
            self.qos_ax2.set_xlabel('Utilizare Bandwidth (%)')
            self.qos_ax2.set_ylabel('Număr Legături')
            self.qos_ax2.set_title('Distribuția Utilizării Bandwidth')

        self.qos_fig.tight_layout()
        self.qos_canvas.draw()

    def simulate_attack(self):
        attack_type = random.choice(["DDoS", "Man-in-the-Middle", "Port Scanning", "ARP Spoofing", "DNS Spoofing"])
        target = random.choice(list(self.simulator.nodes.keys())) if self.simulator.nodes else "N/A"

        self.security_results.delete(1.0, tk.END)
        self.security_results.insert(tk.END, f"=== Simulare Atac de Tip {attack_type} ===\n\n")

        if attack_type == "DDoS":
            self.security_results.insert(tk.END, f"Atac DDoS asupra nodului {target}\n")
            self.security_results.insert(tk.END, "• Nodul este inundat cu cereri false\n")
            self.security_results.insert(tk.END, "• Consumă resursele nodului (CPU, memorie, bandwidth)\n")
            self.security_results.insert(tk.END, "• Poate cauza indisponibilitate servicii\n")

            # Simulare efecte
            if target in self.simulator.nodes:
                self.simulator.nodes[target]['load'] = min(100, self.simulator.nodes[target].get('load', 0) + 80)
                for edge_id, edge in self.simulator.edges.items():
                    if target in edge['nodes']:
                        edge['utilization'] = min(100, edge.get('utilization', 0) + 70)

        elif attack_type == "Man-in-the-Middle":
            node1, node2 = random.sample(list(self.simulator.nodes.keys()), 2) if len(self.simulator.nodes) >= 2 else (
                "A", "B")
            self.security_results.insert(tk.END, f"Atac Man-in-the-Middle între {node1} și {node2}\n")
            self.security_results.insert(tk.END, "• Atacatorul interceptează comunicarea\n")
            self.security_results.insert(tk.END, "• Poate citi/modifica datele transmise\n")
            self.security_results.insert(tk.END, "• Poate falsifica identitatea nodurilor\n")

        elif attack_type == "Port Scanning":
            self.security_results.insert(tk.END, f"Scanare porturi pe nodul {target}\n")
            self.security_results.insert(tk.END, "• Atacatorul caută porturi deschise\n")
            self.security_results.insert(tk.END, "• Identifică vulnerabilități în servicii\n")
            self.security_results.insert(tk.END, "• Poate duce la acces neautorizat\n")

        elif attack_type == "ARP Spoofing":
            self.security_results.insert(tk.END, "Atac ARP Spoofing în rețea\n")
            self.security_results.insert(tk.END, "• Atacatorul falsifică adrese MAC\n")
            self.security_results.insert(tk.END, "• Redirectează traficul către el\n")
            self.security_results.insert(tk.END, "• Poate intercepta sau modifica date\n")

        elif attack_type == "DNS Spoofing":
            self.security_results.insert(tk.END, "Atac DNS Spoofing\n")
            self.security_results.insert(tk.END, "• Atacatorul falsifică răspunsuri DNS\n")
            self.security_results.insert(tk.END, "• Redirectează utilizatorii către site-uri false\n")
            self.security_results.insert(tk.END, "• Poate fi folosit pentru phishing\n")

        self.security_results.insert(tk.END, "\nMăsuri de protecție recomandate:\n")
        if attack_type == "DDoS":
            self.security_results.insert(tk.END, "• Rate limiting\n• Filtrare trafic\n• Sisteme de detectare DDoS\n")
        elif attack_type in ["Man-in-the-Middle", "ARP Spoofing"]:
            self.security_results.insert(tk.END,
                                         "• Autentificare puternică\n• Criptare trafic\n• Utilizare ARP secure\n")
        elif attack_type == "Port Scanning":
            self.security_results.insert(tk.END,
                                         "• Firewall\n• Ascunderea porturilor\n• Sistem de detectare intruziuni\n")
        elif attack_type == "DNS Spoofing":
            self.security_results.insert(tk.END, "• DNSSEC\n• Validare certificare\n• Cache-uri DNS securizate\n")

        self.update_security_metrics()
        self.update_routing_visualization()

    def test_firewall(self):
        self.security_results.delete(1.0, tk.END)
        self.security_results.insert(tk.END, "=== Testare Firewall ===\n\n")

        # Simulare reguli firewall
        firewall_rules = [
            {"src": "any", "dst": "A", "port": 80, "action": "allow"},
            {"src": "any", "dst": "A", "port": 443, "action": "allow"},
            {"src": "any", "dst": "A", "port": 22, "action": "deny"},
            {"src": "B", "dst": "C", "port": "any", "action": "allow"},
            {"src": "D", "dst": "any", "port": "any", "action": "deny"}
        ]

        self.security_results.insert(tk.END, "Reguli Firewall Configurate:\n")
        for i, rule in enumerate(firewall_rules, 1):
            self.security_results.insert(tk.END,
                                         f"{i}. Sursa: {rule['src']}, Destinație: {rule['dst']}, "
                                         f"Port: {rule['port']}, Acțiune: {rule['action']}\n")

        # Testează câteva scenarii
        test_cases = [
            {"src": "E", "dst": "A", "port": 80, "expected": "allow"},
            {"src": "F", "dst": "A", "port": 22, "expected": "deny"},
            {"src": "B", "dst": "C", "port": 3389, "expected": "allow"},
            {"src": "D", "dst": "F", "port": 443, "expected": "deny"}
        ]

        self.security_results.insert(tk.END, "\nRezultate Teste Firewall:\n")
        for test in test_cases:
            action = self.check_firewall_rules(test['src'], test['dst'], test['port'], firewall_rules)
            result = "PASS" if action == test['expected'] else "FAIL"
            self.security_results.insert(tk.END,
                                         f"Test {test['src']} -> {test['dst']}:{test['port']}: "
                                         f"Actual={action}, Expected={test['expected']} [{result}]\n")

    def check_firewall_rules(self, src, dst, port, rules):
        for rule in rules:
            # Verifică dacă regula se aplică
            src_match = (rule['src'] == "any") or (rule['src'] == src)
            dst_match = (rule['dst'] == "any") or (rule['dst'] == dst)
            port_match = (rule['port'] == "any") or (rule['port'] == port)

            if src_match and dst_match and port_match:
                return rule['action']
        return "deny"  # Default deny

    def vulnerability_scan(self):
        self.security_results.delete(1.0, tk.END)
        self.security_results.insert(tk.END, "=== Scanare Vulnerabilități ===\n\n")

        # Simulare scanare vulnerabilități
        vulnerabilities = [
            {"node": "A", "type": "Serviciu SSH", "severity": "High",
             "description": "SSH versiune veche cu vulnerabilități cunoscute"},
            {"node": "B", "type": "Firewall", "severity": "Medium",
             "description": "Reguli firewall lipsă pentru porturi sensibile"},
            {"node": "C", "type": "Aplicație Web", "severity": "Critical",
             "description": "Vulnerabilitate XSS în aplicația web"},
            {"node": "D", "type": "Sistem Operare", "severity": "High",
             "description": "Sistemul operare nu are patch-uri de securitate"},
            {"node": "E", "type": "Configurație", "severity": "Low", "description": "Parole default în echipament"}
        ]

        self.security_results.insert(tk.END, "Vulnerabilități Identificate:\n")
        for vuln in vulnerabilities:
            self.security_results.insert(tk.END,
                                         f"Nod: {vuln['node']} - {vuln['type']} ({vuln['severity']})\n"
                                         f"Descriere: {vuln['description']}\n\n")

        # Rezumat severitate
        critical = sum(1 for v in vulnerabilities if v['severity'] == "Critical")
        high = sum(1 for v in vulnerabilities if v['severity'] == "High")
        medium = sum(1 for v in vulnerabilities if v['severity'] == "Medium")
        low = sum(1 for v in vulnerabilities if v['severity'] == "Low")

        self.security_results.insert(tk.END,
                                     f"\nRezumat Vulnerabilități:\n"
                                     f"Critical: {critical}\nHigh: {high}\nMedium: {medium}\nLow: {low}\n")

        self.update_security_metrics()

    def demonstrate_encryption(self):
        method = self.encryption_method.get()
        self.security_results.delete(1.0, tk.END)
        self.security_results.insert(tk.END, f"=== Demonstrație Criptare {method.upper()} ===\n\n")

        original_message = "Acesta este un mesaj secret pentru demonstratie"

        if method == "aes":
            self.security_results.insert(tk.END, "AES (Advanced Encryption Standard):\n")
            self.security_results.insert(tk.END, "• Criptare simetrică pe blocuri\n")
            self.security_results.insert(tk.END, "• Dimensiuni cheie: 128, 192 sau 256 biți\n")
            self.security_results.insert(tk.END, "• Rapid și securizat\n\n")

            # Simulare criptare (simplificată)
            encrypted = f"AES-256({original_message}) = 4f8a...d3c2"
            decrypted = original_message

        elif method == "rsa":
            self.security_results.insert(tk.END, "RSA (Public Key Cryptography):\n")
            self.security_results.insert(tk.END, "• Criptare asimetrică\n")
            self.security_results.insert(tk.END, "• Folosește cheie publică și privată\n")
            self.security_results.insert(tk.END, "• Mai lent decât AES\n\n")

            # Simulare criptare (simplificată)
            encrypted = f"RSA-Public({original_message}) = 9b2e...7a1f"
            decrypted = f"RSA-Private({encrypted}) = {original_message}"

        elif method == "des":
            self.security_results.insert(tk.END, "DES (Data Encryption Standard):\n")
            self.security_results.insert(tk.END, "• Criptare simetrică pe blocuri (56 biți)\n")
            self.security_results.insert(tk.END, "• Considerat nesigur pentru date sensibile\n")
            self.security_results.insert(tk.END, "• Înlocuit de AES\n\n")

            # Simulare criptare (simplificată)
            encrypted = f"DES({original_message}) = 3c7a...e9d1"
            decrypted = original_message

        self.security_results.insert(tk.END, f"Mesaj original: {original_message}\n")
        self.security_results.insert(tk.END, f"Mesaj criptat: {encrypted}\n")
        self.security_results.insert(tk.END, f"Mesaj decriptat: {decrypted}\n")

        self.update_security_metrics()

    def update_security_metrics(self):
        # Simulare metrici de securitate
        security_score = random.randint(60, 95)  # Scor securitate procentual
        attack_resistance = random.randint(70, 100)
        encryption_coverage = random.randint(50, 100)

        self.security_metrics.delete(1.0, tk.END)
        self.security_metrics.insert(tk.END,
                                     f"Scor Securitate: {security_score}%\n"
                                     f"Rezistență la Atacuri: {attack_resistance}%\n"
                                     f"Acoperire Criptare: {encryption_coverage}%\n"
                                     f"Vulnerabilități Critice: {random.randint(0, 3)}\n"
                                     f"Ultimul Scan: {time.strftime('%d/%m/%Y %H:%M')}\n")

    def packet_capture(self):
        self.protocol_details.delete(1.0, tk.END)
        self.protocol_details.insert(tk.END, "=== Packet Capture ===\n\n")

        # Simulare captură pachete
        packets = [
            {"src": "192.168.1.1", "dst": "192.168.1.2", "protocol": "TCP", "port": 80, "size": 1500},
            {"src": "192.168.1.2", "dst": "192.168.1.1", "protocol": "TCP", "port": 80, "size": 540},
            {"src": "192.168.1.3", "dst": "8.8.8.8", "protocol": "UDP", "port": 53, "size": 78},
            {"src": "8.8.8.8", "dst": "192.168.1.3", "protocol": "UDP", "port": 53, "size": 142},
            {"src": "192.168.1.4", "dst": "192.168.1.1", "protocol": "ICMP", "port": None, "size": 64}
        ]

        for i, pkt in enumerate(packets, 1):
            self.protocol_details.insert(tk.END,
                                         f"{i}. {pkt['src']}:{pkt['port'] or ''} -> {pkt['dst']}:{pkt['port'] or ''} "
                                         f"{pkt['protocol']} {pkt['size']}B\n")

        self.protocol_details.insert(tk.END, "\nAnaliză Protocol:\n")
        self.protocol_details.insert(tk.END, "• 2 conexiuni TCP (HTTP)\n")
        self.protocol_details.insert(tk.END, "• 2 cereri DNS\n")
        self.protocol_details.insert(tk.END, "• 1 ping (ICMP)\n")

        self.update_protocol_visualization(packets)

    def protocol_decode(self):
        self.protocol_details.delete(1.0, tk.END)
        self.protocol_details.insert(tk.END, "=== Protocol Decoder ===\n\n")

        # Simulare decodare pachet
        protocol = random.choice(["TCP", "UDP", "ICMP", "HTTP", "DNS"])

        if protocol == "TCP":
            self.protocol_details.insert(tk.END, "TCP Header Analysis:\n")
            self.protocol_details.insert(tk.END, "Source Port: 49234\n")
            self.protocol_details.insert(tk.END, "Destination Port: 80 (HTTP)\n")
            self.protocol_details.insert(tk.END, "Sequence Number: 123456789\n")
            self.protocol_details.insert(tk.END, "ACK Number: 987654321\n")
            self.protocol_details.insert(tk.END, "Flags: SYN-ACK\n")
            self.protocol_details.insert(tk.END, "Window Size: 64240\n")

        elif protocol == "UDP":
            self.protocol_details.insert(tk.END, "UDP Header Analysis:\n")
            self.protocol_details.insert(tk.END, "Source Port: 53124\n")
            self.protocol_details.insert(tk.END, "Destination Port: 53 (DNS)\n")
            self.protocol_details.insert(tk.END, "Length: 64 bytes\n")
            self.protocol_details.insert(tk.END, "Checksum: 0x2a3b\n")

        elif protocol == "ICMP":
            self.protocol_details.insert(tk.END, "ICMP Packet Analysis:\n")
            self.protocol_details.insert(tk.END, "Type: 8 (Echo Request)\n")
            self.protocol_details.insert(tk.END, "Code: 0\n")
            self.protocol_details.insert(tk.END, "Checksum: 0x4c7d\n")
            self.protocol_details.insert(tk.END, "Identifier: 1234\n")
            self.protocol_details.insert(tk.END, "Sequence Number: 1\n")

        elif protocol == "HTTP":
            self.protocol_details.insert(tk.END, "HTTP Request:\n")
            self.protocol_details.insert(tk.END, "GET /index.html HTTP/1.1\n")
            self.protocol_details.insert(tk.END, "Host: www.example.com\n")
            self.protocol_details.insert(tk.END, "User-Agent: Mozilla/5.0\n")
            self.protocol_details.insert(tk.END, "Accept: text/html\n")

        elif protocol == "DNS":
            self.protocol_details.insert(tk.END, "DNS Query:\n")
            self.protocol_details.insert(tk.END, "Transaction ID: 0x2f4a\n")
            self.protocol_details.insert(tk.END, "Flags: Standard query\n")
            self.protocol_details.insert(tk.END, "Questions: 1\n")
            self.protocol_details.insert(tk.END, "Query: www.example.com A IN\n")

        self.update_protocol_stack(protocol)

    def flow_analysis(self):
        self.protocol_details.delete(1.0, tk.END)
        self.protocol_details.insert(tk.END, "=== Flow Analysis ===\n\n")

        # Simulare analiză flux
        flows = [
            {"src": "192.168.1.1", "dst": "10.0.0.2", "protocol": "TCP", "bytes": 1500000, "packets": 1200},
            {"src": "10.0.0.2", "dst": "192.168.1.1", "protocol": "TCP", "bytes": 500000, "packets": 800},
            {"src": "192.168.1.3", "dst": "8.8.8.8", "protocol": "UDP", "bytes": 2000, "packets": 10},
            {"src": "192.168.1.4", "dst": "192.168.1.5", "protocol": "TCP", "bytes": 5000000, "packets": 4000}
        ]

        self.protocol_details.insert(tk.END, "Top Flows by Bytes:\n")
        for flow in sorted(flows, key=lambda x: -x['bytes'])[:3]:
            self.protocol_details.insert(tk.END,
                                         f"{flow['src']} -> {flow['dst']} {flow['protocol']}: "
                                         f"{flow['bytes'] / 1000:.1f}KB, {flow['packets']} pachete\n")

        self.protocol_details.insert(tk.END, "\nStatistici Protocol:\n")
        protocols = {f['protocol'] for f in flows}
        for proto in protocols:
            total_bytes = sum(f['bytes'] for f in flows if f['protocol'] == proto)
            total_packets = sum(f['packets'] for f in flows if f['protocol'] == proto)
            self.protocol_details.insert(tk.END,
                                         f"{proto}: {total_bytes / 1000000:.2f}MB, {total_packets} pachete\n")

        self.update_flow_visualization(flows)

    def update_protocol_visualization(self, packets):
        self.protocol_ax.clear()

        # Grupează pachete pe protocol
        protocol_counts = {}
        for pkt in packets:
            proto = pkt['protocol']
            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

        if protocol_counts:
            self.protocol_ax.bar(protocol_counts.keys(), protocol_counts.values(), color='skyblue')
            self.protocol_ax.set_title('Distribuție Pachete pe Protocol')
            self.protocol_ax.set_xlabel('Protocol')
            self.protocol_ax.set_ylabel('Număr Pachete')

        self.protocol_canvas.draw()

    def update_protocol_stack(self, protocol):
        self.protocol_ax.clear()

        # Desenează stiva de protocol
        layers = {
            "Application": ["HTTP", "DNS", "DHCP"],
            "Transport": ["TCP", "UDP"],
            "Network": ["IP", "ICMP"],
            "Data Link": ["Ethernet", "WiFi"],
            "Physical": ["Fiber", "Copper"]
        }

        current_layer = None
        for layer, protocols in layers.items():
            if protocol in protocols:
                current_layer = layer
                break

        if current_layer:
            y_pos = len(layers)
            for i, (layer, protocols) in enumerate(layers.items()):
                y = y_pos - i
                self.protocol_ax.barh(y, 10, color='lightblue', alpha=0.7)
                self.protocol_ax.text(5, y, layer, ha='center', va='center')

                if layer == current_layer:
                    self.protocol_ax.barh(y, 8, color='red', alpha=0.5)
                    self.protocol_ax.text(4, y, protocol, ha='center', va='center')

        self.protocol_ax.set_title('Stiva de Protocol')
        self.protocol_ax.set_xlim(0, 10)
        self.protocol_ax.set_ylim(0, len(layers) + 1)
        self.protocol_ax.axis('off')
        self.protocol_canvas.draw()

    def update_flow_visualization(self, flows):
        self.protocol_ax.clear()

        # Grafic fluxuri pe protocol
        protocol_bytes = {}
        for flow in flows:
            proto = flow['protocol']
            protocol_bytes[proto] = protocol_bytes.get(proto, 0) + flow['bytes']

        if protocol_bytes:
            total_bytes = sum(protocol_bytes.values())
            sizes = [b / total_bytes for b in protocol_bytes.values()]
            labels = [f"{k} ({v / 1000000:.1f}MB)" for k, v in protocol_bytes.items()]

            self.protocol_ax.pie(sizes, labels=labels, autopct='%1.1f%%')
            self.protocol_ax.set_title('Distribuție Fluxuri pe Protocol')

        self.protocol_canvas.draw()

    def start_monitoring(self):
        if not hasattr(self, 'monitoring_active') or not self.monitoring_active:
            self.monitoring_active = True
            self.monitor_thread = threading.Thread(target=self.monitoring_worker)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
            self.perf_summary.insert(tk.END, "Monitorizare pornită...\n")
        else:
            self.monitoring_active = False
            self.perf_summary.insert(tk.END, "Monitorizare oprită\n")

    def monitoring_worker(self):
        metrics = ['throughput', 'latency', 'cpu', 'memory']
        time_points = []
        data = {m: [] for m in metrics}

        while self.monitoring_active and len(time_points) < 20:
            time_points.append(time.strftime("%H:%M:%S"))

            # Generează date de monitorizare aleatorii
            data['throughput'].append(random.uniform(50, 200))
            data['latency'].append(random.uniform(1, 50))
            data['cpu'].append(random.uniform(10, 90))
            data['memory'].append(random.uniform(20, 80))

            # Actualizează graficele
            self.root.after(0, self.update_performance_visualization, time_points, data)
            time.sleep(1)

    def update_performance_visualization(self, time_points, data):
        self.perf_ax1.clear()
        self.perf_ax2.clear()
        self.perf_ax3.clear()
        self.perf_ax4.clear()

        # Throughput
        self.perf_ax1.plot(time_points, data['throughput'], 'b-')
        self.perf_ax1.set_title('Throughput (Mbps)')
        self.perf_ax1.grid(True)

        # Latency
        self.perf_ax2.plot(time_points, data['latency'], 'r-')
        self.perf_ax2.set_title('Latency (ms)')
        self.perf_ax2.grid(True)

        # CPU Usage
        self.perf_ax3.plot(time_points, data['cpu'], 'g-')
        self.perf_ax3.set_title('CPU Usage (%)')
        self.perf_ax3.grid(True)

        # Memory Usage
        self.perf_ax4.plot(time_points, data['memory'], 'm-')
        self.perf_ax4.set_title('Memory Usage (%)')
        self.perf_ax4.grid(True)

        self.perf_fig.tight_layout()
        self.perf_canvas.draw()

        # Actualizează rezumat
        self.perf_summary.delete(1.0, tk.END)
        self.perf_summary.insert(tk.END,
                                 f"Ultimele metrici:\n"
                                 f"Throughput: {data['throughput'][-1]:.1f} Mbps\n"
                                 f"Latency: {data['latency'][-1]:.1f} ms\n"
                                 f"CPU: {data['cpu'][-1]:.1f}%\n"
                                 f"Memory: {data['memory'][-1]:.1f}%\n")

    def bandwidth_test(self):
        self.perf_summary.delete(1.0, tk.END)

        # Simulare test de bandwidth
        download = random.uniform(50, 200)
        upload = random.uniform(10, 50)
        latency = random.uniform(1, 20)

        self.perf_summary.insert(tk.END,
                                 f"Rezultate Test Bandwidth:\n"
                                 f"Download: {download:.1f} Mbps\n"
                                 f"Upload: {upload:.1f} Mbps\n"
                                 f"Latency: {latency:.1f} ms\n")

        # Actualizează graficul
        self.perf_ax1.clear()
        self.perf_ax1.bar(['Download', 'Upload'], [download, upload], color=['blue', 'green'])
        self.perf_ax1.set_title('Bandwidth Test')
        self.perf_ax1.set_ylabel('Mbps')
        self.perf_canvas.draw()

    def latency_test(self):
        self.perf_summary.delete(1.0, tk.END)

        # Simulare test de latență
        nodes = list(self.simulator.nodes.keys())
        if len(nodes) < 2:
            self.perf_summary.insert(tk.END, "Rețeau prea mic pentru test de latență\n")
            return
        source, dest = random.sample(nodes, 2)
        path, distance = self.simulator.dijkstra(source, dest)
        if not path:
            self.perf_summary.insert(tk.END, f"Nu există cale între {source} și {dest}\n")
            return
        latency = distance * 2  # ms per hop
        self.perf_summary.insert(tk.END,
                                 f"Rezultate Test Latență:\n"
                                 f"De la {source} la {dest}: {latency:.1f} ms\n")
        # Actualizează graficul
        self.perf_ax2.clear()
        self.perf_ax2.bar(['Latency'], [latency], color='red')
        self.perf_ax2.set_title('Latency Test')
        self.perf_ax2.set_ylabel('ms')
        self.perf_canvas.draw()
        self.perf_fig.tight_layout()
        self.perf_canvas.draw()
        self.perf_summary.insert(tk.END, "Test de latență finalizat\n")
        self.perf_summary.insert(tk.END, "Rezultate:\n")
        self.perf_summary.insert(tk.END, f"De la {source} la {dest}: {latency:.1f} ms\n")


if __name__ == "__main__":
    root = tk.Tk()
    app = AdvancedNetworksApp(root)
    root.mainloop()
