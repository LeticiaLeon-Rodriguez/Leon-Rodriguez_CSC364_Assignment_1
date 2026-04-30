import socket
import sys
import traceback
from threading import Thread, Lock


# Helper Functions

def create_socket(host, port):
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        soc.connect((host, port))
    except:
        print("Connection Error to", port)
        sys.exit()
    return soc


def read_csv(path):
    table_file = open(path, "r")
    table = table_file.readlines()
    table_list = []
    for line in table:
        row = line.split(",")
        row = [item.strip() for item in row]
        table_list.append(row)
    table_file.close()
    return table_list


def find_default_gateway(table):
    for row in table:
        if row[0] == "0.0.0.0":
            return row[3]


def generate_forwarding_table_with_range(table):
    new_table = []
    for row in table:
        if row[0] != "0.0.0.0":
            network_dst_string = row[0]
            netmask_string = row[1]
            network_dst_bin = ip_to_bin(network_dst_string)
            netmask_bin = ip_to_bin(netmask_string)
            ip_range = find_ip_range(int(network_dst_bin, 2), int(netmask_bin, 2))
            new_row = [ip_range[0], ip_range[1], row[3]]
            new_table.append(new_row)
    return new_table


def ip_to_bin(ip):
    ip_octets = ip.split(".")
    ip_bin_string = ""
    for octet in ip_octets:
        int_octet = int(octet)
        bin_octet = bin(int_octet)
        bin_octet_string = bin_octet[2:]
        while len(bin_octet_string) < 8:
            bin_octet_string = "0" + bin_octet_string
        ip_bin_string = ip_bin_string + bin_octet_string
    ip_int = int(ip_bin_string, 2)
    return bin(ip_int)


def find_ip_range(network_dst, netmask):
    bitwise_and = network_dst & netmask
    compliment = bit_not(netmask)
    min_ip = bitwise_and
    max_ip = min_ip + compliment
    return [min_ip, max_ip]


def bit_not(n, numbits=32):
    return (1 << numbits) - 1 - n


def receive_packet(connection, max_buffer_size):
    received_packet = connection.recv(max_buffer_size)
    packet_size = sys.getsizeof(received_packet)
    if packet_size > max_buffer_size:
        print("The packet size is greater than expected", packet_size)

    decoded_packet = received_packet.decode("utf-8").strip()

    if decoded_packet != "":
        print("received packet", decoded_packet)
        write_to_file("output/received_by_router_4.txt", decoded_packet)

    packet = decoded_packet.split(",") if decoded_packet != "" else []
    return packet


def write_to_file(path, packet_to_write, send_to_router=None):
    out_file = open(path, "a")
    if send_to_router is None:
        out_file.write(packet_to_write + "\n")
    else:
        out_file.write(packet_to_write + " " + "to Router " + send_to_router + "\n")
    out_file.close()


# Shared inbound connection registry for interfaces b and c
inbound_connections = {}
inbound_lock = Lock()


def register_inbound_router(connection):
    """
    Expects the peer to send one label immediately after connect:
    ROUTER1 or ROUTER2
    """
    label = connection.recv(32).decode("utf-8").strip()
    with inbound_lock:
        if label == "ROUTER1":
            inbound_connections["b"] = connection
            print("Registered interface b for Router 1")
        elif label == "ROUTER2":
            inbound_connections["c"] = connection
            print("Registered interface c for Router 2")
        else:
            print("Unknown inbound label:", label)
    return label


def start_server():
    host = "127.0.0.1"
    port = 8004
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print("Socket created")

    try:
        soc.bind((host, port))
    except:
        print("Bind failed. Error : " + str(sys.exc_info()))
        sys.exit()

    soc.listen()
    print("Socket now listening")

    forwarding_table = read_csv("router_4_table.csv")
    default_gateway_port = find_default_gateway(forwarding_table)
    forwarding_table_with_range = generate_forwarding_table_with_range(forwarding_table)

    while True:
        connection, address = soc.accept()
        ip = address[0]
        remote_port = str(address[1])
        print("Connected with " + ip + ":" + remote_port)

        try:
            register_inbound_router(connection)

            Thread(
                target=processing_thread,
                args=(connection, ip, remote_port, forwarding_table_with_range, default_gateway_port)
            ).start()
        except:
            print("Thread did not start.")
            traceback.print_exc()


def processing_thread(connection, ip, port, forwarding_table_with_range, default_gateway_port, max_buffer_size=5120):
    router5_socket = create_socket("127.0.0.1", 8005)
    router6_socket = create_socket("127.0.0.1", 8006)

    while True:
        packet = receive_packet(connection, max_buffer_size)

        if not packet:
            break

        sourceIP = packet[0]
        destinationIP = packet[1]
        payload = packet[2]
        ttl = packet[3]

        new_ttl = int(ttl) - 1
        new_packet = sourceIP + "," + destinationIP + "," + payload + "," + str(new_ttl)

        destinationIP_bin = ip_to_bin(destinationIP)
        destinationIP_int = int(destinationIP_bin, 2)

        send_port = None
        for row in forwarding_table_with_range:
            min_ip = row[0]
            max_ip = row[1]
            interface = row[2]
            if min_ip <= destinationIP_int <= max_ip:
                send_port = interface
                break

        if send_port is None:
            send_port = default_gateway_port

        if send_port == "8005" and new_ttl > 0:
            print("sending packet", new_packet, "to Router 5")
            write_to_file("output/sent_by_router_4.txt", new_packet, "5")
            router5_socket.send(new_packet.encode())

        elif send_port == "8006" and new_ttl > 0:
            print("sending packet", new_packet, "to Router 6")
            write_to_file("output/sent_by_router_4.txt", new_packet, "6")
            router6_socket.send(new_packet.encode())

        elif send_port == "b" and new_ttl > 0:
            with inbound_lock:
                back_conn = inbound_connections.get("b")
            if back_conn is not None:
                print("sending packet", new_packet, "to Router 1")
                write_to_file("output/sent_by_router_4.txt", new_packet, "1")
                back_conn.send(new_packet.encode())
            else:
                print("DISCARD: missing interface b for", new_packet)
                write_to_file("output/discarded_by_router_4.txt", new_packet)

        elif send_port == "c" and new_ttl > 0:
            with inbound_lock:
                back_conn = inbound_connections.get("c")
            if back_conn is not None:
                print("sending packet", new_packet, "to Router 2")
                write_to_file("output/sent_by_router_4.txt", new_packet, "2")
                back_conn.send(new_packet.encode())
            else:
                print("DISCARD: missing interface c for", new_packet)
                write_to_file("output/discarded_by_router_4.txt", new_packet)

        elif send_port == "127.0.0.1":
            print("OUT:", payload)
            write_to_file("output/out_router_4.txt", payload)

        else:
            print("DISCARD:", new_packet)
            write_to_file("output/discarded_by_router_4.txt", new_packet)


# Main Program
start_server()