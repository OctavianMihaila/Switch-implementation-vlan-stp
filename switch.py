#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

VLAN_TAG_SIZE = 4
STANDARD_LINK_COST = 10
LLC_LENGTH = 38

class BPDUConfig:
    def __init__(self, flags, root_bridge_id, root_path_cost, bridge_id, port_id,
                 message_age, max_age, hello_time, forward_delay):
        self.flags = flags
        self.root_bridge_id = root_bridge_id
        self.root_path_cost = root_path_cost
        self.bridge_id = bridge_id
        self.port_id = port_id
        self.message_age = message_age
        self.max_age = max_age
        self.hello_time = hello_time
        self.forward_delay = forward_delay

    @classmethod
    def from_bytes(cls, data):
        return cls(
            flags=data[0:1],
            root_bridge_id=data[1:2] + b'\x00\x00\x00\x00\x00\x00\x00',
            root_path_cost=data[2:6],
            bridge_id=data[6:7] + b'\x00\x00\x00\x00\x00\x00\x00',
            port_id=data[7:9],
            message_age=data[9:11],
            max_age=data[11:13],
            hello_time=data[13:15],
            forward_delay=data[15:17]
        )

    def serialize(self):
        return (
            bytes(self.flags) +
            bytes(self.root_bridge_id) +
            bytes(self.root_path_cost) +
            bytes(self.bridge_id) +
            self.port_id +
            bytes(self.message_age) +
            bytes(self.max_age) +
            bytes(self.hello_time) +
            bytes(self.forward_delay)
        )

    @staticmethod
    def update_sender_bridge_id(data, own_bridge_id):
        return data[0:7] + bytes(own_bridge_id) + data[8:]

    @staticmethod
    def update_root_path_cost(data, link_cost):
        return data[0:5] + bytes(link_cost) + data[9:]
    
def check_bpdu_packet(data):
    if data[14] == 0x42 and data[15] == 0x42 and data[16] == 0x03:
        return True
    return False    

def get_root_bridge_id(data):
    root_bridge_id = struct.unpack('!B', data[22:23])
    return root_bridge_id[0]

def get_sender_bridge_id(data):
    sender_bridge_id = struct.unpack('!B', data[34:35])
    return sender_bridge_id[0]

def get_root_path_cost(data):
    root_path_cost = struct.unpack('!I', data[30:34])
    return root_path_cost[0]

def get_port_id(data):
    port_id = struct.unpack('!H', data[43:45])
    return port_id[0]

def send_bpdu_every_sec(interfaces, interface_vlan_mapping, own_bridge_id, root_bridge_id):
    while True:
        # If a bpdu is received from a switch with a lower bridge id, then we stop sending bpdu.
        if root_bridge_id != own_bridge_id:
            break

        for interface in interfaces:
            if interface_vlan_mapping[interface] == 'T':
                # Create ethernet header.
                dest_mac = struct.pack('!6s', b'\x01\x80\xC2\x00\x00\x00')
                src_mac = get_switch_mac()
                llc_length = struct.pack('!H', LLC_LENGTH)
                llc_header = struct.pack('!BBB', 0x42, 0x42, 0x03)

                # BPDU header: protocol ID, protocol version ID, BPDU type.
                bpdu_header = struct.pack('!HBB', 0x0000, 0x00, 0x00)
                port_id = struct.pack('!H', interface)
                
                # BPDU configuration.
                bpdu_config = BPDUConfig(
                    flags = b'\x00',
                    root_bridge_id = struct.pack('!B', root_bridge_id) 
                    + b'\x00\x00\x00\x00\x00\x00\x00',
                    root_path_cost = b'\x00\x00\x00\x00', 
                    bridge_id = struct.pack('!B', own_bridge_id) 
                    + b'\x00\x00\x00\x00\x00\x00\x00',
                    port_id = port_id,
                    message_age = b'\x00\x00',
                    max_age = b'\x00\x00',
                    hello_time = b'\x00\x00',
                    forward_delay = b'\x00\x00'
                )

                serialized_bpdu_config = bpdu_config.serialize()
                data = dest_mac + src_mac + llc_length + llc_header + bpdu_header + serialized_bpdu_config
                send_to_link(interface, data, len(data))
        time.sleep(1)

def perform_vlan_tagging(data, data_length, vlan_id):
    # Using vlan_id & 0x0FFF ensures that the id is stored in the last 12 bits.
    vlan_id = int(vlan_id) & 0xFFF  # Mask to ensure it fits within 12 bits.
    vlan_tag = struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id)
    new_data_length = data_length + VLAN_TAG_SIZE
    
    return data[0:12] + vlan_tag + data[12:], new_data_length

def extract_vlan_id(data):
    vlan_tci = int.from_bytes(data[14:16], byteorder='big')
    vlan_id = vlan_tci & 0xFFF  # Extract the 12-bit VLAN ID.

    return vlan_id

def handle_vlan_frame(data, data_length, interface_to_send_on, source_vlan_id,
                       target_interface_vlan_id, switch_port_states):
    def should_send_packet():
        return (
            interface_to_send_on in switch_port_states and
            switch_port_states[interface_to_send_on] == 'listening'
        )

    if source_vlan_id != 'T':  # Access port.
        if str(target_interface_vlan_id) == 'T':
            data, data_length = perform_vlan_tagging(data, data_length, source_vlan_id)
        elif int(source_vlan_id) == int(target_interface_vlan_id):
            # Check if the frame has a VLAN tag.
            if data[12] == 0x81 and data[13] == 0x00:
                data = data[0:12] + data[16:]
                data_length = data_length - VLAN_TAG_SIZE
        else:
            return

    if source_vlan_id == 'T':  # Trunk port.
        vlan_for_received_frame = extract_vlan_id(data)
        if str(target_interface_vlan_id) == 'T':
            pass  # No additional processing needed
        elif int(target_interface_vlan_id) == int(vlan_for_received_frame):
            data = data[0:12] + data[16:]
            data_length = data_length - VLAN_TAG_SIZE
        else:
            return

    if should_send_packet():
        send_to_link(interface_to_send_on, data, data_length)

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    dest_mac = data[0:6]
    src_mac = data[6:12]
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # Extract the 12-bit VLAN ID.
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id


def read_switch_config(id, nr_interfaces):
    file_path = "configs/switch{}.cfg".format(id)
    with open(file_path, "r") as file:
        lines = file.readlines()

    switch_priority = int(lines[0])

    # Create a dictionary to store interface-to-VLAN mappings
    interface_vlan_mapping = {}

    for i in range(1, nr_interfaces + 1):
        line = lines[i].split()
        if len(line) > 1:
            vlan_number = line[1]
            interface_vlan_mapping[i - 1] = vlan_number

    return switch_priority, interface_vlan_mapping

# If the least significant bit of the first byte is 0, it is unicast.
def check_unicast_mac(mac):
    return mac[0] & 1 == 0

def main():
    MAC_table = {} # Mapping MAC address to interface.
    switch_port_states = {} # Mapping interface to state.
    switch_id = sys.argv[1]
    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)
    switch_priority, interface_vlan_mapping = read_switch_config(switch_id, num_interfaces)

    # Setting each trunk port to blocking state.
    for interface in interfaces:
        if interface_vlan_mapping[interface] == 'T':
            switch_port_states[interface] = 'blocking'

    own_bridge_id = switch_priority
    root_bridge_id = switch_priority
    link_cost = 0

    # If the switch is the root bridge, set all trunk ports to listening state.
    if own_bridge_id == root_bridge_id:
        for interface in interfaces:
            switch_port_states[interface] = 'listening'

    dest_mac = '01:80:C2:00:00:00' # BPDU multicast MAC
    src_mac = get_switch_mac()
    
    # Create and start a new thread that deals with sending BPDU
    t = threading.Thread(target=send_bpdu_every_sec, args =
                          (interfaces, interface_vlan_mapping, own_bridge_id, root_bridge_id))
    t.start()

    while True:
        interface, data, length = recv_from_any_link()
        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        if check_bpdu_packet(data): # handle received BPDU
            if get_root_bridge_id(data) < root_bridge_id:
                root_bridge_id = get_root_bridge_id(data)
                link_cost = get_root_path_cost(data) + STANDARD_LINK_COST
                bpdu_root_port = interface
                
                # Stoping sending BPDU when a lower bridge id is found.
                if root_bridge_id != own_bridge_id:
                    for interface in interfaces:
                        if interface_vlan_mapping[interface] == 'T' and interface != bpdu_root_port:
                            switch_port_states[interface] = 'blocking'

                if switch_port_states[bpdu_root_port] == 'blocking':
                    switch_port_states[bpdu_root_port] = 'listening'

                BPDUConfig.update_sender_bridge_id(data, own_bridge_id)
                BPDUConfig.update_sender_bridge_id(data, own_bridge_id)

                # Send to all other interfaces.
                for interface in interfaces:
                    if interface != bpdu_root_port and switch_port_states[interface] == 'listening':
                        send_to_link(interface, data, len(data))
                        continue

            # Case when the root bridge is found.
            elif get_root_bridge_id(data) == root_bridge_id:
                if interface == get_port_id(data) and \
                get_root_path_cost(data) + STANDARD_LINK_COST < link_cost:
                    link_cost = get_root_path_cost + STANDARD_LINK_COST
                elif interface != get_port_id(data):
                    if get_root_path_cost(data) > link_cost:
                        switch_port_states[interface] = 'listening'

            elif get_sender_bridge_id(data) == own_bridge_id:
                switch_port_states[interface] = 'blocking'
            else: # Discard the BPDU.
                continue

            if own_bridge_id == root_bridge_id:
                for interface in interfaces:
                    if interface_vlan_mapping[interface] == 'T':
                        switch_port_states[interface] = 'listening'

        MAC_table[src_mac] = interface
        source_vlan_id = interface_vlan_mapping[interface]

        if check_unicast_mac(dest_mac):
            if dest_mac in MAC_table: # Send only to the interface that has the destination MAC.
                unicast_target_interface = MAC_table[dest_mac]
                if unicast_target_interface in interface_vlan_mapping:
                    target_interface_vlan_id = interface_vlan_mapping[unicast_target_interface]

                handle_vlan_frame(data, length, unicast_target_interface, source_vlan_id,
                                   target_interface_vlan_id, switch_port_states)
            else: # Flooding for unicast MAC
                for target_interface in interfaces:
                    if target_interface != interface:
                        if target_interface in interface_vlan_mapping:
                            target_interface_vlan_id = interface_vlan_mapping[target_interface]

                        handle_vlan_frame(data, length, target_interface, source_vlan_id,
                         target_interface_vlan_id, switch_port_states)
        else: # Flooding for multicast MAC
            for target_interface in interfaces:
                if target_interface != interface:
                    if target_interface in interface_vlan_mapping:
                        target_interface_vlan_id = interface_vlan_mapping[target_interface]

                    handle_vlan_frame(data, length, target_interface, source_vlan_id, target_interface_vlan_id, switch_port_states)

if __name__ == "__main__":
    main()
