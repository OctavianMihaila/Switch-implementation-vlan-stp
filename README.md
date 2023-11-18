'1 2 3'

## Switch implementation with VLANs and STP
    >> It is written in Python3 and uses Mininet for network simulation.
    >> The switch is implemented in the file switch.py and the topology is defined in topo.py.
    >> The topology can be found [here](https://ocw.cs.pub.ro/courses/_detail/rl/teme/tema1_topo.png?id=rl%3Ateme%3Atema1_sw) 

## How to Run

    ```bash
    sudo python3 checker/topo.py
    ```

    This will open 9 terminals, 6 hosts and 3 for the switches. On the switch terminal you will run 

    ```bash
    make run_switch SWITCH_ID=X # X is 0,1 or 2
    ```

## Implementation details

    >> Switch table
        -- When receiving a packet, the first thing the switch does is to check if the
        MAC address is unicast (If the least significant bit of the first byte is 0,
        it is unicast.).

        -- If it is unicast, the switch will forward the packet only on the interface
        coressponding to the destination MAC address. If it is broadcast, the switch
        will forward the packet on all interfaces except the one it received.

    >> VLAN
        -- Used a dictionary to map between interfaces and vlan ids. Created a handler that
        takes care of finding the interface corresponding to the target_vlan_id which is 
        found using the dictionary mentioned above and the destination MAC address.

        -- When it has to deal with a trunk port, the switch will forward the packet without
        changing the VLAN id if the interface on which the packet was received is also a trunk.
        If it is not, then the switch will ad the 802.1q header to the packet and tag it with
        the specific vlan id (from the port that the packet was received on).

    >> STP

        -- Created a dictionary that associates an interface with a state(in our simplified 
        version, the stats are listening and blocking). After the switch starts, it will set
        all of its trunk ports to blocking state.

        -- Create a class BPDUConfig that takes care of creating the BPDU Configuration which
        is later encapsulated in an ethernet frame and sent on all trunk ports by the switch.
        The enthernet frame is constructed exactly as in the given example (added 7 bytes of 
        0x00 after root_bride_id and bride_id in order to have the same length as in documentation).

        -- A thread is created that deals with sending the BPDU packet every second. It runs
        until a BPDU packet that contains a lower root_bridge_id is received. When this event
        happens, the received packet is forwarded on all trunk ports except the one it was
        received on and the thread is stopped. 

        -- Added aditional checks so that the forwarding is done only on the interfaces that
        are in the blocking state.
