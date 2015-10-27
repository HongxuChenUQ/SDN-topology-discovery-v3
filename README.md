# SDN-topology-discovery-v3

To run OFDPv3:

preparation:
1: Create a topogy in mininet: sudo mn --topo.... 

To load the new discovery code:
3: cd pox/pox/openflow/
4: gedit discoveryV3.py
5: copy and paste the source code into discoveryV3.py
6: save 

To Run:
1: Open another teminal and : cd pox
2: Type: ./pox.py --verbose openflow.discoveryV3