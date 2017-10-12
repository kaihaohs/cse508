# CSE508 HW2 mydump 


	bin/mydump [-h] [-i interface] [-r file] [-s string] [expression]

	For each packet, mydump outputs a record containing 
	the timestamp, source and destination MAC address, EtherType, packet 
	length, source and destination IP address and port, protocol type("TCP", "UDP",
	"ICMP","OTHER"), and the raw content of the application-layer packet 
	payload.

	-h                               Displays this help menu.

	-i                               Listen on network device <interface>
                                 (e.g., eth0). If not specified,
                                 automatically select a default interface.
	
	-r                               Read packets from <file> in tcpdump format.
	
	-s                               Keep only packets that contain
	                                 <string> in their payload.
	
	expression                       A BPF filter that specifies which
	                                 packets will be dumped. If no filter is
	                                 given, all packets seen on the interface
	                                 (or contained in the trace) will be
                                 dumped. Otherwise, only packets matching
                                 <expression> will be dumped.