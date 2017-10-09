# CSE508 HW2 mydump 
## Usage

	./mydump [-h] [-i interface] [-r file] [-s string] [expression]

	For each packet, mydump outputs a record containing
	the timestamp, source and destination MAC address, EtherType, packet
	length, source and destination IP address and port, protocol (TCP, UDP,
	ICMP, OTHER), and the raw content of the application-layer packet
	payload.
	
	-h                               Displays this help menu.
	
	-i                               Listen on network device &lt;interface&gt;
	                                 (e.g., eth0). If not specified,
	                                 defaults to the first interface found.
	
	-r                               Read packets from &lt;file&gt; (tcpdump format).
	
	-s                               Keep only packets that contain
	                                 &lt;string&gt; in their payload.
	
	expression                       A BPF filter that specifies which
	                                 packets will be dumped. If no filter is
	                                 given, all packets seen on the interface
	                                 (or contained in the trace) will be
	                                 dumped. Otherwise, only packets matching
	                                 &lt;expression&gt; will be dumped.