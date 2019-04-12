#! Provide interface state commons

module osquery;

export {
	type AddrInfo: record {
		ip: addr;
		mask: string &optional;
	};

	type InterfaceInfo: record {
		name: string;
		mac: string;
		addrs: vector of AddrInfo &default = vector();
	};

	## Event when added to the state of interfaces
	##
	## <params missing>
	global interface_state_added: event(host_id: string, name: string, mac: string, addr_info: AddrInfo);
	
	## Event when removing a host from the state of interfaces
	##
	## <params missing>
	global interface_host_state_removed: event(host_id: string);
	
	## Event when removing from the state of interfaces
	##
	## <params missing>
	global interface_state_removed: event(host_id: string, name: string, mac: string, addr_info: AddrInfo);
}

module osquery::state::interfaces;

export {
	# Table to access AddrInfo by HostID
	global interfaces: table[string] of table[string] of osquery::InterfaceInfo;

	# Table to indicate freshness of AddrInfo by HostID
	global interface_freshness: table[string] of table[string, addr] of bool;

	# Table to indicate freshness of hosts by HostID
	global host_freshness: table[string] of bool;

	# Set of HostID that have maintenance scheduled
	global host_maintenance: set[string];

	# Add an entry to the interface state
	global add_entry: function(host_id: string, name: string, mac: string, ip: addr, mask: string);

	# Remove an entry from the interface state
	global remove_entry: function(host_id: string, name: string, ip: addr);

	# Remove all entries for host from the interface state
	global remove_host: function(host_id: string);
}

function add_entry(host_id: string, name: string, mac: string, ip: addr, mask: string) {
	local addr_info: osquery::AddrInfo = [$ip=ip];
	if (mask != "") { addr_info$mask = mask; }

	# Insert into state
	if (host_id !in interfaces) { interfaces[host_id] = table(); }
	if (name !in interfaces[host_id]) {
		interfaces[host_id][name] = [$name=name, $mac=mac];
	}
	if (mac != interfaces[host_id][name]$mac) {
		print(fmt("Overriding MAC address of interface %s", name));
		interfaces[host_id][name]$mac = mac;
	}
	interfaces[host_id][name]$addrs += addr_info;

	# Set fresh
	interface_freshness[host_id][name, ip] = T;
	event osquery::interface_state_added(host_id, name, mac, addr_info);
}

function remove_entry(host_id: string, name: string, ip: addr) {
	# Check if interface exists
	if (host_id !in interfaces) { return; }
	if (name !in interfaces[host_id]) { return; }

	# Check if interface is fresh
	if (interface_freshness[host_id][name, ip]) { return; }

	# Remove from state
	local addr_info: osquery::AddrInfo;
	for (idx in interfaces[host_id][name]$addrs) {
		if (interfaces[host_id][name]$addrs[idx]$ip == ip) {
			addr_info = interfaces[host_id][name]$addrs[idx];
			# Delete element
			local addrs_new: vector of osquery::AddrInfo = vector();
			for (a in interfaces[host_id][name]$addrs) {
				if (a == idx) { next; }
				addrs_new += interfaces[host_id][name]$addrs[a];
			}
			interfaces[host_id][name]$addrs = addrs_new;
			break;
		}
	}

	# Remove freshness
	delete interface_freshness[host_id][name, ip];
	local mac = interfaces[host_id][name]$mac;
	event osquery::interface_state_removed(host_id, name, mac, addr_info);
}

function remove_host(host_id: string) {
	if (host_id !in interfaces) { return; }

	for (name in interfaces[host_id]) {
		local mac = interfaces[host_id][name]$mac;
		for (idx in interfaces[host_id][name]$addrs) {
			local addr_info = interfaces[host_id][name]$addrs[idx];
			event osquery::interface_state_removed(host_id, name, mac, addr_info);
		}
	}
	delete interfaces[host_id];
}
