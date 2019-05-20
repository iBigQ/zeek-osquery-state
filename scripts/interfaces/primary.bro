#! Provide current interface information about hosts.

@load zeek-osquery-framework
@load zeek-osquery-queries/tables/interfaces

module osquery::state::interfaces;

event osquery::interface_added(t: time, host_id: string, interface: string, mac: string, ip: string, mask: string) {
	add_entry(host_id, interface, mac, ip, mask);
}

event osquery::state::interfaces::scheduled_remove(host_id: string, name: string, mac: string, ip: string, mask: string) {
	# Delete
	remove_entry(host_id, name, mac, ip, mask);
}

event osquery::state::interfaces::scheduled_remove_host(host_id: string, cookie: string) {
	# Verify host freshness
	if (host_freshness[host_id] != cookie) { return; }
	delete host_freshness[host_id];
	if (host_id in connect_balance) { delete connect_balance[host_id]; }
	if (host_id in host_maintenance) { delete host_maintenance[host_id]; }

	# Indicate state changes
	event osquery::interface_host_state_removed(host_id);
	Broker::publish(Cluster::worker_topic, Broker::make_event(osquery::interface_host_state_removed, host_id));
	remove_host(host_id);
}

function schedule_remove(host_id: string, name: string, mac: string, ip: string, mask: string) {
	# Verify state
	if (host_id !in interfaces) { return; }
	if (name !in interfaces[host_id]) { return; }

	# InterfaceInfo to delete
	local interface_info: osquery::InterfaceInfo = [$name=name, $mac=mac];
	if (ip != "") {
		local a = to_addr(ip);
		local addr_info: osquery::AddrInfo = [$ip=a];
		if (mask != "") { addr_info$mask = mask; }
		interface_info$addr_info = addr_info;
	}
	
	# Find next item
	local exists = F;
	for (idx in interfaces[host_id][name]) {
		if (!osquery::equalInterfaceInfos(interface_info, interfaces[host_id][name][idx])) {
			next;
		}
		# Mark deleting
		interfaces[host_id][name][idx]$deleting = T;
		exists = T;
		break;
	}

	# Schedule delete
	if (!exists) { return; }
	schedule osquery::STATE_REMOVAL_DELAY { osquery::state::interfaces::scheduled_remove(host_id, name, mac, ip, mask) };
}

event osquery::interface_removed(t: time, host_id: string, interface: string, mac: string, ip: string, mask: string) {
	# Schedule remove
	schedule_remove(host_id, interface, mac, ip, mask);
}

function remove_legacy(host_id: string) {
	# Check host
	if (host_id !in interfaces) { return; }

	# Iterate InterfaceID
	for (name in interfaces[host_id]) {
		if (|interfaces[host_id][name]| == 0) { next; }
		# Remove remaining state
		local interface_info: osquery::InterfaceInfo;
		local mac = ""; 
		local ip = "";
		local mask = "";
		for (idx in interfaces[host_id][name]) {
			# Skip already deleting
			if (interfaces[host_id][name][idx]$deleting) { next; }

			# Extract attributes
			interface_info = interfaces[host_id][name][idx];
			mac = interface_info$mac;
			if (interface_info?$addr_info) {
				ip = cat(interface_info$addr_info$ip);
				if (interface_info$addr_info?$mask) {
					mask = interface_info$addr_info$mask;
				} else { mask = ""; }
			} else {
				ip = "";
				mask = "";
			}

			# Schedule remove
			schedule_remove(host_id, name, mac, ip, mask);
		}
	}
}

event osquery::host_connected(host_id: string) {
	# Update freshnes
	host_freshness[host_id] = "";

	# First connect
	if (host_id !in connect_balance) {
		connect_balance[host_id] = 0;
	}
	# Remove legacy
	if (connect_balance[host_id] >= 0) {
		remove_legacy(host_id);
	}
	# Update balance
	connect_balance[host_id] += 1;
}

event osquery::host_disconnected(host_id: string) {
	# Update balance
	connect_balance[host_id] -= 1;
	# - Last disconnect
	if (connect_balance[host_id] == 0) {
		# Schedule removal of host
		host_freshness[host_id] = cat(rand(0xffffffffffffffff));
		schedule osquery::STATE_REMOVAL_DELAY { osquery::state::interfaces::scheduled_remove_host(host_id, host_freshness[host_id]) };
		# Remove legacy
		remove_legacy(host_id);
	}
}

hook osquery::getIPsOfHost(host_id: string, addresses: vector of addr)
{
    local addr_infos = osquery::getAddrInfosByHostID(host_id);
    for (addr_info in addr_infos) {
	addresses += addr_info$ip;
    }
    break;
}
