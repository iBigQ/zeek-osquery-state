#! Provide current interface information about hosts.

@load zeek-osquery-framework
@load zeek-osquery-queries/tables/interfaces

module osquery::state::interfaces;

event osquery::interface_added(t: time, host_id: string, interface: string, mac: string, ip: string, mask: string) {
	local a = to_addr(ip);
	add_entry(host_id, interface, mac, a , mask);
}

event osquery::state::interfaces::scheduled_remove(host_id: string, name: string, ip: addr) {
	remove_entry(host_id, name, ip);
}

event osquery::interface_removed(t: time, host_id: string, interface: string, mac: string, ip: string, mask: string) {
	local a = to_addr(ip);
	interface_freshness[host_id][interface, a] = F;
	schedule osquery::STATE_REMOVAL_DELAY { osquery::state::interfaces::scheduled_remove(host_id, interface, a) };
}

event osquery::state::interfaces::scheduled_remove_host(host_id: string) {
	# Skip if host reconnected in the meantime
	if (host_id !in host_freshness) { return; }
	if (host_freshness[host_id]) { return; }

	# Indicate state changes
	event osquery::interface_host_state_removed(host_id);
	remove_host(host_id);

	# Delete freshness
	delete interface_freshness[host_id];
	delete host_freshness[host_id];
}

event osquery::host_connected(host_id: string) {
	host_freshness[host_id] = T;
	if (host_id !in interface_freshness) { interface_freshness[host_id] = table(); }
	if (host_id !in interfaces) { interfaces[host_id] = table(); }
}

event osquery::host_disconnected(host_id: string) {
	# Set host and state not fresh
	host_freshness[host_id] = F;
	for (name in interfaces[host_id]) {
		for (idx in interfaces[host_id][name]$addrs)
		local ip = interfaces[host_id][name]$addrs[idx]$ip;
		interface_freshness[host_id][name, ip] = F;
	}

	# Schedule removal of host
	schedule osquery::STATE_REMOVAL_DELAY { osquery::state::interfaces::scheduled_remove_host(host_id) };
}

hook osquery::getIPsOfHost(host_id: string, addresses: vector of addr)
{
    local addr_infos = osquery::getAddrInfosByHostID(host_id);
    for (addr_info in addr_infos) {
	addresses += addr_info$ip;
    }
    break;
}
