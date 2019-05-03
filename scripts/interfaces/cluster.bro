#! Provide synchronization of state from manager to workers

module osquery::state::interfaces;

event osquery::interface_state_added(host_id: string, name: string, mac: string, addr_info: osquery::AddrInfo) &priority=10 {
	local mask = "";
	if (addr_info?$mask) { mask = addr_info$mask; }
	add_entry(host_id, name, mac, addr_info$ip, mask);
}

event osquery::interface_host_state_removed(host_id: string) &priority=10 {
	host_freshness[host_id] = F;
	remove_host(host_id);

	delete host_freshness[host_id];
	if (host_id in interface_freshness) {
		delete interface_freshness[host_id];
	}
}

event osquery::interface_state_removed(host_id: string, name: string, mac: string, addr_info: osquery::AddrInfo) &priority=10 {
	if (host_id !in interface_freshness) { return; }
	if ([name, addr_info$ip] !in interface_freshness[host_id]) { return; }
	
	interface_freshness[host_id][name, addr_info$ip] = F;
	remove_entry(host_id, name, addr_info$ip);
}
