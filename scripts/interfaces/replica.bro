#! Provide synchronization of state from manager to workers

module osquery::state::interfaces;

event osquery::interface_state_added(t: time, host_id: string, interface_info: osquery::InterfaceInfo) &priority=10 {
	local name = interface_info$name;

	# Initialize
	if (host_id !in interfaces) { interfaces[host_id] = table(); }
	
	# Insert into state
	if (name in interfaces[host_id]) { 
		interfaces[host_id][name] += interface_info;
	} else {
		interfaces[host_id][name] = vector(interface_info);
	}
}

event osquery::interface_host_state_removed(t: time, now: time, host_id: string) &priority=10 {
	if (host_id in interfaces) { delete interfaces[host_id]; }
}

event osquery::interface_state_removed(t: time, now: time, host_id: string, interface_info: osquery::InterfaceInfo) &priority=10 {
	local name = interface_info$name;

	# Check state
	if (host_id !in interfaces) { return; }
	if (name !in interfaces[host_id]) { return; }

	# Remove last item in state
	if (|interfaces[host_id][name]| == 1) {
		if (osquery::equalInterfaceInfos(interface_info, interfaces[host_id][name][0])) {
			delete interfaces[host_id][name];
		}
		return;
	}

	# Remove from state
	local interface_infos: vector of osquery::InterfaceInfo = vector();
	for (idx in interfaces[host_id][name]) {
		if (idx == |interface_infos| && osquery::equalInterfaceInfos(interface_info, interfaces[host_id][name][idx])) { next; }
		interface_infos += interfaces[host_id][name][idx];
	}

	# Save state
	interfaces[host_id][name] = interface_infos;
}
