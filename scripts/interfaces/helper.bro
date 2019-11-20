#! Provide interface state helper

#module osquery;
#@if ( Cluster::local_node_type() == Cluster::MANAGER )
## Manager need ability to forward state to workers.
#event zeek_init() {
#	Broker::auto_publish(Cluster::worker_topic, osquery::interface_state_added);
#	Broker::auto_publish(Cluster::worker_topic, osquery::interface_host_state_removed);
#	Broker::auto_publish(Cluster::worker_topic, osquery::interface_state_removed);
#}
#@endif

module osquery::state::interfaces;

export {
	# Table to count the balance of connects by HostID
	global connect_balance: table[string] of count;

	# Table to indidate host freshness by HostID
	global host_freshness: table[string] of string;

	# Set of HostID that have maintenance scheduled
	global host_maintenance: set[string];

	# Add an entry to the interface state
	global add_entry: function(t: time, host_id: string, name: string, mac: string, ip: string, mask: string);

	# Remove an entry from the interface state
	global remove_entry: function(t: time, now: time, host_id: string, name: string, mac: string, ip: string, mask: string);

	# Remove all entries for host from the interface state
	global remove_host: function(t: time, now: time, host_id: string);
}

function add_entry(t: time, host_id: string, name: string, mac: string, ip: string, mask: string) {
	local interface_info: osquery::InterfaceInfo = [$name=name, $mac=mac];
	if (ip != "") {
		local a = to_addr(ip);
		local addr_info: osquery::AddrInfo = [$ip=a];
		if (mask != "") { addr_info$mask = mask; }
		interface_info$addr_info = addr_info;
	}

	# Initialize
	if (host_id !in interfaces) { interfaces[host_id] = table(); }

	# Key already in state
	if (name in interfaces[host_id]) {
		# Identify duplicates
		local new = T;
		for (idx in interfaces[host_id][name]) {
			if (osquery::equalInterfaceInfos(interface_info, interfaces[host_id][name][idx])) { new = F; }
		}
		# Raise event
		if (new) {
			event osquery::interface_state_added(t, host_id, interface_info);
			Broker::publish(Cluster::worker_topic, Broker::make_event(osquery::interface_state_added, t, host_id, interface_info));
		}
		# Save state
		interfaces[host_id][name] += interface_info;
	# New key in state
	} else {
		# Raise event
		event osquery::interface_state_added(t, host_id, interface_info);
		Broker::publish(Cluster::worker_topic, Broker::make_event(osquery::interface_state_added, t, host_id, interface_info));
		# Create state
		interfaces[host_id][name] = vector(interface_info);
	}
}

function remove_entry(t: time, now: time, host_id: string, name: string, mac: string, ip: string, mask: string) {
	# Check if interface exists
	if (host_id !in interfaces) { return; }
	if (name !in interfaces[host_id]) { return; }
	if (|interfaces[host_id][name]| == 0) { return; }

	# Remove from state
	local interface_info: osquery::InterfaceInfo = [$name=name, $mac=mac];
	if (ip != "") {
		local a = to_addr(ip);
		local addr_info: osquery::AddrInfo = [$ip=a];
		if (mask != "") { addr_info$mask = mask; }
		interface_info$addr_info = addr_info;
	}

	# Last item in state
	if (|interfaces[host_id][name]| == 1) {
		if (!osquery::equalInterfaceInfos(interface_info, interfaces[host_id][name][0])) { return; }
		# Raise event
		event osquery::interface_state_removed(t, now, host_id, interface_info);
		Broker::publish(Cluster::worker_topic, Broker::make_event(osquery::interface_state_removed, t, now, host_id, interface_info));
		# Delete state
		delete interfaces[host_id][name];
	# Oldest item in state
	} else {
		local interface_infos: vector of osquery::InterfaceInfo = vector();
		# --- Identify duplicates
		local old = T;
		for (idx in interfaces[host_id][name]) {
			if (idx == |interface_infos|) {
				if (osquery::equalInterfaceInfos(interface_info, interfaces[host_id][name][idx])) { 
					next; 
				}
			} else {
				if (old && osquery::equalInterfaceInfos(interface_info, interfaces[host_id][name][idx])) { 
					old = F; 
				}
			}
			interface_infos += interfaces[host_id][name][idx];
		}
		# Raise event
		if (old) {
			event osquery::interface_state_removed(t, now, host_id, interface_info);
			Broker::publish(Cluster::worker_topic, Broker::make_event(osquery::interface_state_removed, t, now, host_id, interface_info));
		}
		# Save state
		interfaces[host_id][name] = interface_infos;
	}
}

function remove_host(t: time, now: time, host_id: string) {
	# Check if host exists
	if (host_id !in interfaces) { return; }

	# Iterate state
	for (name in interfaces[host_id]) {
		for (idx in interfaces[host_id][name]) {
			# Raise event
			event osquery::interface_state_removed(t, now, host_id, interfaces[host_id][name][idx]);
			Broker::publish(Cluster::worker_topic, Broker::make_event(osquery::interface_state_removed, t, now, host_id, interfaces[host_id][name][idx]));
		}
	}

	# Delete state
	delete interfaces[host_id];
}
