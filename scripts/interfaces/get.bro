#! Provide access to user information about hosts.

module osquery;

export {
	## Get the all AddrInfo of a host by its id
	##
	## host_id: The identifier of the host
	global getAddrInfosByHostID: function(host_id: string): set[AddrInfo];

	## Get the Host Info of a host by its address
	##
	## ip: the ip address of the host
	global getHostIDsByAddress: function(a: addr): set[string];
}

function getAddrInfosByHostID(host_id: string): set[AddrInfo] {
	local addr_infos: set[AddrInfo] = set();
	if (host_id !in osquery::state::interfaces::interfaces) { return addr_infos; }

	for (name in osquery::state::interfaces::interfaces[host_id]) {
		for (idx in osquery::state::interfaces::interfaces[host_id][name]) {
			if (osquery::state::interfaces::interfaces[host_id][name][idx]?$addr_info) {
				add addr_infos[osquery::state::interfaces::interfaces[host_id][name][idx]$addr_info];
			}
		}
	}

	return addr_infos;
}

function getHostIDsByAddress(a: addr): set[string] {
	local host_ids: set[string] = set();

	for (host_id in osquery::state::interfaces::interfaces) {
		for (name in osquery::state::interfaces::interfaces[host_id]) {
			for (idx in osquery::state::interfaces::interfaces[host_id][name]) {
				if (!osquery::state::interfaces::interfaces[host_id][name][idx]?$addr_info) {
					next;
				}
				if (osquery::state::interfaces::interfaces[host_id][name][idx]$addr_info$ip == a) {
					add host_ids[host_id];
					break;
				}
			}
			if (host_id in host_ids) { break; }
		}
	}

	return host_ids;
}
