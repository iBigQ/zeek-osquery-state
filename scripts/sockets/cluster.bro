#! Provide synchronization of state from manager to workers

module osquery::state::sockets;

event osquery::socket_state_added(host_id: string, socket_info: osquery::SocketInfo) &priority=10 {
	local path = "";
	local family = -1;
	local success = -1;
	if (socket_info?$path) { path = socket_info$path; }
	if (socket_info?$family) { family = socket_info$family; }
	if (socket_info?$success) { success = socket_info$success; }
	add_entry(host_id, socket_info$pid, socket_info$fd, socket_info$connection, socket_info$state, path, family, success);
}

event osquery::socket_host_state_removed(host_id: string) &priority=10 {
	host_freshness[host_id] = F;
	remove_host(host_id);

	delete host_freshness[host_id];
	if (host_id in socket_events_freshness) {
		delete socket_events_freshness[host_id];
	}
}

event osquery::socket_state_removed(host_id: string, socket_info: osquery::SocketInfo) &priority=10 {
	local oldest = T;
	if (socket_info$state == "connect" || socket_info$state == "bind") {
		local sockets = socket_events;
		if (host_id !in sockets) { return; }
		if (|sockets[host_id][socket_info$pid, socket_info$fd]| == 1) { 
			if (host_id !in socket_events_freshness) { socket_events_freshness[host_id] = table(); }
			socket_events_freshness[host_id][socket_info$pid, socket_info$fd] = F;
			oldest = F;
		}
	}
	remove_entry(host_id, socket_info$pid, socket_info$fd, socket_info$state, oldest);
}
