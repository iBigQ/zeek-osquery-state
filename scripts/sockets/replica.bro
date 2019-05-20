#! Provide synchronization of state from manager to workers

module osquery::state::sockets;

event osquery::socket_state_added(host_id: string, socket_info: osquery::SocketInfo) &priority=10 {
	local pid = socket_info$pid;
	local fd = socket_info$fd;

	# Select table
	local sockets: SocketState;
	if (socket_info$state == "established") { sockets = process_open_sockets; }
	else if (socket_info$state == "listening") { sockets = listening_ports; }
	else if (socket_info$state == "connect") { sockets = socket_events; }
	else if (socket_info$state == "bind") { sockets = socket_events; }
	else { return; }

	# Initialize
	if (host_id !in sockets) { sockets[host_id] = table(); }
	
	# Insert into state
	if ([pid, fd] in sockets[host_id]) { 
		sockets[host_id][pid, fd] += socket_info;
	} else {
		sockets[host_id][pid, fd] = vector(socket_info);
	}
}

event osquery::socket_host_state_removed(host_id: string) &priority=10 {
	if (host_id in process_open_sockets) { delete process_open_sockets[host_id]; }
	if (host_id in listening_ports) { delete listening_ports[host_id]; }
	if (host_id in socket_events) { delete socket_events[host_id]; }
}

event osquery::socket_state_removed(host_id: string, socket_info: osquery::SocketInfo) &priority=10 {
	local pid = socket_info$pid;
	local fd = socket_info$fd;

	# Select table
	local sockets: SocketState;
	if (socket_info$state == "established") { sockets = process_open_sockets; }
	else if (socket_info$state == "listening") { sockets = listening_ports; }
	else if (socket_info$state == "connect") { sockets = socket_events; }
	else if (socket_info$state == "bind") { sockets = socket_events; }
	else { return; }

	# Check state
	if (host_id !in sockets) { return; }
	if ([pid, fd] !in sockets[host_id]) { return; }

	# Remove last item in state
	if (|sockets[host_id][pid, fd]| == 1) {
		if (osquery::equalSocketInfos(socket_info, sockets[host_id][pid, fd][0])) {
			delete sockets[host_id][pid, fd];
		}
		return;
	}

	# Remove from state
	local socket_infos: vector of osquery::SocketInfo = vector();
	for (idx in sockets[host_id][pid, fd]) {
		if (idx == |socket_infos| && osquery::equalSocketInfos(socket_info, sockets[host_id][pid, fd][idx])) { next; }
		socket_infos += sockets[host_id][pid, fd][idx];
	}

	# Save state
	sockets[host_id][pid, fd] = socket_infos;
}
