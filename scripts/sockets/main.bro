#! Provide current socket information about hosts.

@load zeek-osquery-framework
@load zeek-osquery-queries/tables/listening_ports
@load zeek-osquery-queries/tables/process_open_sockets
#@load zeek-osquery-queries/tables/socket_events

module osquery::state::sockets;

event osquery::state::sockets::initial_process_open_socket(resultInfo: osquery::ResultInfo, pid: int, fd: int, family: int, protocol: int, local_address: string, remote_address: string, local_port: int, remote_port: int) {
	local path: string = "";
	local success: int = 1;
	local state: string = "connect";
	local connection_tuple = osquery::create_connection_tuple(local_address, remote_address, local_port, remote_port, protocol);
	add_entry(resultInfo$host, pid, fd, connection_tuple, state, path, family, success);
}

event osquery::state::sockets::initial_listening_port(resultInfo: osquery::ResultInfo, pid: int, fd: int, family: int, socket: int, protocol: int, local_address: string, local_port: int) {
	local path: string = "";
	local success: int = 1;
	local state: string = "bind";
	local remote_address = "";
	local remote_port = -1;
	local connection_tuple = osquery::create_connection_tuple(local_address, remote_address, local_port, remote_port, protocol);
	add_entry(resultInfo$host, pid, fd, connection_tuple, state, path, family, success);
}

event osquery::process_open_socket_added(t: time, host_id: string, pid: int, fd: int, family: int, protocol: int, local_address: string, remote_address: string, local_port: int, remote_port: int) {
	local path: string = "";
	local success: int = 1;
	local state: string = "established";
	local connection_tuple = osquery::create_connection_tuple(local_address, remote_address, local_port, remote_port, protocol);
	add_entry(host_id, pid, fd, connection_tuple, state, path, family, success);
}

event osquery::listening_port_added(t: time, host_id: string, pid: int, fd: int, family: int, socket: int, protocol: int, local_address: string, local_port: int) {
	local path: string = "";
	local success: int = 1;
	local state: string = "listening";
	local remote_address = "";
	local remote_port = -1;
	local connection_tuple = osquery::create_connection_tuple(local_address, remote_address, local_port, remote_port, protocol);
	add_entry(host_id, pid, fd, connection_tuple, state, path, family, success);
}

event osquery::socket_event_added(t: time, host_id: string, action: string, pid: int, fd: int, path: string, family: int, protocol: int, local_address: string, remote_address: string, local_port: int, remote_port: int, start_time: int, success: int) {
	local connection_tuple = osquery::create_connection_tuple(local_address, remote_address, local_port, remote_port, protocol);
	add_entry(host_id, pid, fd, connection_tuple, action, path, family, success);
}

event osquery::state::sockets::scheduled_remove(host_id: string, pid: int, fd: int, state: string, oldest: bool) {
	remove_entry(host_id, pid, fd, state, oldest);
}

event osquery::process_open_socket_removed(t: time, host_id: string, pid: int, fd: int, family: int, protocol: int, local_address: string, remote_address: string, local_port: int, remote_port: int) {
	local state: string = "established";
	schedule osquery::STATE_REMOVAL_DELAY { osquery::state::sockets::scheduled_remove(host_id, pid, fd, state, T) };
}

event osquery::listening_port_removed(t: time, host_id: string, pid: int, fd: int, family: int, socket: int, protocol: int, local_address: string, local_port: int) {
	local state: string = "listening";
	schedule osquery::STATE_REMOVAL_DELAY { osquery::state::sockets::scheduled_remove(host_id, pid, fd, state, T) };
}

event osquery::state::sockets::scheduled_remove_host(host_id: string) {
	# Skip if host reconnected in the meantime
	if (host_id !in host_freshness) { return; }
	if (host_freshness[host_id]) { return; }

	# Indicate state changes
	event osquery::socket_host_state_removed(host_id);
	remove_host(host_id);

	# Delete freshness
	delete socket_events_freshness[host_id];
	delete host_freshness[host_id];
}

event osquery::state::sockets::state_outdated(resultInfo: osquery::ResultInfo, pid_str: string, fd_str: string, state: string) {
	local pid = to_int(pid_str);
	local fd = to_int(fd_str);
	# Host already removed?
	if (resultInfo$host !in socket_events_freshness) { return; }

	socket_events_freshness[resultInfo$host][pid, fd] = F;
	schedule osquery::STATE_REMOVAL_DELAY { osquery::state::sockets::scheduled_remove(resultInfo$host, pid, fd, state, F) };
}

event osquery::state::sockets::verify(host_id: string) {
	local query: osquery::Query;
	local select_binds: vector of string = vector();
	local select_connects: vector of string = vector();
	local query_string: string;

	# Host successfully removed from state
	if (host_id !in host_freshness) { 
		# Stop further verifies
		delete host_maintenance[host_id];
		return; 
	}

	# Skip if host is offline or no state
	if (!host_freshness[host_id] || host_id !in socket_events) { 
		schedule osquery::STATE_MAINTENANCE_INTERVAL { osquery::state::sockets::verify(host_id) };
		return; 
	}

	# Collect event socket state
	for ([pid, fd] in socket_events[host_id]) {
		for (idx in socket_events[host_id][pid, fd]) {
			if (socket_events[host_id][pid, fd][idx]$state == "bind") {
				select_binds += fmt("SELECT %d AS x, %d AS y", pid, fd);
			} else if (socket_events[host_id][pid, fd][idx]$state == "connect") {
				select_connects += fmt("SELECT %d AS x, %d AS y", pid, fd);
			}
		}
	}

	if (|select_binds| != 0) {
		# Select query
		query_string = fmt("SELECT x, y, 'bind' FROM (%s) WHERE (x, y) NOT IN (SELECT pid, fd FROM listening_ports)" , join_string_vec(select_connects, " UNION "));
	
		# Send query
		query = [$ev=osquery::state::sockets::state_outdated, $query=query_string];
		osquery::execute(query, host_id);
	}

	if (|select_connects| != 0) {
		# Select query
		query_string = fmt("SELECT x, y, 'connect' FROM (%s) WHERE (x, y) NOT IN (SELECT pid, fd FROM process_open_sockets)" , join_string_vec(select_connects, " UNION "));
	
		# Send query
		query = [$ev=osquery::state::sockets::state_outdated, $query=query_string];
		osquery::execute(query, host_id);
	}
	
	# Schedule next verification
	schedule osquery::STATE_MAINTENANCE_INTERVAL { osquery::state::sockets::verify(host_id) };

}

event osquery::host_connected(host_id: string) {
	# Retrieve initial state
        local ev_sockets: osquery::Query;
	ev_sockets = [$ev=osquery::state::sockets::initial_process_open_socket, $query="SELECT pid, fd, family, protocol, local_address, remote_address, local_port, remote_port FROM process_open_sockets WHERE family=2 AND 1=1"];
	osquery::execute(ev_sockets, host_id);
        ev_sockets = [$ev=osquery::state::sockets::initial_listening_port, $query="SELECT pid, fd, family, socket, protocol, address, port FROM listening_ports WHERE family=2 AND 1=1"];
	osquery::execute(ev_sockets, host_id);

	# Schedule maintenance
	if (host_id !in host_maintenance) {
		add host_maintenance[host_id];
		event osquery::state::sockets::verify(host_id);
	}
	host_freshness[host_id] = T;
	if (host_id !in socket_events_freshness) { socket_events_freshness[host_id] = table(); }
	if (host_id !in process_open_sockets) { process_open_sockets[host_id] = table(); }
	if (host_id !in listening_ports) { listening_ports[host_id] = table(); }
	if (host_id !in socket_events) { socket_events[host_id] = table(); }
}

event osquery::host_disconnected(host_id: string) {
	# Set host and state not fresh
	host_freshness[host_id] = F;
	if (host_id !in socket_events_freshness) { socket_events_freshness[host_id] = table(); }
	for ([pid, fd] in socket_events_freshness[host_id]) {
		socket_events_freshness[host_id][pid, fd] = F;
	}

	# Schedule removal of host
	schedule osquery::STATE_REMOVAL_DELAY { osquery::state::sockets::scheduled_remove_host(host_id) };
}
