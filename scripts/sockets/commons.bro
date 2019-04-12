#! Provide socket state commons

module osquery;

export {
	## Event when added to the state of sockets
	##
	## <params missing>
	global socket_state_added: event(host_id: string, socket_info: SocketInfo);
	
	## Event when removing a host from the state of sockets
	##
	## <params missing>
	global socket_host_state_removed: event(host_id: string);
	
	## Event when removing from the state of sockets
	##
	## <params missing>
	global socket_state_removed: event(host_id: string, socket_info: SocketInfo);
}

module osquery::state::sockets;

export {
	type SocketState: table[string] of table[int, int] of vector of osquery::SocketInfo;

	# Table to access SocketInfo by HostID
	global process_open_sockets: SocketState = table();
	global socket_events: SocketState = table();
	global listening_ports: SocketState = table();

	# Table to indicate freshness of SocketInfo by HostID
	global socket_events_freshness: table[string] of table[int, int] of bool;

	# Table to indicate freshness of hosts by HostID
	global host_freshness: table[string] of bool;

	# Set of HostID that have maintenance scheduled
	global host_maintenance: set[string];

	# Add an entry to the socket state
	global add_entry: function(host_id: string, pid: int, fd: int, connection_tuple: osquery::ConnectionTuple, state: string, path: string, family: int, start_time: int, success: int);

	# Remove entries with the ConnectionTuple from the socket state
	global remove_entry: function(host_id: string, pid: int, fd: int, state: string);

	# Remove all entries for host from the socket state
	global remove_host: function(host_id: string);
}

global scheduled_remove: event(host_id: string, pid: int, fd: int, state: string);

function add_entry(host_id: string, pid: int, fd: int, connection_tuple: osquery::ConnectionTuple, state: string, path: string, family: int, start_time: int, success: int) {
	local socket_info: osquery::SocketInfo = [$pid=pid, $fd=fd, $connection=connection_tuple, $state=state];
	if (path != "") { socket_info$path = path; }
	if (family != -1) { socket_info$family = family; }
	if (start_time != -1) { socket_info$start_time = start_time; }
	if (success != -1) { socket_info$success = success; }

	local sockets: SocketState;
	if (state == "established") { sockets = process_open_sockets; }
	if (state == "listening") { sockets = listening_ports; }
	if (state == "connect" || state == "bind" ) { sockets = socket_events; }

	# Insert into state
	if (host_id in sockets) {
		if ([pid, fd] in sockets[host_id]) {
			sockets[host_id][pid, fd][|sockets[host_id][pid, fd]|] = socket_info;
		} else {
			sockets[host_id][pid, fd] = vector(socket_info);
		}
	} else {
		sockets[host_id] = table([pid, fd] = vector(socket_info));
	}


	# Set fresh
	if (state == "connect" || state == "bind") {
		socket_events_freshness[host_id][pid, fd] = T;
	}
	# Schedule removal of overriden event entry
	if (|sockets[host_id][pid, fd]| > 1) {
		schedule 30sec { osquery::state::sockets::scheduled_remove(host_id, pid, fd, state) };
	}
	event osquery::socket_state_added(host_id, socket_info);
}

function remove_entry(host_id: string, pid: int, fd: int, state: string) {
	local sockets: SocketState;
	if (state == "established") { sockets = process_open_sockets; }
	if (state == "listening") { sockets = listening_ports; }
	if (state == "connect" || state == "bind" ) { sockets = socket_events; }

	# Check if socket exists
	if (host_id !in sockets) { return; }
	if ([pid, fd] !in sockets[host_id]) { return; }
	if (|sockets[host_id][pid,fd]| == 0) { return; }

	# Check if socket event is fresh
	if (state == "connect" || state == "bind") {
		if (|sockets[host_id][pid, fd]| == 1 && socket_events_freshness[host_id][pid, fd]) { return; }
	}

	# Remove from state
	local socket_info = sockets[host_id][pid, fd][0];
	local socket_infos: vector of osquery::SocketInfo = vector();
	for (idx in sockets[host_id][pid, fd]) {
		if (idx == 0) { next; }
		socket_infos += sockets[host_id][pid, fd][idx];
	}
	sockets[host_id][pid, fd] = socket_infos;

	# Remove freshness
	if (state == "connect" || state == "bind") {
		if (|sockets[host_id][pid, fd]| == 0) {
			delete socket_events_freshness[host_id][pid, fd];
		}
	}
	event osquery::socket_state_removed(host_id, socket_info);
}

function remove_host(host_id: string) {
	if (host_id !in process_open_sockets && host_id !in listening_ports && host_id !in socket_events) { return; }

	local sockets_vec: vector of SocketState = vector(process_open_sockets, listening_ports, socket_events);
	local sockets: SocketState;
	for (idx in sockets_vec) {
		sockets = sockets_vec[idx];
		if (host_id !in sockets) { next; }

		for ([pid, fd] in sockets[host_id]) {
			for (idx in sockets[host_id][pid, fd]) {
				event osquery::socket_state_removed(host_id, sockets[host_id][pid, fd][idx]);
			}
		}
		delete sockets[host_id];
	}
}
