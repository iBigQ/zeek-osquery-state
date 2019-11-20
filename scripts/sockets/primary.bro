#! Provide current socket information about hosts.

@load zeek-osquery-framework
@load zeek-osquery-queries/tables/listening_ports
@load zeek-osquery-queries/tables/process_open_sockets
#@load zeek-osquery-queries/tables/socket_events

module osquery::state::sockets;

event osquery::state::sockets::scheduled_remove(t: time, host_id: string, pid: int, fd: int, state: string, oldest: bool) {
	# Select table
	local deleting_sockets: DeletingSocketState;
	if (state == "established") { deleting_sockets = deleting_established; }
	if (state == "listening") { deleting_sockets = deleting_listening; }
	if (state == "connect" || state == "bind" ) { deleting_sockets = deleting_events; }

	# Verify scheduled deletes
	if (host_id !in deleting_sockets) {
		#print fmt("Scheduled remove for process but host state already deleted");
		return;
	}
	if ([pid, fd] !in deleting_sockets[host_id]) {
		#print fmt("Scheduled remove for process but no deleting counter for pid");
		return;
	}

	# Decrease scheduled deletes
	deleting_sockets[host_id][pid, fd] -= 1;
	if (deleting_sockets[host_id][pid, fd] == 0) {
		delete deleting_sockets[host_id][pid, fd];
	}

	# Last event
	#if (ev && !oldest) {
	#	# Event became fresh
	#	if (pid !in socket_events_freshness[host_id]) { return; }
	#	if (socket_events_freshness[host_id][pid] != freshness) { return; }
	#	delete socket_events_freshness[host_id][pid];
	#}

	# Delete
	remove_entry(t, current_time(), host_id, pid, fd, state, oldest);
}

function schedule_remove(t: time, host_id: string, pid: int, fd: int, state: string, oldest: bool) {
	# Select table
	local deleting_sockets: DeletingSocketState;
	if (state == "established") { deleting_sockets = deleting_established; }
	if (state == "listening") { deleting_sockets = deleting_listening; }
	if (state == "connect" || state == "bind" ) { deleting_sockets = deleting_events; }
	
	# Verify removal of last event item
	local skip = F;
	local ev = F;
	if (state == "connect" || state == "bind" ) { ev = T; }
	if (ev && !oldest) {
		if (host_id !in deleting_events) {
			print fmt("Unable to verify removal of last socket event item because host state already deleted");
			skip = T;
		} else if ([pid, fd] !in socket_events[host_id] || |socket_events[host_id][pid, fd]| == 0) {
			print fmt("Indicator for removal of last socket event is incorrect because no events remaining");
			skip = T;
		} else if ([pid, fd] !in deleting_events[host_id] && |socket_events[host_id][pid, fd]| != 1) {
			print fmt("Indicator for removal of last socket event is incorrect because only one event was expected");
			skip = T;
		} else if ([pid, fd] in deleting_events[host_id] && |socket_events[host_id][pid, fd]| - deleting_events[host_id][pid, fd] != 1) {
			print fmt("Indicator for removal of last socket event is incorrect because not excatly one event remaining");
			skip = T;
		}
	}

	# Increase scheduled deletes
	if (host_id !in deleting_sockets) { deleting_sockets[host_id] = table(); }
	if ([pid, fd] in deleting_sockets[host_id]) { 
		deleting_sockets[host_id][pid, fd] += 1; 
	} else {
		deleting_sockets[host_id][pid, fd] = 0; 
	}

	# Schedule delete
	#if (skip) { return; }
	schedule osquery::STATE_REMOVAL_DELAY { osquery::state::sockets::scheduled_remove(t, host_id, pid, fd, state, oldest) };
}

function _add_event(t: time, host_id: string, pid: int, fd: int, connection_tuple: osquery::ConnectionTuple, state: string, path: string, family: int, success: int) {
	add_entry(t, host_id, pid, fd, connection_tuple, state, path, family, success);

	# Schedule removal of overriden event entry
	if ([pid, fd] !in deleting_events[host_id]) { deleting_events[host_id][pid, fd] = 0; }
	if (deleting_events[host_id][pid, fd] + 1 < |socket_events[host_id][pid, fd]|) {
		schedule_remove(t, host_id, pid, fd, state, T);
	}

	# Set fresh
	if ([pid, fd] in socket_events_freshness[host_id]) {
		delete socket_events_freshness[host_id][pid, fd];
	}
}

event osquery::state::sockets::initial_process_open_socket(resultInfo: osquery::ResultInfo, pid: int, fd: int, family: int, protocol: int, local_address: string, remote_address: string, local_port: int, remote_port: int) {
	local path: string = "";
	local success: int = 1;
	local state: string = "connect";
	local connection_tuple = osquery::create_connection_tuple(local_address, remote_address, local_port, remote_port, protocol);
	_add_event(network_time(), resultInfo$host, pid, fd, connection_tuple, state, path, family, success);
}

event osquery::state::sockets::initial_listening_port(resultInfo: osquery::ResultInfo, pid: int, fd: int, family: int, socket: int, protocol: int, local_address: string, local_port: int) {
	local path: string = "";
	local success: int = 1;
	local state: string = "bind";
	local remote_address = "";
	local remote_port = -1;
	local connection_tuple = osquery::create_connection_tuple(local_address, remote_address, local_port, remote_port, protocol);
	_add_event(network_time(), resultInfo$host, pid, fd, connection_tuple, state, path, family, success);
}

event osquery::process_open_socket_added(t: time, host_id: string, pid: int, fd: int, family: int, protocol: int, local_address: string, remote_address: string, local_port: int, remote_port: int) {
	local path: string = "";
	local success: int = 1;
	local state: string = "established";
	local connection_tuple = osquery::create_connection_tuple(local_address, remote_address, local_port, remote_port, protocol);
	add_entry(t, host_id, pid, fd, connection_tuple, state, path, family, success);
}

event osquery::listening_port_added(t: time, host_id: string, pid: int, fd: int, family: int, socket: int, protocol: int, local_address: string, local_port: int) {
	local path: string = "";
	local success: int = 1;
	local state: string = "listening";
	local remote_address = "";
	local remote_port = -1;
	local connection_tuple = osquery::create_connection_tuple(local_address, remote_address, local_port, remote_port, protocol);
	add_entry(t, host_id, pid, fd, connection_tuple, state, path, family, success);
}

event osquery::socket_event_added(t: time, host_id: string, action: string, pid: int, fd: int, path: string, family: int, protocol: int, local_address: string, remote_address: string, local_port: int, remote_port: int, start_time: int, success: int) {
	local connection_tuple = osquery::create_connection_tuple(local_address, remote_address, local_port, remote_port, protocol);
	_add_event(t, host_id, pid, fd, connection_tuple, action, path, family, success);
}

event osquery::process_open_socket_removed(t: time, host_id: string, pid: int, fd: int, family: int, protocol: int, local_address: string, remote_address: string, local_port: int, remote_port: int) {
	local state: string = "established";
	# Schedule remove
	schedule_remove(t, host_id, pid, fd, state, T);
}

event osquery::listening_port_removed(t: time, host_id: string, pid: int, fd: int, family: int, socket: int, protocol: int, local_address: string, local_port: int) {
	local state: string = "listening";
	# Schedule remove
	schedule_remove(t, host_id, pid, fd, state, T);
}

event osquery::state::sockets::scheduled_remove_host(t: time, host_id: string, cookie: string) {
	# Verify host freshness
	if (host_freshness[host_id] != cookie) { return; }
	delete host_freshness[host_id];
	if (host_id in connect_balance) { delete connect_balance[host_id]; }
	if (host_id in host_maintenance) { delete host_maintenance[host_id]; }
	if (host_id in deleting_established) { delete deleting_established[host_id]; }
	if (host_id in deleting_listening) { delete deleting_listening[host_id]; }
	if (host_id in deleting_events) { delete deleting_events[host_id]; }
	if (host_id in socket_events_freshness) { delete socket_events_freshness[host_id]; }
	local now = current_time();

	# Indicate state changes
	event osquery::socket_host_state_removed(t, now, host_id);
	Broker::publish(Cluster::worker_topic, Broker::make_event(osquery::socket_host_state_removed, t, now, host_id));
	remove_host(t, now, host_id);
}

event osquery::state::sockets::state_outdated(resultInfo: osquery::ResultInfo, pid_str: string, fd_str: string, state: string) {
	local pid = to_int(pid_str);
	local fd = to_int(fd_str);
	local host_id = resultInfo$host;

	# Verify freshness
	if (host_id !in socket_events_freshness) { return; }
	if ([pid, fd] !in socket_events_freshness[host_id]) { return; }
	if (socket_events_freshness[host_id][pid, fd] != resultInfo$cookie) { return; }
	delete socket_events_freshness[host_id][pid, fd];

	# Schedule remove
	#print("State Outdated");
	schedule_remove(network_time(), host_id, pid, fd, state, F);
}

function send_maintenance_chunk(host_id: string, select_vec: vector of string, socket_type: string, cookie: string) {
	local table_name: string;
	if (socket_type == "bind") { table_name = "listening_ports"; }
	else if (socket_type == "connect") { table_name = "process_open_sockets"; }
	else { return; }
	
	if (|select_vec| != 0) {
		# Select query
		local query_string = fmt("SELECT x, y, '%s' FROM (%s) WHERE (x, y) NOT IN (SELECT pid, fd FROM %s)", socket_type, join_string_vec(select_vec, " UNION "), table_name);
		#local query_string = fmt("SELECT x, y, '%s' FROM (%s) AS b LEFT JOIN (SELECT pid, fd FROM %s WHERE family = 2 AND pid != -1) AS o ON b.x = o.pid AND b.y = o.fd WHERE o.pid IS NULL", socket_type, join_string_vec(select_vec, " UNION "), table_name);
	
		# Send query
		local query = [$ev=osquery::state::sockets::state_outdated, $query=query_string, $cookie=cookie];
		osquery::execute(query, host_id);
	}
}

event osquery::state::sockets::verify(host_id: string) {
	local select_binds: vector of string = vector();
	local select_connects: vector of string = vector();

	# Host successfully removed from state
	if (host_id !in host_freshness) { 
		# Stop further verifies
		delete host_maintenance[host_id];
		return; 
	}

	# Skip if host is offline or no state
	if (host_freshness[host_id] != "" || host_id !in socket_events) { 
		schedule osquery::STATE_MAINTENANCE_INTERVAL { osquery::state::sockets::verify(host_id) };
		return; 
	}

	# Collect event socket state
	local bind_count = 0;
	local connect_count = 0;
	local len: count;
	local r = cat(rand(0xffffffffffffffff));
	for ([pid, fd] in socket_events[host_id]) {
		# Number of state entries
		len = |socket_events[host_id][pid, fd]|;
		if (len == 0) { next; }

		# Already deleting?
		if ([pid, fd] !in deleting_events[host_id]) {
			deleting_events[host_id][pid, fd] = 0;
		}
		if (deleting_events[host_id][pid, fd] >= |socket_events[host_id][pid, fd]|) {
			next;
		}

		# Update freshness
		socket_events_freshness[host_id][pid,fd] = r;

		# Verify bind
		if (socket_events[host_id][pid, fd][len-1]$state == "bind") {
			select_binds += fmt("SELECT %d AS x, %d AS y", pid, fd);
			bind_count += 1;
			if (bind_count >= osquery::MAX_VALIDATION_SELECT) {
				send_maintenance_chunk(host_id, select_binds, "bind", r);
				select_binds = vector();
				bind_count = 0;
			}
		# Verify connect
		} else if (socket_events[host_id][pid, fd][len-1]$state == "connect") {
			select_connects += fmt("SELECT %d AS x, %d AS y", pid, fd);
			connect_count += 1;
			if (connect_count >= osquery::MAX_VALIDATION_SELECT) {
				send_maintenance_chunk(host_id, select_connects, "connect", r);
				select_connects = vector();
				connect_count = 0;
			}
		}

	}

	# Verify last chunks
	send_maintenance_chunk(host_id, select_binds, "bind", r);
	send_maintenance_chunk(host_id, select_connects, "connect", r);
	
	# Schedule next verification
	schedule osquery::STATE_MAINTENANCE_INTERVAL { osquery::state::sockets::verify(host_id) };

}

function _remove_legacy(t: time, host_id: string, sockets: SocketState, deleting_sockets: DeletingSocketState, state: string) {
	# Check host
	if (host_id !in sockets) { return; }
	if (host_id !in deleting_sockets) { deleting_sockets[host_id] = table(); }
	local ev = F;
	if (state == "connect" || state == "bind" ) { ev = T; }
	local oldest: bool;

	# Iterate ProcessID/FD
	for ([pid, fd] in sockets[host_id]) {
		if (|sockets[host_id][pid, fd]| == 0) { next; }
		if ([pid,fd] !in deleting_sockets[host_id]) { 
			deleting_sockets[host_id][pid, fd] = 0; 
		}
		# Remove remaining state
		oldest = T;
		while (deleting_sockets[host_id][pid, fd] < |sockets[host_id][pid, fd]|) {
			if (ev && deleting_sockets[host_id][pid, fd] + 1 == |sockets[host_id][pid, fd]|) {
				# Last event
				oldest = F;
				#print("Remove legacy");
			}
			schedule_remove(t, host_id, pid, fd, state, oldest);
		}
		if (ev && [pid, fd] in socket_events_freshness[host_id]) {
			delete socket_events_freshness[host_id][pid, fd];
		}
	}
}

function remove_legacy(t: time, host_id: string) {
	# Established Legacy
	_remove_legacy(t, host_id, process_open_sockets, deleting_established, "established");
	# Listening Legacy
	_remove_legacy(t, host_id, listening_ports, deleting_listening, "listening");
	# Events Legacy
	_remove_legacy(t, host_id, socket_events, deleting_events, "connect");
}

event osquery::host_connected(host_id: string) {
	# Initialize state
	if (host_id !in process_open_sockets) { process_open_sockets[host_id] = table(); }
	if (host_id !in listening_ports) { listening_ports[host_id] = table(); }
	if (host_id !in socket_events) { socket_events[host_id] = table(); }
	if (host_id !in deleting_established) { deleting_established[host_id] = table(); }
	if (host_id !in deleting_listening) { deleting_listening[host_id] = table(); }
	if (host_id !in deleting_events) { deleting_events[host_id] = table(); }
	if (host_id !in socket_events_freshness) { socket_events_freshness[host_id] = table(); }

	# Update freshnes
	host_freshness[host_id] = "";

	# First connect
	if (host_id !in connect_balance) {
		connect_balance[host_id] = 0;
	}
	# Remove legacy
	if (connect_balance[host_id] >= 0) {
		remove_legacy(network_time(), host_id);
	}
	# Update balance
	connect_balance[host_id] += 1;

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
}

event osquery::host_disconnected(host_id: string) {
	# Update balance
	connect_balance[host_id] -= 1;
	# - Last disconnect
	if (connect_balance[host_id] == 0) {
		local t = network_time();
		# Schedule removal of host
		host_freshness[host_id] = cat(rand(0xffffffffffffffff));
		schedule osquery::STATE_REMOVAL_DELAY { osquery::state::sockets::scheduled_remove_host(t, host_id, host_freshness[host_id]) };
		# Remove legacy
		remove_legacy(t, host_id);
	}
}
