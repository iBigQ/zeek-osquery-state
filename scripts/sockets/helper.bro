#! Provide socket state helper

#module osquery;
#@if ( Cluster::local_node_type() == Cluster::MANAGER )
## Manager need ability to forward state to workers.
#event zeek_init() {
#	Broker::auto_publish(Cluster::worker_topic, osquery::socket_state_added);
#	Broker::auto_publish(Cluster::worker_topic, osquery::socket_host_state_removed);
#	Broker::auto_publish(Cluster::worker_topic, osquery::socket_state_removed);
#}
#@endif

module osquery::state::sockets;

export {
	# Table to access number of scheduled deletes by HostID and UserID
	global deleting_established: DeletingSocketState;
	global deleting_listening: DeletingSocketState;
	global deleting_events: DeletingSocketState;

	# Table to count the balance of connects by HostID
	global connect_balance: table[string] of count;

	# Table to indicate freshness of SocketInfo by HostID and ProcessID/FD
	global socket_events_freshness: table[string] of table[int, int] of string;

	# Table to indicate freshness of hosts by HostID
	global host_freshness: table[string] of string;

	# Set of HostID that have maintenance scheduled
	global host_maintenance: set[string];

	# Add an entry to the socket state
	global add_entry: function(host_id: string, pid: int, fd: int, connection_tuple: osquery::ConnectionTuple, state: string, path: string, family: int, success: int);

	# Remove entries with the ConnectionTuple from the socket state
	global remove_entry: function(host_id: string, pid: int, fd: int, state: string, oldest: bool);

	# Remove all entries for host from the socket state
	global remove_host: function(host_id: string);
}

global scheduled_remove: event(host_id: string, pid: int, fd: int, state: string, oldest: bool);

function add_entry(host_id: string, pid: int, fd: int, connection_tuple: osquery::ConnectionTuple, state: string, path: string, family: int, success: int) {
	local socket_info: osquery::SocketInfo = [$pid=pid, $fd=fd, $connection=connection_tuple, $state=state];
	if (path != "") { socket_info$path = path; }
	if (family != -1) { socket_info$family = family; }
	if (success != -1) { socket_info$success = success; }

	# Select table
	local sockets: SocketState;
	if (state == "established") { sockets = process_open_sockets; }
	if (state == "listening") { sockets = listening_ports; }
	if (state == "connect" || state == "bind" ) { sockets = socket_events; }

	# Initialize
	if (host_id !in sockets) { sockets[host_id] = table(); }

	# Key already in state
	if ([pid, fd] in sockets[host_id]) {
		# Identify duplicates
		local new = T;
		for (idx in sockets[host_id][pid, fd]) {
			if (osquery::equalSocketInfos(socket_info, sockets[host_id][pid, fd][idx])) { new = F; }
		}
		# Raise event
		if (new) {
			event osquery::socket_state_added(host_id, socket_info);
			Broker::publish(Cluster::worker_topic, Broker::make_event(osquery::socket_state_added, host_id, socket_info));
		}
		# Save state
		sockets[host_id][pid, fd] += socket_info;
	# New key in state
	} else {
		# Raise event
		event osquery::socket_state_added(host_id, socket_info);
		Broker::publish(Cluster::worker_topic, Broker::make_event(osquery::socket_state_added, host_id, socket_info));
		sockets[host_id][pid, fd] = vector(socket_info);
	}
}

function remove_entry(host_id: string, pid: int, fd: int, state: string, oldest: bool) {
	# Select table
	local sockets: SocketState;
	if (state == "established") { sockets = process_open_sockets; }
	if (state == "listening") { sockets = listening_ports; }
	if (state == "connect" || state == "bind" ) { sockets = socket_events; }
	
	# Check if socket exists
	if (host_id !in sockets) { return; }
	if ([pid, fd] !in sockets[host_id]) { return; }
	if (|sockets[host_id][pid, fd]| == 0) { return; }

	# Asserts
	#local ev = F;
	#if (state == "connect" || state == "bind" ) { ev = T; }
	#if (ev) {
	#	if (oldest) {
	#		if (|sockets[host_id][pid, fd]| == 1) {
	#			print fmt("Only one socket despite oldest removal for PID %s FD %s on host %s", pid, fd, host_id);
	#		}
	#	} else {
	#		if (|sockets[host_id][pid, fd]| != 1) {
	#			print fmt("More than one socket despite latest removal for PID %s FD %s on host %s", pid, fd, host_id);
	#		}
	#	}
	#} else {
	#	if (!oldest) {
	#		print fmt("Latest socket removal despite no event for PID %s FD %s on host %s", pid, fd, host_id);
	#	}
	#}

	# Remove from state
	local socket_info = sockets[host_id][pid, fd][0];
	# Last item in state
	if (|sockets[host_id][pid, fd]| == 1) {
		# Raise event
		event osquery::socket_state_removed(host_id, socket_info);
		Broker::publish(Cluster::worker_topic, Broker::make_event(osquery::socket_state_removed, host_id, socket_info));
		# Delete state
		delete sockets[host_id][pid, fd];
	# Oldest item in state
	} else {
		local socket_infos: vector of osquery::SocketInfo = vector();
		# Identify duplicates
		local old = T;
		for (idx in sockets[host_id][pid, fd]) {
			if (idx == 0) { next; }
			socket_infos += sockets[host_id][pid, fd][idx];
			if (osquery::equalSocketInfos(socket_info, sockets[host_id][pid, fd][idx])) { old = F; }
		}
		# Raise event
		if (old) {
			event osquery::socket_state_removed(host_id, socket_info);
			Broker::publish(Cluster::worker_topic, Broker::make_event(osquery::socket_state_removed, host_id, socket_info));
		}
		# Save state
		sockets[host_id][pid, fd] = socket_infos;
	}
}

function remove_host(host_id: string) {
	# Check if host exists
	if (host_id !in process_open_sockets && host_id !in listening_ports && host_id !in socket_events) { return; }

	# Iterate state
	local sockets_vec: vector of SocketState = vector(process_open_sockets, listening_ports, socket_events);
	local sockets: SocketState;
	for (idx in sockets_vec) {
		sockets = sockets_vec[idx];
		if (host_id !in sockets) { next; }
		for ([pid, fd] in sockets[host_id]) {
			for (idx in sockets[host_id][pid, fd]) {
				# Raise event
				event osquery::socket_state_removed(host_id, sockets[host_id][pid, fd][idx]);
				Broker::publish(Cluster::worker_topic, Broker::make_event(osquery::socket_state_removed, host_id, sockets[host_id][pid, fd][idx]));
			}
		}

		# Delete state
		delete sockets[host_id];
	}
}
