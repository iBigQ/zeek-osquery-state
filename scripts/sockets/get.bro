#! Provide access to socket information about hosts.

module osquery;

export {
	## Get the SocketInfos of a host by its id
	##
	## host_id: The identifier of the host
	global getSocketInfosByHostID: function(host_id: string): vector of SocketInfo;

	## Get the SocketInfos of a host by its id and PID
	##
	## host_id: The identifier of the host
	## pid: The identifier of the process
	global getSocketInfosByHostIDByPID: function(host_id: string, pid: int): vector of SocketInfo;

	## Get the SocketInfos of a host by its id
	##
	## host_id: The identifier of the host
	## connPattern: The pattern of a connection tuple
	global getSocketInfosByHostIDByConnectionTuple: function(host_id: string, connPattern: ConnectionTuple): vector of SocketInfo;

	## Get the SocketInfos of a host by its id
	##
	## connPattern: The pattern of a connection tuple
	global getSocketInfosByConnectionTuple: function(connPattern: ConnectionTuple): vector of SocketInfo;
}

function getSocketInfosByHostID(host_id: string): vector of SocketInfo {
	local socket_infos: vector of SocketInfo = vector();

	local sockets_vec: vector of osquery::state::sockets::SocketState = vector(osquery::state::sockets::process_open_sockets, osquery::state::sockets::listening_ports, osquery::state::sockets::socket_events);
	local sockets: osquery::state::sockets::SocketState;
	for (s_idx in sockets_vec) {
		sockets = sockets_vec[s_idx];
		if (host_id !in sockets) { next; }

		for ([pid, fd] in sockets[host_id]) {
			for (inf_idx in sockets[host_id][pid, fd]) {
				socket_infos += sockets[host_id][pid, fd][inf_idx];
			}
		}
	}

	return socket_infos;
}

function getSocketInfosByHostIDByPID(host_id: string, pid: int): vector of SocketInfo {
	local socket_infos: vector of SocketInfo = vector();

	local sockets_vec: vector of osquery::state::sockets::SocketState = vector(osquery::state::sockets::process_open_sockets, osquery::state::sockets::listening_ports, osquery::state::sockets::socket_events);
	local sockets: osquery::state::sockets::SocketState;
	for (s_idx in sockets_vec) {
		sockets = sockets_vec[s_idx];
		if (host_id !in sockets) { next; }

		for ([pid_i, fd] in sockets[host_id]) {
			if (pid_i != pid) { next; }
			for (inf_idx in sockets[host_id][pid, fd]) {
				socket_infos += sockets[host_id][pid, fd][inf_idx];
			}
		}
	}

	return socket_infos;
}

function getSocketInfosByHostIDByConnectionTuple(host_id: string, connPattern: ConnectionTuple): vector of SocketInfo {
	local socket_infos: vector of SocketInfo = vector();

	local sockets_vec: vector of osquery::state::sockets::SocketState = vector(osquery::state::sockets::process_open_sockets, osquery::state::sockets::listening_ports, osquery::state::sockets::socket_events);
	local sockets: osquery::state::sockets::SocketState;
	for (s_idx in sockets_vec) {
		sockets = sockets_vec[s_idx];
		if (host_id !in sockets) { next; }

		for ([pid, fd] in sockets[host_id]) {
			for (inf_idx in sockets[host_id][pid, fd]) {
				if (!matchConnectionTuplePattern(sockets[host_id][pid, fd][inf_idx]$connection, connPattern)) { next; }
				socket_infos += sockets[host_id][pid, fd][inf_idx];
			}
		}
	}

	return socket_infos;
}

function getSocketInfosByConnectionTuple(connPattern: ConnectionTuple):  vector of SocketInfo {
	local socket_infos: vector of SocketInfo = vector();
	local host_socket_infos: vector of SocketInfo;
	local host_ids: set[string] = set();

	# Collect host IDs
	local sockets_vec: vector of osquery::state::sockets::SocketState = vector(osquery::state::sockets::process_open_sockets, osquery::state::sockets::listening_ports, osquery::state::sockets::socket_events);
	local sockets: osquery::state::sockets::SocketState;
	for (s_idx in sockets_vec) {
		for (host_id in sockets_vec[s_idx]) {
			add host_ids[host_id];
		}
	}

	for (host_id in host_ids) {
		host_socket_infos = getSocketInfosByHostIDByConnectionTuple(host_id, connPattern);
		for (inf_idx in host_socket_infos) {
			socket_infos += host_socket_infos[inf_idx];
		}
	}
	
	return socket_infos;
}
