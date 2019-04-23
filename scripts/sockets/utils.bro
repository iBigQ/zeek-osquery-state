#! Provide socket state utils

module osquery;

export {
	type ConnectionTuple: record {
		local_address: addr &optional;
		remote_address: addr &optional;
		local_port: int &optional;
		remote_port: int &optional;
		protocol: int &optional;
	};

	type SocketInfo: record {
		pid: int;
		fd: int;
		connection: ConnectionTuple &default=[];
		state: string;
		path: string &optional;
		family: int &optional;
		success: int &optional;
	};

	## Checks if the connection is described by the connection pattern
	##
	## <params missing>
	global matchConnectionTuplePattern: function(conn: ConnectionTuple, conn_pattern: ConnectionTuple): bool;

	## Check if two socket infos have equal keys
	##
	## <params missing>
	global equalSocketKeys: function(sock1: SocketInfo, sock2: SocketInfo): bool;

	## Check if two socket infos are equal
	##
	## <params missing>
	global equalSocketInfos: function(sock1: SocketInfo, sock2: SocketInfo): bool;

	## Converts from a connection type to ConnectionTuple type
	##
	## <params missing>
	global convert_conn_to_conntuple: function(c: connection, reverse: bool): ConnectionTuple;

	## Creates a ConnectionTuple from given parameters
	##
	## <params missing>
	global create_connection_tuple: function(local_address: string, remote_address: string, local_port: int, remote_port: int, protocol: int): ConnectionTuple;
}

function convert_conn_to_conntuple(c: connection, reverse: bool): ConnectionTuple {
	local local_port: int = port_to_count(c$id$orig_p) + 0;
	local remote_port: int = port_to_count(c$id$resp_p) + 0;
	local proto = -1;
	local proto_type = get_port_transport_proto(c$id$orig_p);
	if (proto_type == tcp) { proto = 6; }
	else if (proto_type == udp) { proto = 17; }

	if (reverse) {
		return [$local_address=c$id$resp_h, $remote_address=c$id$orig_h, $local_port=remote_port, $remote_port=local_port, $protocol=proto];
	}

	return [$local_address=c$id$orig_h, $remote_address=c$id$resp_h, $local_port=local_port, $remote_port=remote_port, $protocol=proto];
}

function equalConnectionTuples(conn1: ConnectionTuple, conn2: ConnectionTuple): bool {
	if (conn1?$local_address != conn2?$local_address) {
		return F;
	}
	if (conn1?$local_address && conn1$local_address != conn2$local_address) {
		return F;
	}
	if (conn1?$remote_address != conn2?$remote_address) {
		return F;
	}
	if (conn1?$remote_address && conn1$remote_address != conn2$remote_address) {
		return F;
	}
	if (conn1?$local_port != conn2?$local_port) {
		return F;
	}
	if (conn1?$local_port && conn1$local_port != conn2$local_port) {
		return F;
	}
	if (conn1?$remote_port != conn2?$remote_port) {
		return F;
	}
	if (conn1?$remote_port && conn1$remote_port != conn2$remote_port) {
		return F;
	}
	if (conn1?$protocol != conn2?$protocol) {
		return F;
	}
	if (conn1?$protocol && conn1$protocol != conn2$protocol) {
		return F;
	}
	return T;
}

function matchConnectionTuplePattern(conn: ConnectionTuple, conn_pattern: ConnectionTuple): bool {
	if (conn_pattern?$local_address && conn_pattern$local_address != 0.0.0.0 && (!conn?$local_address || conn$local_address != conn_pattern$local_address)) {
		return F;
	}
	if (conn_pattern?$remote_address && conn_pattern$remote_address != 0.0.0.0 && (!conn?$remote_address || conn$remote_address != conn_pattern$remote_address)) {
		return F;
	}
	if (conn_pattern?$local_port && conn_pattern$local_port != 0 && (!conn?$local_port || conn$local_port != conn_pattern$local_port)) {
		return F;
	}
	if (conn_pattern?$remote_port && conn_pattern$remote_port != 0 && (!conn?$remote_port || conn$remote_port != conn_pattern$remote_port)) {
		return F;
	}
	if (conn_pattern?$protocol && conn_pattern$protocol != 0 && (!conn?$protocol || conn$protocol != conn_pattern$protocol)) {
		return F;
	}
	return T;
}

function equalSocketKeys(sock1: SocketInfo, sock2: SocketInfo): bool {
	if (sock1$pid != sock2$pid) {
		return F;
	}
	if (sock1$fd != sock2$fd) {
		return F;
	}
	return T;
}

function equalSocketInfos(sock1: SocketInfo, sock2: SocketInfo): bool {
	if (!equalSocketKeys(sock1, sock2)) {
		return F;
	}
	if (sock1$state != sock2$state) {
		return F;
	}
	if (!equalConnectionTuples(sock1$connection, sock2$connection)) {
		return F;
	}
	if (sock1?$path != sock2?$path) {
		return F;
	}
	if (sock1?$path && sock1$path != sock2$path) {
		return F;
	}
	if (sock1?$family != sock2?$family) {
		return F;
	}
	if (sock1?$family && sock1$family != sock2$family) {
		return F;
	}
	if (sock1?$success != sock2?$success) {
		return F;
	}
	if (sock1?$success && sock1$success != sock2$success) {
		return F;
	}
	return T;
}

function create_connection_tuple(local_address: string, remote_address: string, local_port: int, remote_port: int, protocol: int): ConnectionTuple {
	local connection_tuple: ConnectionTuple = [];
	if (local_address != "") { connection_tuple$local_address = to_addr(local_address); }
	if (remote_address != "") { connection_tuple$remote_address = to_addr(remote_address); }
	if (local_port != -1) { connection_tuple$local_port = local_port; }
	if (remote_port != -1) { connection_tuple$remote_port = remote_port; }
	if (protocol != -1) { connection_tuple$protocol = protocol; }

	return connection_tuple;
}
