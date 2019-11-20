#! Provide socket state commons

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

	## Event when added to the state of sockets
	##
	## <params missing>
	global socket_state_added: event(t: time, host_id: string, socket_info: SocketInfo);
	
	## Event when removing a host from the state of sockets
	##
	## <params missing>
	global socket_host_state_removed: event(t: time, now: time, host_id: string);
	
	## Event when removing from the state of sockets
	##
	## <params missing>
	global socket_state_removed: event(t: time, now: time, host_id: string, socket_info: SocketInfo);
}

module osquery::state::sockets;

export {
	type SocketState: table[string] of table[int, int] of vector of osquery::SocketInfo;
	type DeletingSocketState: table[string] of table[int, int] of count;

	# Table to access SocketInfo by HostID
	global process_open_sockets: SocketState = table();
	global socket_events: SocketState = table();
	global listening_ports: SocketState = table();
}


