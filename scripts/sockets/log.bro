#! Logs socket state activity.

module osquery::logging::state_sockets;

export {
	# Logging
        redef enum Log::ID += { LOG };

        type Info: record {
                t: time &log;
                t_effective: time &log &optional;
                host: string &log;
		added: bool &log;
                pid: int &log;
		fd: int &log;
		state: string &log;
		local_addr: addr &log &optional;
		remote_addr: addr &log &optional;
		local_port: int &log &optional;
		remote_port: int &log &optional;
		protocol: int &log &optional;
                path: string &log &optional;
		family: int &log &optional;
		success: int &log &optional;
        };
}

@if ( !Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
event osquery::socket_state_added(t: time, host_id: string, socket_info: osquery::SocketInfo) {
        local info: Info = [
		$t = t,
		$host = host_id,
		$added = T,
               	$pid = socket_info$pid,
               	$fd = socket_info$fd,
               	$state = socket_info$state
	];
	if (socket_info$connection?$local_address) { info$local_addr = socket_info$connection$local_address; }
	if (socket_info$connection?$remote_address) { info$remote_addr = socket_info$connection$remote_address; }
	if (socket_info$connection?$local_port) { info$local_port = socket_info$connection$local_port; }
	if (socket_info$connection?$remote_port) { info$remote_port = socket_info$connection$remote_port; }
	if (socket_info$connection?$protocol) { info$protocol = socket_info$connection$protocol; }
	if (socket_info?$path) { info$path = socket_info$path; }
	if (socket_info?$family) { info$family = socket_info$family; }
	if (socket_info?$success) { info$success = socket_info$success; }

        Log::write(LOG, info);
}

event osquery::socket_state_removed(t: time, now: time, host_id: string, socket_info: osquery::SocketInfo) {
        local info: Info = [
		$t = t,
		$t_effective = now,
		$host = host_id,
		$added = F,
               	$pid = socket_info$pid,
               	$fd = socket_info$fd,
               	$state = socket_info$state
	];
	if (socket_info$connection?$local_address) { info$local_addr = socket_info$connection$local_address; }
	if (socket_info$connection?$remote_address) { info$remote_addr = socket_info$connection$remote_address; }
	if (socket_info$connection?$local_port) { info$local_port = socket_info$connection$local_port; }
	if (socket_info$connection?$remote_port) { info$remote_port = socket_info$connection$remote_port; }
	if (socket_info$connection?$protocol) { info$protocol = socket_info$connection$protocol; }
	if (socket_info?$path) { info$path = socket_info$path; }
	if (socket_info?$family) { info$family = socket_info$family; }
	if (socket_info?$success) { info$success = socket_info$success; }

        Log::write(LOG, info);
}
@endif

event bro_init() {
        Log::create_stream(LOG, [$columns=Info, $path="osq-socket-state"]);
}
