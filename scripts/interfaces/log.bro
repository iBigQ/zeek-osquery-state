#! Logs interface state activity.

module osquery::logging::state_interfaces;

export {
	# Logging
        redef enum Log::ID += { LOG };

        type Info: record {
                host: string &log;
		added: bool &log;
                name: string &log;
                mac: string &log;
                ip: addr &log;
                mask: string &log &optional;
        };
}

@if ( !Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
event osquery::interface_state_added(host_id: string, name: string, mac: string, addr_info: osquery::AddrInfo) {
        local info: Info = [
		$host = host_id,
		$added = T,
               	$name = name,
		$mac = mac,
		$ip = addr_info$ip
	];
        if (addr_info?$mask) { info$mask = addr_info$mask; }

        Log::write(LOG, info);
}

event osquery::interface_state_removed(host_id: string, name: string, mac: string, addr_info: osquery::AddrInfo) {
        local info: Info = [
		$host = host_id,
		$added = F,
               	$name = name,
		$mac = mac,
		$ip = addr_info$ip
	];
        if (addr_info?$mask) { info$mask = addr_info$mask; }

        Log::write(LOG, info);
}
@endif

event bro_init() {
        Log::create_stream(LOG, [$columns=Info, $path="osq-interface-state"]);
}
