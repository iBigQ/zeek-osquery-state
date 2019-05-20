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
                ip: addr &log &optional;
                mask: string &log &optional;
        };
}

@if ( !Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
event osquery::interface_state_added(host_id: string, interface_info: osquery::InterfaceInfo) {
        local info: Info = [
		$host = host_id,
		$added = T,
               	$name = interface_info$name,
		$mac = interface_info$mac
	];
        if (interface_info?$addr_info) { info$ip = interface_info$addr_info$ip; }
        if (interface_info?$addr_info && interface_info$addr_info?$mask) { info$mask = interface_info$addr_info$mask; }

        Log::write(LOG, info);
}

event osquery::interface_state_removed(host_id: string, interface_info: osquery::InterfaceInfo) {
        local info: Info = [
		$host = host_id,
		$added = F,
               	$name = interface_info$name,
		$mac = interface_info$mac
	];
        if (interface_info?$addr_info) { info$ip = interface_info$addr_info$ip; }
        if (interface_info?$addr_info && interface_info$addr_info?$mask) { info$mask = interface_info$addr_info$mask; }

        Log::write(LOG, info);
}
@endif

event bro_init() {
        Log::create_stream(LOG, [$columns=Info, $path="osq-interface-state"]);
}
