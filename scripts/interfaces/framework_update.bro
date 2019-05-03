#! Update the framework with interface state.

module osquery::updating::state_interfaces;

event osquery::interface_state_added(host_id: string, name: string, mac: string, addr_info: osquery::AddrInfo) {
	hook osquery::add_host_addr(host_id, addr_info$ip);
}

event osquery::interface_state_removed(host_id: string, name: string, mac: string, addr_info: osquery::AddrInfo) {
	hook osquery::remove_host_addr(host_id, addr_info$ip);
}
