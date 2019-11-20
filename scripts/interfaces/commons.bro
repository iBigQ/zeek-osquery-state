#! Provide interface state commons

module osquery;

export {
	type AddrInfo: record {
		ip: addr;
		mask: string &optional;
	};

	type InterfaceInfo: record {
		name: string;
		mac: string;
		addr_info: AddrInfo &optional;
		deleting: bool &default=F;
	};

	## Event when added to the state of interfaces
	##
	## <params missing>
	global interface_state_added: event(t: time, host_id: string, interface_info: InterfaceInfo);
	
	## Event when removing a host from the state of interfaces
	##
	## <params missing>
	global interface_host_state_removed: event(t: time, now: time, host_id: string);
	
	## Event when removing from the state of interfaces
	##
	## <params missing>
	global interface_state_removed: event(t: time, now: time, host_id: string, interface_info: InterfaceInfo);
}

module osquery::state::interfaces;

export {
	# Table to access InterfaceInfo by HostID and interface name
	global interfaces: table[string] of table[string] of vector of osquery::InterfaceInfo;
}
