#! Provide interface state utils

module osquery;

export {
	## Check if two interface infos have equal keys
	##
	## <params missing>
	global equalInterfaceKeys: function(interface1: InterfaceInfo, interface2: InterfaceInfo): bool;


	## Check if two process infos are equal
	##
	## <params missing>
	global equalInterfaceInfos: function(interface1: InterfaceInfo, interface2: InterfaceInfo): bool;
}

function equalInterfaceKeys(interface1: InterfaceInfo, interface2: InterfaceInfo): bool {
	if (interface1$name != interface2$name) {
		return F;
	}
	if (interface1$mac != interface2$mac) {
		return F;
	}
	if (interface1?$addr_info != interface2?$addr_info) {
		return F;
	}
	if (interface1?$addr_info && interface1$addr_info$ip != interface2$addr_info$ip) {
		return F;
	}
	return T;
}

function equalInterfaceInfos(interface1: InterfaceInfo, interface2: InterfaceInfo): bool {
	if (!equalInterfaceKeys(interface1, interface2)) {
		return F;
	}
	if (interface1?$addr_info != interface2?$addr_info) {
		return F;
	}
	if (interface1?$addr_info && interface1$addr_info$mask != interface2$addr_info$mask) {
		return F;
	}
	return T;
}
