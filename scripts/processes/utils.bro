#! Provide process state utils

module osquery;

export {
	## Check if two process infos have equal keys
	##
	## <params missing>
	global equalProcessKeys: function(proc1: ProcessInfo, proc2: ProcessInfo): bool;


	## Check if two process infos are equal
	##
	## <params missing>
	global equalProcessInfos: function(proc1: ProcessInfo, proc2: ProcessInfo): bool;
}

function equalProcessKeys(proc1: ProcessInfo, proc2: ProcessInfo): bool {
	if (proc1$pid != proc2$pid) {
		return F;
	}
	return T;
}

function equalProcessInfos(proc1: ProcessInfo, proc2: ProcessInfo): bool {
	if (!equalProcessKeys(proc1, proc2)) {
		return F;
	}
	if (proc1$ev != proc2$ev) {
		return F;
	}
	if (proc1?$name != proc2?$name) {
		return F;
	}
	if (proc1?$name && proc1$name != proc2$name) {
		return F;
	}
	if (proc1?$path != proc2?$path) {
		return F;
	}
	if (proc1?$path && proc1$path != proc2$path) {
		return F;
	}
	if (proc1?$cmdline != proc2?$cmdline) {
		return F;
	}
	if (proc1?$cmdline && proc1$cmdline != proc2$cmdline) {
		return F;
	}
	if (proc1?$uid != proc2?$uid) {
		return F;
	}
	if (proc1?$uid && proc1$uid != proc2$uid) {
		return F;
	}
	if (proc1?$parent != proc2?$parent) {
		return F;
	}
	if (proc1?$parent && proc1$parent != proc2$parent) {
		return F;
	}
	return T;
}
