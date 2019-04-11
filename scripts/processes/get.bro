#! Provide access to process information about hosts.

module osquery;

export {
	## Get the ProcessInfos of a host by its id
	##
	## host_id: The identifier of the host
	global getProcessInfosByHostID: function(host_id: string): set[ProcessInfo];

	## Get the ProcessInfo of a host by its id
	##
	## host_id: The identifier of the host
	## pid: The identifier of the process
	global getProcessInfoByHostID: function(host_id: string, pid: int): vector of ProcessInfo;
}

function getProcessInfosByHostID(host_id: string): set[ProcessInfo] {
	local process_infos: set[ProcessInfo] = set();
	if (host_id !in osquery::state::processes::processes) { return process_infos; }

	for (pid in osquery::state::processes::processes[host_id]) {
		add process_infos[osquery::state::processes::processes[host_id][pid]];
	}

	return process_infos;
}

function getProcessInfoByHostID(host_id: string, pid: int): vector of ProcessInfo {
	if (host_id !in osquery::state::processes::processes) { return vector(); }
	if (pid !in osquery::state::processes::processes[host_id]) { return vector(); }

	return vector(osquery::state::processes::processes[host_id][pid]);
}