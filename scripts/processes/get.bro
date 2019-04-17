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
	global getProcessInfosByHostIDByPID: function(host_id: string, pid: int): set[ProcessInfo];
}

function getProcessInfosByHostID(host_id: string): set[ProcessInfo] {
	local process_infos: set[ProcessInfo] = set();

	local procs_vec: vector of osquery::state::processes::ProcessState = vector(osquery::state::processes::processes, osquery::state::processes::process_events);
	local procs: osquery::state::processes::ProcessState;
	for (p_idx in procs_vec) {
		procs = procs_vec[p_idx];
		if (host_id !in procs) { next; }

		for (pid in procs[host_id]) {
			for (inf_idx in procs[host_id][pid]) {
				add process_infos[procs[host_id][pid][inf_idx]];
			}
		}
	}

	return process_infos;
}

function getProcessInfosByHostIDByPID(host_id: string, pid: int): set[ProcessInfo] {
	local process_infos: set[ProcessInfo] = set();

	local procs_vec: vector of osquery::state::processes::ProcessState = vector(osquery::state::processes::processes, osquery::state::processes::process_events);
	local procs: osquery::state::processes::ProcessState;
	for (p_idx in procs_vec) {
		procs = procs_vec[p_idx];
		if (host_id !in procs) { next; }
		if (pid !in procs[host_id]) { next; }

		for (inf_idx in procs[host_id][pid]) {
			add process_infos[procs[host_id][pid][inf_idx]];
		}
	}

	return process_infos;
}
