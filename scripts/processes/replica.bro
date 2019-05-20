#! Provide synchronization of state from manager to workers

module osquery::state::processes;

event osquery::process_state_added(host_id: string, process_info: osquery::ProcessInfo) &priority=10 {
	local pid = process_info$pid;

	# Select table
	local procs: ProcessState;
	if (process_info$ev) { procs = process_events; }
	else { procs = processes; }

	# Initialize
	if (host_id !in procs) { procs[host_id] = table(); }
	
	# Insert into state
	if (pid in procs[host_id]) { 
		procs[host_id][pid] += process_info;
	} else {
		procs[host_id][pid] = vector(process_info);
	}
}

event osquery::process_host_state_removed(host_id: string) &priority=10 {
	if (host_id in processes) { delete processes[host_id]; }
	if (host_id in process_events) { delete process_events[host_id]; }
}

event osquery::process_state_removed(host_id: string, process_info: osquery::ProcessInfo) &priority=10 {
	local pid = process_info$pid;

	# Select table
	local procs: ProcessState;
	if (process_info$ev) { procs = process_events; }
	else { procs = processes; }

	# Check state
	if (host_id !in procs) { return; }
	if (pid !in procs[host_id]) { return; }

	# Remove last item in state
	if (|procs[host_id][pid]| == 1) {
		if (osquery::equalProcessInfos(process_info, procs[host_id][pid][0])) {
			delete procs[host_id][pid];
		}
		return;
	}

	# Remove from state
	local process_infos: vector of osquery::ProcessInfo = vector();
	for (idx in procs[host_id][pid]) {
		if (idx == |process_infos| && osquery::equalProcessInfos(process_info, procs[host_id][pid][idx])) { next; }
		process_infos += procs[host_id][pid][idx];
	}

	# Save state
	procs[host_id][pid] = process_infos;
}
