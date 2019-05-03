#! Provide synchronization of state from manager to workers

module osquery::state::processes;

event osquery::process_state_added(host_id: string, process_info: osquery::ProcessInfo) &priority=10 {
	local path = "";
	local cmdline = "";
	local uid = -1;
	local parent = -1;
	if (process_info?$path) { path = process_info$path; }
	if (process_info?$cmdline) { cmdline = process_info$cmdline; }
	if (process_info?$uid) { uid = process_info$uid; }
	if (process_info?$parent) { parent = process_info$parent; }
	add_entry(host_id, process_info$ev, process_info$pid, path, cmdline, uid, parent);
}

event osquery::process_host_state_removed(host_id: string) &priority=10 {
	host_freshness[host_id] = F;
	remove_host(host_id);

	delete host_freshness[host_id];
	if (host_id in process_events_freshness) {
		delete process_events_freshness[host_id];
	}
}

event osquery::process_state_removed(host_id: string, process_info: osquery::ProcessInfo) &priority=10 {
	local oldest = T;
	if (process_info$ev) {
		local procs = process_events;
		if (host_id !in procs) { return; }
		if (|procs[host_id][process_info$pid]| == 1) { 
			if (host_id !in process_events_freshness) { process_events_freshness[host_id] = table(); }
			process_events_freshness[host_id][process_info$pid] = F;
			oldest = F;
		}
	}
	remove_entry(host_id, process_info$pid, process_info$ev, oldest);
}
