#! Provide process state commons

module osquery;

export {
	## Event when added to the state of processes
	##
	## <params missing>
	global process_state_added: event(host_id: string, process_info: ProcessInfo);
	
	## Event when removing a host from the state of processes
	##
	## <params missing>
	global process_host_state_removed: event(host_id: string);
	
	## Event when removing from the state of processes
	##
	## <params missing>
	global process_state_removed: event(host_id: string, process_info: ProcessInfo);
}

module osquery::state::processes;

export {
	type ProcessState: table[string] of table[int] of vector of osquery::ProcessInfo;

	# Table to access ProcessInfo by HostID
	global processes: ProcessState = table();
	global process_events: ProcessState = table();

	# Table to indicate freshness of ProcessInfo by HostID
	global process_events_freshness: table[string] of table[int] of bool;

	# Table to indicate freshness of hosts by HostID
	global host_freshness: table[string] of bool;

	# Set of HostID that have maintenance scheduled
	global host_maintenance: set[string];

	# Add an entry to the process state
	global add_entry: function(host_id: string, ev: bool, pid: int, path: string, cmdline: string, uid: int, parent: int);

	# Remove an entry from the process state
	global remove_entry: function(host_id: string, pid: int, ev: bool, oldest: bool);

	# Remove all entries for host from the process state
	global remove_host: function(host_id: string);
}

global scheduled_remove: event(host_id: string, pid: int, ev: bool, oldest: bool);

function add_entry(host_id: string, ev: bool, pid: int, path: string, cmdline: string, uid: int, parent: int) {
	local process_info: osquery::ProcessInfo = [$pid=pid];
	if (path != "") { process_info$path = path; }
	if (cmdline != "") { process_info$cmdline = cmdline; }
	if (uid != -1) { process_info$uid = uid; }
	if (parent != -1) { process_info$parent = parent; }

	local procs: ProcessState;
	if (ev) { procs = process_events; }
	else { procs = processes; }

	# Insert into state
	if (host_id !in procs) { procs[host_id] = table(); }
	if (pid in procs[host_id]) {
		procs[host_id][pid] += process_info;
	} else {
		procs[host_id][pid] = vector(process_info);
	}

	# For event entry
	if (ev) { 
		# Set fresh
		process_events_freshness[host_id][pid] = T;
		# Schedule removal of overriden event entry
		if (|procs[host_id][pid]| > 1) {
			schedule 30sec { osquery::state::processes::scheduled_remove(host_id, pid, ev, T) };
		}
	}

	event osquery::process_state_added(host_id, process_info);
}

function remove_entry(host_id: string, pid: int, ev: bool, oldest: bool) {
	local procs: ProcessState;
	if (ev) { procs = process_events; }
	else { procs = processes; }
	
	# Check if process exists
	if (host_id !in procs) { return; }
	if (pid !in procs[host_id]) { return; }
	if (|procs[host_id][pid]| == 0) { return; }

	# Check if new process event was added
	if (ev && !oldest && process_events_freshness[host_id][pid]) { return; }
	# Asserts
	if (ev) {
		if (oldest) {
			if (|procs[host_id][pid]| == 1) {
				print fmt("Only one process despite oldest removal for PID %s on host %s", pid, host_id);
			}
		} else {
			if (|procs[host_id][pid]| != 1) {
				print fmt("More than one process despite latest removal for PID %s on host %s", pid, host_id);
			}
		}
	} else {
		if (!oldest) {
			print fmt("Latest process removal despite no event for PID %s on host %s", pid, host_id);
		}
	}

	# Remove from state
	local process_info = procs[host_id][pid][0];
	if (|procs[host_id][pid]| == 1) {
		delete procs[host_id][pid];
		# Remove freshness
		if (ev) { delete process_events_freshness[host_id][pid]; }
	} else {
		local process_infos: vector of osquery::ProcessInfo = vector();
		for (idx in procs[host_id][pid]) {
			if (idx == 0) { next; }
			process_infos += procs[host_id][pid][idx];
		}
		procs[host_id][pid] = process_infos;
	}

	event osquery::process_state_removed(host_id, process_info);
}

function remove_host(host_id: string) {
	if (host_id !in processes && host_id !in process_events) { return; }

	local procs_vec: vector of ProcessState = vector(processes, process_events);
	local procs: ProcessState;
	for (idx in procs_vec) {
		procs = procs_vec[idx];
		if (host_id !in procs) { next; }

		for (pid in procs[host_id]) {
			for (idx in procs[host_id][pid]) {
				event osquery::process_state_removed(host_id, procs[host_id][pid][idx]);
			}
		}
		delete procs[host_id];
	}
}
