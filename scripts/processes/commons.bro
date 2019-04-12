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
	# Table to access ProcessInfo by HostID
	global processes: table[string] of table[int] of osquery::ProcessInfo;

	# Table to indicate freshness of ProcessInfo by HostID
	global process_freshness: table[string] of table[int] of bool;

	# Table to indicate freshness of hosts by HostID
	global host_freshness: table[string] of bool;

	# Set of HostID that have maintenance scheduled
	global host_maintenance: set[string];

	# Add an entry to the process state
	global add_entry: function(host_id: string, pid: int, path: string, cmdline: string, uid: int, parent: int);

	# Remove an entry from the process state
	global remove_entry: function(host_id: string, pid: int);

	# Remove all entries for host from the process state
	global remove_host: function(host_id: string);
}

function add_entry(host_id: string, pid: int, path: string, cmdline: string, uid: int, parent: int) {
	# Update or insert new
	local process_info: osquery::ProcessInfo;
	if (host_id in processes && pid in processes[host_id]) {
		# Update
		process_info = processes[host_id][pid];
	} else {
		# New
		process_info = [$pid=pid];
	}
	# - Path
	if (path != "") { process_info$path = path; }
	# - Cmdline
	if (cmdline != "") { process_info$cmdline = cmdline; }
	# - UID
	if (uid != -1) { process_info$uid = uid; }
	# - Parent
	if (parent != -1) { process_info$parent = parent; }

	# Insert into state
	if (host_id in processes) {
		processes[host_id][pid] = process_info;
	} else {
		processes[host_id] = table([pid] = process_info);
	}

	# Set fresh
	process_freshness[host_id][process_info$pid] = T;
	event osquery::process_state_added(host_id, process_info);
}

function remove_entry(host_id: string, pid: int) {
	# Check if process exists
	if (host_id !in processes) { return; }
	if (pid !in processes[host_id]) { return; }

	# Check if process is fresh
	if (process_freshness[host_id][pid]) { return; }

	# Remove from state
	local process_info = processes[host_id][pid];
	delete processes[host_id][pid];

	# Remove freshness
	delete process_freshness[host_id][pid];
	event osquery::process_state_removed(host_id, process_info);
}

function remove_host(host_id: string) {
	if (host_id !in processes) { return; }

	for (pid in processes[host_id]) {
		event osquery::process_state_removed(host_id, processes[host_id][pid]);
	}
	delete processes[host_id];
}
