#! Provide process state commons

module osquery;

export {
	type ProcessInfo: record {
		pid: int;
		ev: bool;
		name: string &optional;
		path: string &optional;
		cmdline: string &optional;
		uid: int &optional;
		parent: int &optional;
	};

	## Event when added to the state of processes
	##
	## <params missing>
	global process_state_added: event(t: time, host_id: string, process_info: ProcessInfo);
	
	## Event when removing a host from the state of processes
	##
	## <params missing>
	global process_host_state_removed: event(t: time, now: time, host_id: string);
	
	## Event when removing from the state of processes
	##
	## <params missing>
	global process_state_removed: event(t: time, now: time, host_id: string, process_info: ProcessInfo);
}

module osquery::state::processes;

export {
	type ProcessState: table[string] of table[int] of vector of osquery::ProcessInfo;
	type DeletingProcessState: table[string] of table[int] of count;

	# Table to access regular ProcessInfo by HostID and ProcessID
	global processes: ProcessState = table();

	# Table to access event-based ProcessInfo by HostID and ProcessID
	global process_events: ProcessState = table();
}
