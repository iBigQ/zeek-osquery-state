#! Provide process state helper

#module osquery;
#@if ( Cluster::local_node_type() == Cluster::MANAGER )
## Manager need ability to forward state to workers.
#event zeek_init() {
#	Broker::auto_publish(Cluster::worker_topic, osquery::process_state_added);
#	Broker::auto_publish(Cluster::worker_topic, osquery::process_host_state_removed);
#	Broker::auto_publish(Cluster::worker_topic, osquery::process_state_removed);
#}
#@endif

module osquery::state::processes;

export {
	# Table to access number of scheduled deletes by HostID and UserID
	global deleting_processes: DeletingProcessState;
	global deleting_process_events: DeletingProcessState;

	# Table to count the balance of connects by HostID
	global connect_balance: table[string] of count;

	# Table to indicate freshness of ProcessInfo by HostID and ProcessID
	global process_events_freshness: table[string] of table[int] of string;

	# Table to indicate freshness of hosts by HostID
	global host_freshness: table[string] of string;

	# Set of HostID that have maintenance scheduled
	global host_maintenance: set[string];

	# Add an entry to the process state
	global add_entry: function(host_id: string, ev: bool, pid: int, name: string, path: string, cmdline: string, uid: int, parent: int);

	# Remove an entry from the process state
	global remove_entry: function(host_id: string, pid: int, ev: bool, oldest: bool);

	# Remove all entries for host from the process state
	global remove_host: function(host_id: string);
}

global scheduled_remove: event(host_id: string, pid: int, ev: bool, oldest: bool);

function add_entry(host_id: string, ev: bool, pid: int, name: string, path: string, cmdline: string, uid: int, parent: int) {
	local process_info: osquery::ProcessInfo = [$pid=pid, $ev=ev];
	if (name != "") { process_info$name = name; }
	if (path != "") { process_info$path = path; }
	if (cmdline != "") { process_info$cmdline = cmdline; }
	if (uid != -1) { process_info$uid = uid; }
	if (parent != -1) { process_info$parent = parent; }

	# Select table
	local procs: ProcessState;
	if (ev) { procs = process_events; }
	else { procs = processes; }

	# Initialize
	if (host_id !in procs) { procs[host_id] = table(); }

	# Key already in state
	if (pid in procs[host_id]) {
		# Identify duplicates
		local new = T;
		for (idx in procs[host_id][pid]) {
			if (osquery::equalProcessInfos(process_info, procs[host_id][pid][idx])) { new = F; }
		}
		# Raise event
		if (new) {
			event osquery::process_state_added(host_id, process_info);
			Broker::publish(Cluster::worker_topic, Broker::make_event(osquery::process_state_added, host_id, process_info));
		}
		# Save state
		procs[host_id][pid] += process_info;
	# New key in state
	} else {
		# Raise event
		event osquery::process_state_added(host_id, process_info);
		Broker::publish(Cluster::worker_topic, Broker::make_event(osquery::process_state_added, host_id, process_info));
		procs[host_id][pid] = vector(process_info);
	}
}

function remove_entry(host_id: string, pid: int, ev: bool, oldest: bool) {
	# Select table
	local procs: ProcessState;
	if (ev) { procs = process_events; }
	else { procs = processes; }
	
	# Check if process exists
	if (host_id !in procs) { return; }
	if (pid !in procs[host_id]) { return; }
	if (|procs[host_id][pid]| == 0) { return; }

	# Asserts
	#if (ev) {
	#	if (oldest) {
	#		if (|procs[host_id][pid]| == 1) {
	#			print fmt("Only one process despite oldest removal for PID %s on host %s", pid, host_id);
	#		}
	#	} else {
	#		if (|procs[host_id][pid]| != 1) {
	#			print fmt("More than one process despite latest removal for PID %s on host %s", pid, host_id);
	#		}
	#	}
	#} else {
	#	if (!oldest) {
	#		print fmt("Latest process removal despite no event for PID %s on host %s", pid, host_id);
	#	}
	#}

	# Remove from state
	local process_info = procs[host_id][pid][0];
	# Last item in state
	if (|procs[host_id][pid]| == 1) {
		# Raise event
		event osquery::process_state_removed(host_id, process_info);
		Broker::publish(Cluster::worker_topic, Broker::make_event(osquery::process_state_removed, host_id, process_info));
		# Delete state
		delete procs[host_id][pid];
	# Oldest item in state
	} else {
		local process_infos: vector of osquery::ProcessInfo = vector();
		# Identify duplicates
		local old = T;
		for (idx in procs[host_id][pid]) {
			if (idx == 0) { next; }
			process_infos += procs[host_id][pid][idx];
			if (osquery::equalProcessInfos(process_info, procs[host_id][pid][idx])) { old = F; }
		}
		# Raise event
		if (old) {
			event osquery::process_state_removed(host_id, process_info);
			Broker::publish(Cluster::worker_topic, Broker::make_event(osquery::process_state_removed, host_id, process_info));
		}
		# Save state
		procs[host_id][pid] = process_infos;
	}
}

function remove_host(host_id: string) {
	# Check if host exists
	if (host_id !in processes && host_id !in process_events) { return; }

	# Iterate state
	local procs_vec: vector of ProcessState = vector(processes, process_events);
	local procs: ProcessState;
	for (idx in procs_vec) {
		procs = procs_vec[idx];
		if (host_id !in procs) { next; }
		for (pid in procs[host_id]) {
			for (idx in procs[host_id][pid]) {
				# Raise event
				event osquery::process_state_removed(host_id, procs[host_id][pid][idx]);
				Broker::publish(Cluster::worker_topic, Broker::make_event(osquery::process_state_removed, host_id, procs[host_id][pid][idx]));
			}
		}

		# Delete state
		delete procs[host_id];
	}
}
