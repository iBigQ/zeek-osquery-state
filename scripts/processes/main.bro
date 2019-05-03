#! Provide current process information about hosts.

@load zeek-osquery-framework
@load zeek-osquery-queries/tables/processes
#@load zeek-osquery-queries/tables/process_events

module osquery::state::processes;

event osquery::state::processes::initial_state(resultInfo: osquery::ResultInfo, pid: int, path: string, cmdline: string, cwd: string, uid: int, gid: int,
		parent: int) {
	add_entry(resultInfo$host, T, pid, path, cmdline, uid, parent);
}

event osquery::process_event_added(t: time, host_id: string, pid: int, path: string, cmdline: string, 
				 cwd: string, uid: int, gid: int, start_time: int, parent: int) {
	add_entry(host_id, T, pid, path, cmdline, uid, parent);
}

event osquery::process_added(t: time, host_id: string, pid: int, name: string, path: string, cmdline: string, 
				 cwd: string,root: string,  uid: int, gid: int, on_dist: int, start_time: int, parent: int, pgroup: int) {
	add_entry(host_id, F, pid, path, cmdline, uid, parent);
}

event osquery::state::processes::scheduled_remove(host_id: string, pid: int, ev: bool, oldest: bool) {
	remove_entry(host_id, pid, ev, oldest);
}

event osquery::process_removed(t: time, host_id: string, pid: int, name: string, path: string, cmdline: string, 
				 cwd: string,root: string,  uid: int, gid: int, on_dist: int, start_time: int, parent: int, pgroup: int) {
	schedule osquery::STATE_REMOVAL_DELAY { osquery::state::processes::scheduled_remove(host_id, pid, F, T) };
}

event osquery::state::processes::scheduled_remove_host(host_id: string) {
	# Skip if host reconnected in the meantime
	if (host_id !in host_freshness) { return; }
	if (host_freshness[host_id]) { return; }

	# Indicate state changes
	event osquery::process_host_state_removed(host_id);
	Broker::publish(Cluster::worker_topic, Broker::make_event(osquery::process_host_state_removed, host_id));
	remove_host(host_id);

	# Delete freshness
	delete process_events_freshness[host_id];
	delete host_freshness[host_id];
}

event osquery::state::processes::state_outdated(resultInfo: osquery::ResultInfo, pid_str: string) {
	local pid = to_int(pid_str);
	# Host already removed?
	if (resultInfo$host !in process_events_freshness) { return; }
	
	process_events_freshness[resultInfo$host][pid] = F;
	schedule osquery::STATE_REMOVAL_DELAY { osquery::state::processes::scheduled_remove(resultInfo$host, pid, T, F) };
}

event osquery::state::processes::verify(host_id: string) {
	local query: osquery::Query;
	local select_pids: vector of string = vector();
	local query_string: string;

	# Host successfully removed from state
	if (host_id !in host_freshness) { 
		# Stop further verifies
		delete host_maintenance[host_id];
		return; 
	}

	# Skip if host is offline or no state
	if (!host_freshness[host_id] || host_id !in process_events) { 
		schedule osquery::STATE_MAINTENANCE_INTERVAL { osquery::state::processes::verify(host_id) };
		return; 
	}

	# Collect process state
	for (pid in process_events[host_id]) {
		select_pids += fmt("SELECT %d AS x", pid);
	}

	if (|select_pids| != 0) {
		# Select query
		query_string = fmt("SELECT x FROM (%s) WHERE x NOT IN (SELECT pid FROM processes)" , join_string_vec(select_pids, " UNION "));
	
		# Send query
		query = [$ev=osquery::state::processes::state_outdated, $query=query_string];
		osquery::execute(query, host_id);
	}
	
	# Schedule next verification
	schedule osquery::STATE_MAINTENANCE_INTERVAL { osquery::state::processes::verify(host_id) };
}

event osquery::host_connected(host_id: string) {
	# Retrieve initial state
        local ev_processes = [$ev=osquery::state::processes::initial_state, $query="SELECT pid, path, cmdline, cwd, uid, gid, parent FROM processes WHERE 1=1"];
	osquery::execute(ev_processes, host_id);

	# Schedule maintenance
	if (host_id !in host_maintenance) {
		add host_maintenance[host_id];
		event osquery::state::processes::verify(host_id);
	}
	host_freshness[host_id] = T;
	if (host_id !in process_events_freshness) { process_events_freshness[host_id] = table(); }
	if (host_id !in processes) { processes[host_id] = table(); }
	if (host_id !in process_events) { process_events[host_id] = table(); }
}

event osquery::host_disconnected(host_id: string) {
	# Set host and state not fresh
	host_freshness[host_id] = F;
	if (host_id !in process_events_freshness) { process_events_freshness[host_id] = table(); }
	for (pid in process_events_freshness[host_id]) {
		process_events_freshness[host_id][pid] = F;
	}

	# Schedule removal of host
	schedule osquery::STATE_REMOVAL_DELAY { osquery::state::processes::scheduled_remove_host(host_id) };
}
