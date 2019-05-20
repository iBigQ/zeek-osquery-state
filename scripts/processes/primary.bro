#! Provide current process information about hosts.

@load zeek-osquery-framework
@load zeek-osquery-queries/tables/processes
#@load zeek-osquery-queries/tables/process_events

module osquery::state::processes;

event osquery::state::processes::scheduled_remove(host_id: string, pid: int, ev: bool, oldest: bool) {
	# Select table
	local deleting_procs: DeletingProcessState;
	if (ev) { deleting_procs = deleting_process_events; }
	else { deleting_procs = deleting_processes; }

	# Verify scheduled deletes
	if (host_id !in deleting_procs) {
		#print fmt("Scheduled remove for process but host state already deleted");
		return;
	}
	if (pid !in deleting_procs[host_id]) {
		#print fmt("Scheduled remove for process but no deleting counter for pid");
		return;
	}

	# Decrease scheduled deletes
	deleting_procs[host_id][pid] -= 1;
	if (deleting_procs[host_id][pid] == 0) {
		delete deleting_procs[host_id][pid];
	}

	# Last event
	#if (ev && !oldest) {
	#	# Event became fresh
	#	if (pid !in process_events_freshness[host_id]) { return; }
	#	if (process_events_freshness[host_id][pid] != freshness) { return; }
	#	delete process_events_freshness[host_id][pid];
	#}

	# Delete
	remove_entry(host_id, pid, ev, oldest);
}

function schedule_remove(host_id: string, pid: int, ev: bool, oldest: bool) {
	# Select table
	local deleting_procs: DeletingProcessState;
	if (ev) { deleting_procs = deleting_process_events; }
	else { deleting_procs = deleting_processes; }
	
	# Verify removal of last event item
	local skip = F;
	if (ev && !oldest) {
		if (host_id !in deleting_process_events) {
			print fmt("Unable to verify removal of last process event item because host state already deleted");
			skip = T;
		} else if (pid !in process_events[host_id] || |process_events[host_id][pid]| == 0) {
			print fmt("Indicator for removal of last process event is incorrect because no events remaining");
			skip = T;
		} else if (pid !in deleting_process_events[host_id] && |process_events[host_id][pid]| != 1) {
			print fmt("Indicator for removal of last process event is incorrect because only one event was expected");
			skip = T;
		} else if (pid in deleting_process_events[host_id] && |process_events[host_id][pid]| - deleting_process_events[host_id][pid] != 1) {
			print fmt("Indicator for removal of last process event is incorrect because not excatly one event remaining");
			skip = T;
		}
	}

	# Increase scheduled deletes
	if (host_id !in deleting_procs) { deleting_procs[host_id] = table(); }
	if (pid in deleting_procs[host_id]) { 
		deleting_procs[host_id][pid] += 1; 
	} else {
		deleting_procs[host_id][pid] = 0; 
	}

	# Schedule delete
	#if (skip) { return; }
	schedule osquery::STATE_REMOVAL_DELAY { osquery::state::processes::scheduled_remove(host_id, pid, ev, oldest) };
}

function _add_event(host_id: string, pid: int, name: string, path: string, cmdline: string, uid: int, parent: int) {
	add_entry(host_id, T, pid, name, path, cmdline, uid, parent);

	# Schedule removal of overriden event entry
	if (pid !in deleting_process_events[host_id]) { deleting_process_events[host_id][pid] = 0; }
	if (deleting_process_events[host_id][pid] + 1 < |process_events[host_id][pid]|) {
		schedule_remove(host_id, pid, T, T);
	}

	# Set fresh
	if (pid in process_events_freshness[host_id]) {
		delete process_events_freshness[host_id][pid];
	}
}

event osquery::state::processes::initial_state(resultInfo: osquery::ResultInfo, pid: int, name: string, path: string, cmdline: string, cwd: string, uid: int, gid: int,
		parent: int) {
	_add_event(resultInfo$host, pid, name, path, cmdline, uid, parent);
}

event osquery::process_event_added(t: time, host_id: string, pid: int, path: string, cmdline: string, 
				 cwd: string, uid: int, gid: int, start_time: int, parent: int) {
	local name = "";
	_add_event(host_id, pid, name, path, cmdline, uid, parent);
}

event osquery::process_added(t: time, host_id: string, pid: int, name: string, path: string, cmdline: string, 
				 cwd: string,root: string,  uid: int, gid: int, on_dist: int, start_time: int, parent: int, pgroup: int) {
	add_entry(host_id, F, pid, name, path, cmdline, uid, parent);
}

event osquery::process_removed(t: time, host_id: string, pid: int, name: string, path: string, cmdline: string, 
				 cwd: string,root: string,  uid: int, gid: int, on_dist: int, start_time: int, parent: int, pgroup: int) {
	# Schedule remove
	schedule_remove(host_id, pid, F, T);
}

event osquery::state::processes::scheduled_remove_host(host_id: string, cookie: string) {
	# Verify host freshness
	if (host_freshness[host_id] != cookie) { return; }
	delete host_freshness[host_id];
	if (host_id in connect_balance) { delete connect_balance[host_id]; }
	if (host_id in host_maintenance) { delete host_maintenance[host_id]; }
	if (host_id in deleting_processes) { delete deleting_processes[host_id]; }
	if (host_id in deleting_process_events) { delete deleting_process_events[host_id]; }
	if (host_id in process_events_freshness) { delete process_events_freshness[host_id]; }

	# Indicate state changes
	event osquery::process_host_state_removed(host_id);
	Broker::publish(Cluster::worker_topic, Broker::make_event(osquery::process_host_state_removed, host_id));
	remove_host(host_id);
}

event osquery::state::processes::state_outdated(resultInfo: osquery::ResultInfo, pid_str: string) {
	local pid = to_int(pid_str);
	local host_id = resultInfo$host;
	
	# Verify freshness
	if (host_id !in process_events_freshness) { return; }
	if (pid !in process_events_freshness[host_id]) { return; }
	if (process_events_freshness[host_id][pid] != resultInfo$cookie) { return; }
	delete process_events_freshness[host_id][pid];

	# Schedule remove
	#print("State Outdated");
	schedule_remove(host_id, pid, T, F);
}

function send_maintenance_chunk(host_id: string, select_vec: vector of string, cookie: string) {
	if (|select_vec| == 0) { return; }

	# Select query
	local query_string = fmt("SELECT x FROM (%s) WHERE x NOT IN (SELECT pid FROM processes)", join_string_vec(select_vec, " UNION "));
	#local query_string = fmt("SELECT x FROM (%s) AS b LEFT JOIN (SELECT pid FROM processes WHERE pid != -1) AS o ON b.x = o.pid WHERE o.pid IS NULL", join_string_vec(select_vec, " UNION "));

	# Send query
	local query = [$ev=osquery::state::processes::state_outdated, $query=query_string, $cookie=cookie];
	osquery::execute(query, host_id);
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
	if (host_freshness[host_id] != "" || host_id !in process_events) { 
		schedule osquery::STATE_MAINTENANCE_INTERVAL { osquery::state::processes::verify(host_id) };
		return; 
	}

	# Collect event socket state
	local select_count = 0;
	local len: count;
	local r = cat(rand(0xffffffffffffffff));
	for (pid in process_events[host_id]) {
		# Number of state entries
		len = |process_events[host_id][pid]|;
		if (len == 0) { next; }

		# Already deleting?
		if (pid !in deleting_process_events[host_id]) {
			deleting_process_events[host_id][pid] = 0;
		}
		if (deleting_process_events[host_id][pid] >= |process_events[host_id][pid]|) {
			next;
		}

		# Update freshness
		process_events_freshness[host_id][pid] = r;

		# Verify Chunk
		select_pids += fmt("SELECT %d AS x", pid);
		select_count += 1;
		if (select_count >= osquery::MAX_VALIDATION_SELECT) {
			send_maintenance_chunk(host_id, select_pids, r);
			select_pids = vector();
			select_count = 0;
		}
	}

	# Verify last chunk
	send_maintenance_chunk(host_id, select_pids, r);
	
	# Schedule next verification
	schedule osquery::STATE_MAINTENANCE_INTERVAL { osquery::state::processes::verify(host_id) };
}

function _remove_legacy(host_id: string, procs: ProcessState, deleting_procs: DeletingProcessState, ev: bool) {
	# Check host
	if (host_id !in procs) { return; }
	if (host_id !in deleting_procs) { deleting_procs[host_id] = table(); }
	local oldest: bool;

	# Iterate ProcessID
	for (pid in procs[host_id]) {
		if (|procs[host_id][pid]| == 0) { next; }
		if (pid !in deleting_procs[host_id]) { 
			deleting_procs[host_id][pid] = 0; 
		}
		# Remove remaining state
		oldest = T;
		while (deleting_procs[host_id][pid] < |procs[host_id][pid]|) {
			if (ev && deleting_procs[host_id][pid] + 1 == |procs[host_id][pid]|) {
				# Last event
				oldest = F;
				#print("Remove legacy");
			}
			schedule_remove(host_id, pid, ev, oldest);
		}
		if (ev && pid in process_events_freshness[host_id]) {
			delete process_events_freshness[host_id][pid];
		}
	}
}

function remove_legacy(host_id: string) {
	# Processes Legacy
	_remove_legacy(host_id, processes, deleting_processes, F);
	# Process Events Legacy
	_remove_legacy(host_id, process_events, deleting_process_events, T);
}

event osquery::host_connected(host_id: string) {
	# Initialize state
	if (host_id !in processes) { processes[host_id] = table(); }
	if (host_id !in process_events) { process_events[host_id] = table(); }
	if (host_id !in deleting_processes) { deleting_processes[host_id] = table(); }
	if (host_id !in deleting_process_events) { deleting_process_events[host_id] = table(); }
	if (host_id !in process_events_freshness) { process_events_freshness[host_id] = table(); }

	# Update freshnes
	host_freshness[host_id] = "";

	# First connect
	if (host_id !in connect_balance) {
		connect_balance[host_id] = 0;
	}
	# Remove legacy
	if (connect_balance[host_id] >= 0) {
		remove_legacy(host_id);
	}
	# Update balance
	connect_balance[host_id] += 1;

	# Retrieve initial state
        local ev_processes = [$ev=osquery::state::processes::initial_state, $query="SELECT pid, name, path, cmdline, cwd, uid, gid, parent FROM processes WHERE 1=1"];
	osquery::execute(ev_processes, host_id);

	# Schedule maintenance
	if (host_id !in host_maintenance) {
		add host_maintenance[host_id];
		event osquery::state::processes::verify(host_id);
	}
}

event osquery::host_disconnected(host_id: string) {
	# Update balance
	connect_balance[host_id] -= 1;
	# - Last disconnect
	if (connect_balance[host_id] == 0) {
		# Schedule removal of host
		host_freshness[host_id] = cat(rand(0xffffffffffffffff));
		schedule osquery::STATE_REMOVAL_DELAY { osquery::state::processes::scheduled_remove_host(host_id, host_freshness[host_id]) };
		# Remove legacy
		remove_legacy(host_id);
	}
}
