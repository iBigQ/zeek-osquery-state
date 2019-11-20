#! Provide current user information about hosts.

@load zeek-osquery-framework
@load zeek-osquery-queries/tables/users

module osquery::state::users;

event osquery::user_added(t: time, host_id: string, uid: int, gid: int, uid_signed: int, gid_signed: int, username: string, description: string, directory: string, shell: string, uuid: string, user_type: string) {
	add_entry(t, host_id, uid, gid, username, user_type);
}

event osquery::state::users::scheduled_remove(t: time, host_id: string, uid: int) {
	# Verify scheduled deletes
	if (host_id !in deleting_users) {
		#print fmt("Scheduled remove for process but host state already deleted");
		return;
	}
	if (uid !in deleting_users[host_id]) {
		#print fmt("Scheduled remove for process but no deleting counter for pid");
		return;
	}

	# Decrease scheduled deletes
	deleting_users[host_id][uid] -= 1;
	if (deleting_users[host_id][uid] == 0) {
		delete deleting_users[host_id][uid];
	}

	# Delete
	remove_entry(t, current_time(), host_id, uid);
}

function schedule_remove(t: time, host_id: string, uid: int) {
	# Increase scheduled deletes
	if (host_id !in deleting_users) { deleting_users[host_id] = table(); }
	if (uid in deleting_users[host_id]) { 
		deleting_users[host_id][uid] += 1; 
	} else {
		deleting_users[host_id][uid] = 0; 
	}

	# Schedule delete
	schedule osquery::STATE_REMOVAL_DELAY { osquery::state::users::scheduled_remove(t, host_id, uid) };
}

event osquery::user_removed(t: time, host_id: string, uid: int, gid: int, uid_signed: int, gid_signed: int, username: string,
			description: string, directory: string, shell: string, uuid: string, user_type: string) {
	# Schedule remove
	schedule_remove(t, host_id, uid);
}

event osquery::state::users::scheduled_remove_host(t: time, host_id: string, cookie: string) {
	# Verify host freshness
	if (host_freshness[host_id] != cookie) { return; }
	delete host_freshness[host_id];
	if (host_id in connect_balance) { delete connect_balance[host_id]; }
	if (host_id in host_maintenance) { delete host_maintenance[host_id]; }
	if (host_id in deleting_users) { delete deleting_users[host_id]; }
	local now = current_time();

	# Indicate state changes
	event osquery::user_host_state_removed(t, now, host_id);
	Broker::publish(Cluster::worker_topic, Broker::make_event(osquery::user_host_state_removed, t, now, host_id));
	remove_host(t, now, host_id);
}

function remove_legacy(t: time, host_id: string) {
	# Check host
	if (host_id !in users) { return; }
	if (host_id !in deleting_users) { deleting_users[host_id] = table(); }

	# Iterate UserID
	for (uid in users[host_id]) {
		if (|users[host_id][uid]| == 0) { next; }
		if (uid !in deleting_users[host_id]) { 
			deleting_users[host_id][uid] = 0; 
		}
		# Remove remaining state
		while (deleting_users[host_id][uid] < |users[host_id][uid]|) {
			schedule_remove(t, host_id, uid);
		}
	}
}

event osquery::host_connected(host_id: string) {
	# Initialize state
	if (host_id !in users) { users[host_id] = table(); }
	if (host_id !in deleting_users) { deleting_users[host_id] = table(); }

	# Update freshnes
	host_freshness[host_id] = "";

	# First connect
	if (host_id !in connect_balance) {
		connect_balance[host_id] = 0;
	}
	# Remove legacy
	if (connect_balance[host_id] >= 0) {
		remove_legacy(network_time(), host_id);
	}
	# Update balance
	connect_balance[host_id] += 1;
}

event osquery::host_disconnected(host_id: string) {
	# Update balance
	connect_balance[host_id] -= 1;
	# - Last disconnect
	if (connect_balance[host_id] == 0) {
		local t = network_time();
		# Schedule removal of host
		host_freshness[host_id] = cat(rand(0xffffffffffffffff));
		schedule osquery::STATE_REMOVAL_DELAY { osquery::state::users::scheduled_remove_host(t, host_id, host_freshness[host_id]) };
		# Remove legacy
		remove_legacy(t, host_id);
	}
}
