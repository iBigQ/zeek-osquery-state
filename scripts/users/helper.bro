#! Provide user state helper

#module osquery;
#@if ( Cluster::local_node_type() == Cluster::MANAGER )
## Manager need ability to forward state to workers.
#event zeek_init() {
#	Broker::auto_publish(Cluster::worker_topic, osquery::user_state_added);
#	Broker::auto_publish(Cluster::worker_topic, osquery::user_host_state_removed);
#	Broker::auto_publish(Cluster::worker_topic, osquery::user_state_removed);
#}
#@endif

module osquery::state::users;

export {
	# Table to access number of scheduled deletes by HostID and UserID
	global deleting_users: table[string] of table[int] of count;

	# Table to count the balance of connects by HostID
	global connect_balance: table[string] of count;

	# Table to indidate host freshness by HostID
	global host_freshness: table[string] of string;

	# Set of HostID that have maintenance scheduled
	global host_maintenance: set[string];

	# Add an entry to the user state
	global add_entry: function(t: time, host_id: string, uid: int, gid: int, username: string, user_type: string);

	# Remove an entry from the user state
	global remove_entry: function(t: time, now: time, host_id: string, uid: int);

	# Remove all entries for host from the user state
	global remove_host: function(t: time, now: time, host_id: string);
}

function add_entry(t: time, host_id: string, uid: int, gid: int, username: string, user_type: string) {
	local user_info: osquery::UserInfo = [$uid=uid, $gid=gid, $username=username, $user_type=user_type];

	# Initialize
	if (host_id !in users) { users[host_id] = table(); }

	# Key already in state
	if (uid in users[host_id]) {
		# Identify duplicates
		local new = T;
		for (idx in users[host_id][uid]) {
			if (osquery::equalUserInfos(user_info, users[host_id][uid][idx])) { new = F; }
		}
		# Raise event
		if (new) {
			event osquery::user_state_added(t, host_id, user_info);
			Broker::publish(Cluster::worker_topic, Broker::make_event(osquery::user_state_added, t, host_id, user_info));
		}
		# Save state
		users[host_id][uid] += user_info;
	# New key in state
	} else {
		# Raise event
		event osquery::user_state_added(t, host_id, user_info);
		Broker::publish(Cluster::worker_topic, Broker::make_event(osquery::user_state_added, t, host_id, user_info));
		# Create state
		users[host_id][uid] = vector(user_info);
	}
}

function remove_entry(t: time, now: time, host_id: string, uid: int) {
	# Check if user exists
	if (host_id !in users) { return; }
	if (uid !in users[host_id]) { return; }
	if (|users[host_id][uid]| == 0) { return; }

	# Remove from state
	local user_info = users[host_id][uid][0];
	# Last item in state
	if (|users[host_id][uid]| == 1) {
		# Raise event
		event osquery::user_state_removed(t, now, host_id, user_info);
		Broker::publish(Cluster::worker_topic, Broker::make_event(osquery::user_state_removed, t, now, host_id, user_info));
		# Delete state
		delete users[host_id][uid];
		delete deleting_users[host_id][uid];
	# Oldest item in state
	} else {
		local user_infos: vector of osquery::UserInfo = vector();
		# Identify duplicates
		local old = T;
		for (idx in users[host_id][uid]) {
			if (idx == 0) { next; }
			user_infos += users[host_id][uid][idx];
			if (osquery::equalUserInfos(user_info, users[host_id][uid][idx])) { old = F; }
		}
		# Raise event
		if (old) {
			event osquery::user_state_removed(t, now, host_id, user_info);
			Broker::publish(Cluster::worker_topic, Broker::make_event(osquery::user_state_removed, t, now, host_id, user_info));
		}
		# Save state
		users[host_id][uid] = user_infos;
	}
}

function remove_host(t: time, now: time, host_id: string) {
	# Check if host exists
	if (host_id !in users) { return; }

	# Iterate state
	for (uid in users[host_id]) {
		for (idx in users[host_id][uid]) {
			# Raise event
			event osquery::user_state_removed(t, now, host_id, users[host_id][uid][idx]);
			Broker::publish(Cluster::worker_topic, Broker::make_event(osquery::user_state_removed, t, now, host_id, users[host_id][uid][idx]));
		}
	}

	# Delete state
	delete users[host_id];
}
