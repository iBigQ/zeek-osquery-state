#! Provide user state commons

module osquery;

export {
	type UserInfo: record {
		uid: int;
		gid: int &optional;
		username: string &optional;
		user_type: string &optional;
	};

	## Event when added to the state of users
	##
	## <params missing>
	global user_state_added: event(host_id: string, user_info: UserInfo);
	
	## Event when removing a host from the state of users
	##
	## <params missing>
	global user_host_state_removed: event(host_id: string);
	
	## Event when removing from the state of users
	##
	## <params missing>
	global user_state_removed: event(host_id: string, user_info: UserInfo);
}

module osquery::state::users;

export {
	# Table to access UserInfo by HostID
	global users: table[string] of table[int] of osquery::UserInfo;

	# Table to indicate freshness of UserInfo by HostID
	global user_freshness: table[string] of table[int] of bool;

	# Table to indicate freshness of hosts by HostID
	global host_freshness: table[string] of bool;

	# Set of HostID that have maintenance scheduled
	global host_maintenance: set[string];

	# Add an entry to the process state
	global add_entry: function(host_id: string, uid: int, gid: int, username: string, user_type: string);

	# Remove an entry from the process state
	global remove_entry: function(host_id: string, pid: int);

	# Remove all entries for host from the process state
	global remove_host: function(host_id: string);
}

function add_entry(host_id: string, uid: int, gid: int, username: string, user_type: string) {
	local user_info: osquery::UserInfo = [$uid=uid, $gid=gid, $username=username, $user_type=user_type];

	# Insert into state
	if (host_id in users) {
		users[host_id][uid] = user_info;
	} else {
		users[host_id] = table([uid] = user_info);
	}

	# Set fresh
	user_freshness[host_id][user_info$uid] = T;
	event osquery::user_state_added(host_id, user_info);
}

function remove_entry(host_id: string, uid: int) {
	# Check if user exists
	if (host_id !in users) { return; }
	if (uid !in users[host_id]) { return; }

	# Check if user is fresh
	if (user_freshness[host_id][uid]) { return; }

	# Remove from state
	local user_info = users[host_id][uid];
	delete users[host_id][uid];

	# Remove freshness
	delete user_freshness[host_id][uid];
	event osquery::user_state_removed(host_id, user_info);
}

function remove_host(host_id: string) {
	if (host_id !in users) { return; }

	for (uid in users[host_id]) {
		event osquery::user_state_removed(host_id, users[host_id][uid]);
	}
	delete users[host_id];
}
