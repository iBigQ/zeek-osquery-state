#! Provide synchronization of state from manager to workers

module osquery::state::users;

event osquery::user_state_added(host_id: string, user_info: osquery::UserInfo) &priority=10 {
	local uid = user_info$uid;
	
	# Initialize
	if (host_id !in users) { users[host_id] = table(); }
	
	# Insert into state
	if (uid in users[host_id]) { 
		users[host_id][uid] += user_info;
	} else {
		users[host_id][uid] = vector(user_info);
	}
}

event osquery::user_host_state_removed(host_id: string) &priority=10 {
	if (host_id in users) { delete users[host_id]; }
}

event osquery::user_state_removed(host_id: string, user_info: osquery::UserInfo) &priority=10 {
	local uid = user_info$uid;

	# Check state
	if (host_id !in users) { return; }
	if (uid !in users[host_id]) { return; }

	# Remove last item in state
	if (|users[host_id][uid]| == 1) {
		if (osquery::equalUserInfos(user_info, users[host_id][uid][0])) {
			delete users[host_id][uid];
		}
		return;
	}

	# Remove from state
	local user_infos: vector of osquery::UserInfo = vector();
	for (idx in users[host_id][uid]) {
		if (idx == |user_infos| && osquery::equalUserInfos(user_info, users[host_id][uid][idx])) { next; }
		user_infos += users[host_id][uid][idx];
	}

	# Save state
	users[host_id][uid] = user_infos;
}
