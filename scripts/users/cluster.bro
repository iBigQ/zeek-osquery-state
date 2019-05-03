#! Provide synchronization of state from manager to workers

module osquery::state::users;

event osquery::user_state_added(host_id: string, user_info: osquery::UserInfo) &priority=10 {
	local gid = -1;
	local username = "";
	local user_type = "";
	if (user_info?$gid) { gid = user_info$gid; }
	if (user_info?$username) { username = user_info$username; }
	if (user_info?$user_type) { user_type = user_info$user_type; }
	add_entry(host_id, user_info$uid, gid, username, user_type);
}

event osquery::user_host_state_removed(host_id: string) &priority=10 {
	host_freshness[host_id] = F;
	remove_host(host_id);

	delete host_freshness[host_id];
	if (host_id in user_freshness) {
		delete user_freshness[host_id];
	}
}

event osquery::user_state_removed(host_id: string, user_info: osquery::UserInfo) &priority=10 {
	if (host_id !in user_freshness) { return; }
	if (user_info$uid !in user_freshness[host_id]) { return; }
	
	user_freshness[host_id][user_info$uid] = F;
	remove_entry(host_id, user_info$uid);
}
