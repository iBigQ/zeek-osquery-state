#! Provide current user information about hosts.

@load zeek-osquery-framework
@load zeek-osquery-queries/tables/users

module osquery::state::users;

event osquery::user_added(t: time, host_id: string, uid: int, gid: int, uid_signed: int, gid_signed: int, username: string, description: string, directory: string, shell: string, uuid: string, user_type: string) {
	add_entry(host_id, uid, gid, username, user_type);
}

event osquery::state::users::scheduled_remove(host_id: string, uid: int) {
	remove_entry(host_id, uid);
}

event osquery::user_removed(t: time, host_id: string, uid: int, gid: int, uid_signed: int, gid_signed: int, username: string,
			description: string, directory: string, shell: string, uuid: string, user_type: string) {
	user_freshness[host_id][uid] = F;
	schedule osquery::STATE_REMOVAL_DELAY { osquery::state::users::scheduled_remove(host_id, uid) };
}

event osquery::state::users::scheduled_remove_host(host_id: string) {
	# Skip if host reconnected in the meantime
	if (host_id !in host_freshness) { return; }
	if (host_freshness[host_id]) { return; }

	# Indicate state changes
	event osquery::user_host_state_removed(host_id);
	Broker::publish(Cluster::worker_topic, Broker::make_event(osquery::user_host_state_removed, host_id));
	remove_host(host_id);

	# Delete freshness
	delete user_freshness[host_id];
	delete host_freshness[host_id];
}

event osquery::host_connected(host_id: string) {
	host_freshness[host_id] = T;
	if (host_id !in user_freshness) { user_freshness[host_id] = table(); }
	if (host_id !in users) { users[host_id] = table(); }
}

event osquery::host_disconnected(host_id: string) {
	# Set host and state not fresh
	host_freshness[host_id] = F;
	for (uid in users[host_id]) {
		user_freshness[host_id][uid] = F;
	}

	# Schedule removal of host
	schedule osquery::STATE_REMOVAL_DELAY { osquery::state::users::scheduled_remove_host(host_id) };
}
