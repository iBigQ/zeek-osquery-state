#! Logs user state activity.

module osquery::logging::state_users;

export {
	# Logging
        redef enum Log::ID += { LOG };

        type Info: record {
                host: string &log;
		added: bool &log;
                uid: int &log;
                gid: int &log &optional;
		username: string &log &optional;
		user_type: string &log &optional;
        };
}

@if ( !Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
event osquery::user_state_added(host_id: string, user_info: osquery::UserInfo) {
        local info: Info = [
		$host = host_id,
		$added= T,
               	$uid = user_info$uid
	];
        if (user_info?$gid) { info$gid = user_info$gid; }
        if (user_info?$username) { info$username = user_info$username; }
        if (user_info?$user_type) { info$user_type = user_info$user_type; }

        Log::write(LOG, info);
}

event osquery::user_state_removed(host_id: string, user_info: osquery::UserInfo) {
        local info: Info = [
		$host = host_id,
		$added = F,
               	$uid = user_info$uid
	];
        if (user_info?$gid) { info$gid = user_info$gid; }
        if (user_info?$username) { info$username = user_info$username; }
        if (user_info?$user_type) { info$user_type = user_info$user_type; }

        Log::write(LOG, info);
}
@endif

event bro_init() {
        Log::create_stream(LOG, [$columns=Info, $path="osq-user-state"]);
}
