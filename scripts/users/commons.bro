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
	# Table to access UserInfo by HostID and UserID
	global users: table[string] of table[int] of vector of osquery::UserInfo;
}
