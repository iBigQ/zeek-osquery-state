#! Provide access to user information about hosts.

module osquery;

export {
	## Get the UserInfos of a host by its id
	##
	## host_id: The identifier of the host
	global getUserInfosByHostID: function(host_id: string): set[UserInfo];

	## Get the UserInfo of a host by its id
	##
	## host_id: The identifier of the host
	## uid: The identifier of the user
	global getUserInfoByHostID: function(host_id: string, uid: int): vector of UserInfo;
}

function getUserInfosByHostID(host_id: string): set[UserInfo] {
	local user_infos: set[UserInfo] = set();
	if (host_id !in osquery::state::users::users) { return user_infos; }

	for (uid in osquery::state::users::users[host_id]) {
		add user_infos[osquery::state::users::users[host_id][uid]];
	}

	return user_infos;
}

function getUserInfoByHostID(host_id: string, uid: int): vector of UserInfo {
	if (host_id !in osquery::state::users::users) { return vector(); }
	if (uid !in osquery::state::users::users[host_id]) { return vector(); }

	return vector(osquery::state::users::users[host_id][uid]);
}

