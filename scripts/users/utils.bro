#! Provide user state utils

module osquery;

export {
	## Check if two user infos have equal keys
	##
	## <params missing>
	global equalUserKeys: function(user1: UserInfo, user2: UserInfo): bool;


	## Check if two process infos are equal
	##
	## <params missing>
	global equalUserInfos: function(user1: UserInfo, user2: UserInfo): bool;
}

function equalUserKeys(user1: UserInfo, user2: UserInfo): bool {
	if (user1$uid != user2$uid) {
		return F;
	}
	return T;
}

function equalUserInfos(user1: UserInfo, user2: UserInfo): bool {
	if (!equalUserKeys(user1, user2)) {
		return F;
	}
	if (user1?$gid != user2?$gid) {
		return F;
	}
	if (user1?$gid && user1$gid != user2$gid) {
		return F;
	}
	if (user1?$username != user2?$username) {
		return F;
	}
	if (user1?$username && user1$username != user2$username) {
		return F;
	}
	if (user1?$user_type != user2?$user_type) {
		return F;
	}
	if (user1?$user_type && user1$user_type!= user2$user_type) {
		return F;
	}
	return T;
}
