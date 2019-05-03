#! Logs process state activity.

module osquery::logging::state_processes;

export {
	# Logging
        redef enum Log::ID += { LOG };

        type Info: record {
                host: string &log;
		added: bool &log;
                pid: int &log;
                ev: bool &log;
                path: string &log &optional;
		cmdline: string &log &optional;
		uid: int &log &optional;
		parent: int &log &optional;
        };
}

@if ( !Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
event osquery::process_state_added(host_id: string, process_info: osquery::ProcessInfo) {
        local info: Info = [
		$host=host_id,
		$added=T,
               	$pid = process_info$pid,
		$ev = process_info$ev
	];
	if (process_info?$path) { info$path = process_info$path; }
	if (process_info?$cmdline) { info$cmdline = process_info$cmdline; }
	if (process_info?$uid) { info$uid = process_info$uid; }
	if (process_info?$parent) { info$parent = process_info$parent; }

        Log::write(LOG, info);
}

event osquery::process_state_removed(host_id: string, process_info: osquery::ProcessInfo) {
        local info: Info = [
		$host=host_id,
		$added=F,
               	$pid = process_info$pid,
		$ev = process_info$ev
	];
	if (process_info?$path) { info$path = process_info$path; }
	if (process_info?$cmdline) { info$cmdline = process_info$cmdline; }
	if (process_info?$uid) { info$uid = process_info$uid; }
	if (process_info?$parent) { info$parent = process_info$parent; }

        Log::write(LOG, info);
}
@endif

event bro_init() {
        Log::create_stream(LOG, [$columns=Info, $path="osq-process-state"]);
}
