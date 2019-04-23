module osquery;

export {

	# Delay before entries are removed from state
	global STATE_REMOVAL_DELAY: interval = 10sec &redef;
	
	# Interval to probe if event-based state entries are still valid
	global STATE_MAINTENANCE_INTERVAL: interval = 20sec &redef;
}
