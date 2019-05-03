@load ./commons
@load ./get
@load ./log

@if ( !Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
@load ./main
@load ./framework_update
@else
@load ./cluster
@endif
