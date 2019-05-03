@load ./commons
@load ./get
@load ./log

@if ( !Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
@load ./main
@else
@load ./cluster
@endif
