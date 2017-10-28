########################################################################################################
###
### @author     Alberto Ciolini 
###
########################################################################################################


@load frameworks/communication/listen

# Let's make sure we use the same port no matter whether we use encryption or not:
redef Communication::listen_port = 47758/tcp;

# Redef this to T if you want to use SSL.
redef Communication::listen_ssl = F;

global test_log = open_log_file("test");

global transport_protocol: event(proto: string, src_addr: string, src_port: count, dst_addr: string, dst_port: count);
global tcp_req: event(src_addr: string, src_port: count, dst_addr: string, dst_port: count);
global ping: event(src_addr: string, dst_addr: string, seq:count, timestamp: time);
global event_received: event(dst_time: time);

redef Communication::nodes += {
	["Bro"] = [$host = 127.0.0.1, $events = /transport_protocol|tcp_req|ping/, $connect=F, $ssl=F]
};

event transport_protocol(proto: string, src_addr: string, src_port: count, dst_addr: string, dst_port: count)
        {
	print test_log, fmt("%s data from %s:%d to %s:%d", proto, src_addr, src_port, dst_addr, dst_port);
        event event_received(current_time());
        }

event tcp_req(src_addr: string, src_port: count, dst_addr: string, dst_port: count)
	{
	print test_log, fmt("SYN request from %s:%d to %s at port %d", src_addr, src_port, dst_addr, dst_port);
	event event_received(current_time());
	}

event ping(src_addr: string, dst_addr: string, seq: count, timestamp: time)
	{
	print test_log, fmt("ping request from %s to %s, seq %d, %f at src", src_addr, dst_addr, seq, timestamp);
	event event_received(current_time());
	}

