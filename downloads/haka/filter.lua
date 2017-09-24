local ipv4 = require("protocol/ipv4")
local tcp = require("protocol/tcp_connection")

local net = ipv4.network("192.168.101.0/24")

haka.rule{
	hook = tcp.events.new_connection,
	eval = function (flow, pkt)
	haka.log("tcp connection %s:%i -> %s:%i",
		flow.srcip, flow.srcport,
		flow.dstip, flow.dstport)

	if net:contains(flow.dstip) then
	 	haka.alert{
			severity = "low",
			description = "connection refused",
			start_time = pkt.ip.raw.timestamp
		}
		flow:drop()
	end
 end
}
