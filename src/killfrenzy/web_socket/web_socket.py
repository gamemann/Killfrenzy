import asyncio
from asgiref.sync import sync_to_async
from itertools import chain

from threading import Thread

import websockets
import json

import os

import traceback

#import connections.models as mdls

#from connections.models import Edge, Edge_Settings, Edge_Stats, Connection, Connection_A2S_Response, Connection_Stats, Whitelist, Blacklist, Port_Punch

class Web_Socket(Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True

        self.conns = {}
        self.started = False      

    def thread_id(self):
        return self.native_id

    def run(self):
        self.started = True
        asyncio.run(self.start_server())

        print("Starting web socket thread on PID #" + str(os.getpid()) + ".")

    @sync_to_async
    def get_edge(self, ip):
        import connections.models as mdls
        return mdls.Edge.objects.filter(ip=ip).first()

    @sync_to_async
    def get_edge_settings(self, edge):
        import connections.models as mdls
        return mdls.Edge_Settings.objects.filter(edge_id=edge.id).first()

    def get_conn(self, ip):
        if self.conns is None:
            return None

        for k, v in self.conns.items():
            if k == ip:
                return v

        return None

    @sync_to_async
    def get_connections(self):
        import connections.models as mdls
        connections = list(mdls.Connection.objects.all().values('enabled', 'protocol', 'bind_ip', 'bind_port', 'dest_ip', 'dest_port', 'filters', 'udp_rl_bl', 'udp_rl_pps', 'udp_rl_bps', 'tcp_rl_bl', 'tcp_rl_pps', 'tcp_rl_bps', 'icmp_rl_bl', 'icmp_rl_pps', 'icmp_rl_bps', 'syn_rl_bl', 'syn_rl_pps', 'syn_rl_bps', 'a2s_info_enabled', 'a2s_info_cache_time', 'a2s_info_global_cache', 'a2s_info_cache_timeout'))
        conns_return = []

        for v in connections:
            if v is None:
                continue

            new_v = {}

            new_v = v.copy()

            if new_v is None:
                continue

            new_v["udp_rl"] = {}
            new_v["udp_rl"]["block_time"] = new_v["udp_rl_bl"]
            new_v["udp_rl"]["pps"] = new_v["udp_rl_pps"]
            new_v["udp_rl"]["bps"] = new_v["udp_rl_bps"]

            new_v["tcp_rl"] = {}
            new_v["tcp_rl"]["block_time"] = new_v["tcp_rl_bl"]
            new_v["tcp_rl"]["pps"] = new_v["tcp_rl_pps"]
            new_v["tcp_rl"]["bps"] = new_v["tcp_rl_bps"]

            new_v["icmp_rl"] = {}
            new_v["icmp_rl"]["block_time"] = new_v["icmp_rl_bl"]
            new_v["icmp_rl"]["pps"] = new_v["icmp_rl_pps"]
            new_v["icmp_rl"]["bps"] = new_v["icmp_rl_bps"]

            new_v["syn_settings"] = {}
            new_v["syn_settings"]["rl"] = {}
            new_v["syn_settings"]["rl"]["block_time"] = new_v["syn_rl_bl"]
            new_v["syn_settings"]["rl"]["pps"] = new_v["syn_rl_pps"]
            new_v["syn_settings"]["rl"]["bps"] = new_v["syn_rl_bps"]

            new_v["cache_settings"] = {}
            new_v["cache_settings"]["a2s_info_enabled"] = new_v["a2s_info_enabled"]
            new_v["cache_settings"]["a2s_info_cache_time"] = new_v["a2s_info_cache_time"]
            new_v["cache_settings"]["a2s_info_global_cache"] = new_v["a2s_info_global_cache"]
            new_v["cache_settings"]["a2s_info_cache_timeout"] = new_v["a2s_info_cache_timeout"]

            new_v.pop("udp_rl_bl")
            new_v.pop("udp_rl_pps")
            new_v.pop("udp_rl_bps")

            new_v.pop("tcp_rl_bl")
            new_v.pop("tcp_rl_pps")
            new_v.pop("tcp_rl_bps")

            new_v.pop("icmp_rl_bl")
            new_v.pop("icmp_rl_pps")
            new_v.pop("icmp_rl_bps")

            new_v.pop("syn_rl_bl")
            new_v.pop("syn_rl_pps")
            new_v.pop("syn_rl_bps")

            new_v.pop("a2s_info_enabled")
            new_v.pop("a2s_info_cache_time")
            new_v.pop("a2s_info_global_cache")

            conns_return.append(new_v)

        return list(conns_return)

    @sync_to_async
    def get_whitelist(self):
        import connections.models as mdls
        return list(mdls.Whitelist.objects.all().values_list('prefix', flat=True))

    @sync_to_async
    def get_blacklist(self):
        import connections.models as mdls
        return list(mdls.Blacklist.objects.all().values_list('prefix', flat=True))

    @sync_to_async
    def get_port_punch(self):
        import connections.models as mdls
        return list(mdls.Port_Punch.objects.all().values('ip', 'port', 'service_ip', 'service_port', 'dest_ip'))

    @sync_to_async
    def get_validated_client(self):
        import connections.models as mdls
        return list(mdls.Validated_Client.objects.all().values('src_ip', 'src_port', 'dst_ip', 'dst_port'))

    @sync_to_async
    def push_a2s_response(self, a2s_data):
        import connections.models as mdls

        if "ip" not in a2s_data:
            print("push_a2s_response() :: IP not valid.")

            return

        if "port" not in a2s_data:
            print("push_a2s_response() :: Port not valid.")

            return

        if "expires" not in a2s_data:
            print("push_a2s_response() :: Expire time not valid.")

            return

        if "response" not in a2s_data:
            print("push_a2s_response() :: Response not valid.")

            return

        conn = None

        try:
            conn = mdls.Connection.objects.get(bind_ip=a2s_data["ip"], port=a2s_data["port"]).first()
        except mdls.Connection.DoesNotExist:
            conn = None

        if conn is None:
            print("push_a2s_response() :: Failed to get connection for " + a2s_data["ip"] + ": " + str(a2s_data["port"]) + ".")

            return

        a2s = mdls.Connection_A2S_Response.objects.get(connection_id=conn).first()

        if a2s is not None:
            a2s.expires = a2s_data["expires"]
            a2s.response = a2s_data["response"]

            a2s.save()
        else:
            a2s = mdls.Connection_A2S_Response(connection_id=conn, expires=a2s_data["expires"], data=a2s_data["response"])

            a2s.save()

    @sync_to_async
    def update_stats(self, edge, stat_data):
        import connections.models as mdls

        if "bla_pk" in stat_data:
            stat = mdls.Edge_Stats(edge_id=edge, bla_pckts=stat_data["bla_pk"], bla_pckts_ps=stat_data["bla_pps"], bla_bytes=stat_data["bla_by"], bla_bytes_ps=stat_data["bla_bps"], whi_pckts=stat_data["whi_pk"], whi_pckts_ps=stat_data["whi_pps"], whi_bytes=stat_data["whi_by"], whi_bytes_ps=stat_data["whi_bps"], blo_pckts=stat_data["blo_pk"], blo_pckts_ps=stat_data["blo_pps"], blo_bytes=stat_data["blo_by"], blo_bytes_ps=stat_data["blo_bps"], pass_pckts=stat_data["pass_pk"], pass_pckts_ps=stat_data["pass_pps"], pass_bytes=stat_data["pass_by"], pass_bytes_ps=stat_data["pass_bps"], fwd_pckts=stat_data["fwd_pk"], fwd_pckts_ps=stat_data["fwd_pps"], fwd_bytes=stat_data["fwd_by"], fwd_bytes_ps=stat_data["fwd_bps"], fwdo_pckts=stat_data["fwdo_pk"], fwdo_pckts_ps=stat_data["fwdo_pps"], fwdo_bytes=stat_data["fwdo_by"], fwdo_bytes_ps=stat_data["fwdo_bps"], bad_pckts=stat_data["bad_pk"], bad_pckts_ps=stat_data["bad_pps"], bad_bytes=stat_data["bad_by"], bad_bytes_ps=stat_data["bad_bps"], a2rp_pckts=stat_data["a2rp_pk"], a2rp_pckts_ps=stat_data["a2rp_pps"], a2rp_bytes=stat_data["a2rp_by"], a2rp_bytes_ps=stat_data["a2rp_bps"], a2rs_pckts=stat_data["a2rs_pk"], a2rs_pckts_ps=stat_data["a2rs_pps"], a2rs_bytes=stat_data["a2rs_by"], a2rs_bytes_ps=stat_data["a2rs_bps"], dro_pckts=stat_data["dro_pk"], dro_pckts_ps=stat_data["dro_pps"], dro_bytes=stat_data["dro_by"], dro_bytes_ps=stat_data["dro_bps"], drc_pckts=stat_data["drc_pk"], drc_pckts_ps=stat_data["drc_pps"], drc_bytes=stat_data["drc_by"], drc_bytes_ps=stat_data["drc_bps"], cpu_load=stat_data["cpu_load"])

            stat.save()

    @sync_to_async(thread_sensitive=False)
    def push_port_punch(self, pp_data):
        import connections.models as mdls

        if "ip" not in pp_data:
            print("push_port_punch() :: IP not valid.")

            return

        if "port" not in pp_data:
            print("push_port_punch() :: Port not valid.")

            return

        if "service_ip" not in pp_data:
            print("push_port_punch() :: Service IP not valid.")

            return

        if "service_port" not in pp_data:
            print("push_port_punch() :: Service Port not valid.")

            return

        if "dest_ip" not in pp_data:
            print("push_port_punch() :: Destination IP not valid.")

            return

        check = None

        try:
            check = mdls.Port_Punch.objects.get(ip=pp_data["ip"], port=pp_data["port"], service_ip=pp_data["service_ip"], service_port=pp_data["service_port"], dest_ip=pp_data["dest_ip"])
        except mdls.Port_Punch.DoesNotExist:
            check = None

        if check is None:
            pp = mdls.Port_Punch(ip=pp_data["ip"], port=pp_data["port"], service_ip=pp_data["service_ip"], service_port=pp_data["service_port"], dest_ip=pp_data["dest_ip"])

            pp.save()
        else:
            check.save()

    @sync_to_async(thread_sensitive=False)
    def push_validated_client(self, vc_data):
        import connections.models as mdls

        if "src_ip" not in vc_data:
            print("push_validated_client() :: Source IP not valid.")

            return

        if "src_port" not in vc_data:
            print("push_validated_client() :: Source Port not valid.")

            return

        if "dst_ip" not in vc_data:
            print("push_validated_client() :: Destination IP not valid.")

            return

        if "dst_port" not in vc_data:
            print("push_validated_client() :: Destination Port not valid.")

            return

        check = None

        try:
            check = mdls.Validated_Client.objects.get(src_ip=vc_data["src_ip"], src_port=vc_data["src_port"], dst_ip=vc_data["dst_ip"], dst_port=vc_data["dst_port"])
        except mdls.Validated_Client.DoesNotExist:
            check = None

        if check is None:
            vc = mdls.Validated_Client(src_ip=vc_data["src_ip"], src_port=vc_data["src_port"], dst_ip=vc_data["dst_ip"], dst_port=vc_data["dst_port"])

            vc.save()
        else:
            check.save()

    @sync_to_async
    def set_edge_status(self, edge, status):
        edge.status = status

        edge.save()

    @sync_to_async
    def set_edge_xdp_status(self, edge, status):
        edge.xdp_status = status

        edge.save()

    def to_dict(self, instance):
        opts = instance._meta
        data = {}

        for f in chain(opts.concrete_fields, opts.private_fields):
            data[f.name] = f.value_from_object(instance)

        for f in opts.many_to_many:
            data[f.name] = [i.id for i in f.value_from_object(instance)]

        return data

    async def prepare_and_send_data(self, update_type="full_update", edge=None, settings=None, connections=None, whitelist=None, blacklist=None, port_punch=None, validated_client=None, a2s_resp=None):
        edges = list()

        # If we have one edge, just insert the one.
        if edge is not None:
            edges.append(edge)
        else:
            # Loop through all open connections and add to list.
            for k, v in self.conns.items():
                edges.append(v)

        i = 0

        # Loop through all edges.
        for edge_conn in edges:
            if edge_conn is None:
                print("prepare_and_send_data() :: Edge #" + str(i) + " is none.")

                continue

            # Retrieve IP and port.
            ip = edge_conn.remote_address[0]
            port = edge_conn.remote_address[1]

            # Make sure the edge exists in our database.
            edge_obj = await self.get_edge(ip)

            if edge_obj is None:
                print("Found a connection that is already established, but not validated. Closing " + ip + ":" + str(port))

                await edge_obj.close()

                continue

            ret = {}

            # Set type.
            ret["type"] = update_type

            # Initialize data.
            ret["data"] = {}

            if settings is not None and "delete" not in update_type and len(settings) < 1:
                settings = await self.get_edge_settings(edge_obj)

            if settings is not None:
                # Convert to dictionary if not already.
                if type(settings) is not dict:
                    settings = self.to_dict(settings)

                # Set main settings.
                if "interface" in settings:
                    ret["data"]["interface"] = settings["interface"]
                
                # Only set if the edge IP is filled.
                if "edge_ip" in settings:
                    if len(settings["edge_ip"]) > 1:
                        ret["data"]["edge_ip"] = settings["edge_ip"]
                
                if "force_mode" in settings:
                    ret["data"]["force_mode"] = settings["force_mode"]

                if "socket_count" in settings:    
                    ret["data"]["socket_count"] = settings["socket_count"]

                if "queue_is_static" in settings:
                    ret["data"]["queue_is_static"] = settings["queue_is_static"]

                if "queue_id" in settings:    
                    ret["data"]["queue_id"] = settings["queue_id"]

                if "zero_copy" in settings:    
                    ret["data"]["zero_copy"] = settings["zero_copy"]

                if "need_wakeup" in settings:    
                    ret["data"]["need_wakeup"] = settings["need_wakeup"]

                if "batch_size" in settings:
                    ret["data"]["batch_size"] = settings["batch_size"]

                if "verbose" in settings:
                    ret["data"]["verbose"] = settings["verbose"]

                if "calc_stats" in settings:    
                    ret["data"]["calc_stats"] = settings["calc_stats"]

                if "allow_all_edge" in settings:
                    ret["data"]["allow_all_edge"] = settings["allow_all_edge"]
                
            # Handle new connections.
            if connections is not None and "delete" not in update_type and len(connections) < 1:
                connections = await self.get_connections()
            
            if connections is not None:
                if len(connections) > 0:
                    ret["data"]["connections"] = []

                    for c in connections:
                        ret["data"]["connections"].append(c)

            # Handle whitelist.
            if whitelist is not None and "delete" not in update_type and len(whitelist) < 1:
                whitelist = await self.get_whitelist()
            
            if whitelist is not None:
                if len(whitelist) > 0:
                    ret["data"]["whitelist"] = []

                    for w in whitelist:
                        ret["data"]["whitelist"].append(w)

            # Handle blacklist.
            if blacklist is not None and "delete" not in update_type and len(blacklist) < 1:
                blacklist = await self.get_blacklist()
            
            if blacklist is not None:
                if len(blacklist) > 0:
                    ret["data"]["blacklist"] = []

                    for b in blacklist:
                        ret["data"]["blacklist"].append(b)

            # Handle port punch.
            if port_punch is not None and "delete" not in update_type and len(port_punch) < 1:
                port_punch = await self.get_port_punch()
            
            if port_punch is not None:
                if len(port_punch) > 0:
                    ret["data"]["port_punch"] = []

                    for p in port_punch:
                        ret["data"]["port_punch"].append(p)

            # Handle validated client.
            if validated_client is not None and "delete" not in update_type and len(validated_client) < 1:
                validated_client = await self.get_validated_client()
            
            if validated_client is not None:
                if len(validated_client) > 0:
                    ret["data"]["validated_client"] = []

                    for v in validated_client:
                        ret["data"]["validated_client"].append(v)

            # Handle A2S_INFO response.
            if a2s_resp is not None:
                ret["data"]["ip"] = a2s_resp["ip"]
                ret["data"]["port"] = a2s_resp["port"]
                ret["data"]["expires"] = a2s_resp["expires"]
                ret["data"]["response"] = a2s_resp["response"]

            if edge_conn.open is True:
                new_data = json.dumps(ret)
                await edge_conn.send(new_data)
            
            i = i + 1

    async def handler(self, client):
        ip = client.remote_address[0]
        port = client.remote_address[1]

        self.conns[ip] = client

        edge = None

        while True:
            if client.open is False:
                print("Connection from " + ip + ":" + str(port) + " ended.")
                self.conns.pop(ip, None)

                if edge is not None:
                    await self.set_edge_status(edge, False)

                break

            #print("Handling new client " + ip + ":" + str(port) + "...")

            try:
                async for data in client:
                    try:
                        info = json.loads(data)
                    except json.JSONDecodeError as e:
                        print("handler() :: Error handling JSON load.")
                        print("Error => " + e.msg)
                        print("JSON Data => " + e.doc)

                        continue

                    ret = {}

                    edge = await self.get_edge(ip)

                    if edge is None:
                        print("Found invalidated request from " + ip + ":" + str(port))

                        ret["code"] = 404
                        ret["type"] = "NotAuthorized"
                        ret["message"] = "Not authorized (not in connections list)"

                        await client.send(json.dumps(ret))
                        await client.close()

                        break
                    
                    # Set to online.
                    await self.set_edge_status(edge, True)

                    # Make sure we have valid data.
                    if "type" not in info:
                        continue

                    if info["type"] == "full_update":
                        try:
                            await self.prepare_and_send_data("full_update", client, settings={}, connections=[], whitelist=[], blacklist=[], validated_client=[], port_punch=[])
                        except Exception as e:
                            print("Failed to process full update.")
                            print(e)
                            print(traceback.format_exc())

                    if info["type"] == "settings":
                        try:
                            await self.prepare_and_send_data("settings", client, settings={})
                        except Exception as e:
                            print("Failed to process settings update.")
                            print(e)
                    elif info["type"] == "connections":
                        try:
                            await self.prepare_and_send_data("connections", client, connections=[])
                        except Exception as e:
                            print("Failed to process connections update.")
                            print(e)
                    elif info["type"] == "whitelist":
                        try:
                            await self.prepare_and_send_data("whitelist", client, whitelist=[])
                        except Exception as e:
                            print("Failed to process whitelist update.")
                            print(e)
                    elif info["type"] == "blacklist":
                        try:
                            await self.prepare_and_send_data("blacklist", client, blacklist=[])
                        except Exception as e:
                            print("Failed to process blacklist update.")
                            print(e)
                    elif info["type"] == "port_punch":
                        try:
                            await self.prepare_and_send_data("port_punch", client, port_punch=[])
                        except Exception as e:
                            print("Failed to process port punch update.")
                            print(e)
                    elif info["type"] == "validated_client":
                        try:
                            await self.prepare_and_send_data("validated_client", client, validated_client=[])
                        except Exception as e:
                            print("Failed to process validated client update.")
                            print(e)
                    elif info["type"] == "push_stats":
                        if "data" not in info:
                            continue

                        stat_data = info["data"]

                        try:
                            await self.update_stats(edge, stat_data)
                        except Exception as e:
                            print("Invalid stat data push.")
                            print(e)

                            continue
                    elif info["type"] == "push_xdp_status":
                        if "data" not in info:
                            continue

                        xdp_data = info["data"]
                        
                        if edge is not None:
                            await self.set_edge_xdp_status(edge, xdp_data["status"])
                    elif info["type"] == "push_port_punch":
                        if "data" not in info:
                            continue

                        pp_data = info["data"]

                        try:
                            await self.push_port_punch(pp_data)
                        except Exception as e:
                            print("Invalid port punch push.")
                            print(e)

                            continue
                    elif info["type"] == "push_validated_client":
                        if "data" not in info:
                            continue

                        vc_data = info["data"]

                        try:
                            await self.push_validated_client(vc_data)
                        except Exception as e:
                            print("Invalid validated client push.")
                            print(e)

                            continue
                    elif info["type"] == "push_a2s_response":
                        if "data" not in info:
                            continue

                        a2s_data = info["data"]

                        try:
                            await self.push_a2s_response(a2s_data)
                        except Exception as e:
                            print("Invalid A2S_INFO push.")
                            print(e)

                            continue

            except websockets.exceptions.ConnectionClosedError:
                print("Closing connection...")

        if edge is not None:
            await self.set_edge_status(edge, False)
        
    async def start_server(self):
        async with websockets.serve(self.handler, "0.0.0.0", 8003, compression=None):
            await asyncio.Future()

socket_c = Web_Socket()