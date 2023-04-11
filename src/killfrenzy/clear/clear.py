import asyncio
from asgiref.sync import sync_to_async

from threading import Thread
import os
import datetime
import traceback

import time

class Clear(Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True

        self.started = False      

    def run(self):
        self.started = True
        asyncio.run(self.start_clear())

        print("Starting clear thread on PID #" + str(os.getpid()) + ".")

    @sync_to_async(thread_sensitive=False)
    def get_pps(self):
        import connections.models as mdls
        return list(mdls.Port_Punch.objects.all().values('ip', 'port', 'service_ip', 'service_port', 'dest_ip', 'last_seen', 'created'))

    @sync_to_async(thread_sensitive=False)
    def del_pp(self, ip, port, sip, sport, dip):
        import connections.models as mdls
        mdls.Port_Punch.objects.filter(ip=ip, port=port, service_ip=sip, service_port=sport, dest_ip=dip).delete()


    @sync_to_async(thread_sensitive=False)
    def get_vcs(self):
        import connections.models as mdls
        return list(mdls.Validated_Client.objects.all().values('src_ip', 'src_port', 'dst_ip', 'dst_port', 'last_seen', 'created'))

    @sync_to_async(thread_sensitive=False)
    def del_vc(self, src_ip, src_port, dst_ip, dst_port):
        import connections.models as mdls
        mdls.Validated_Client.objects.filter(src_ip=src_ip, src_port=src_port, dst_ip=dst_ip, dst_port=dst_port).delete()

    @sync_to_async(thread_sensitive=False)
    def get_stats(self):
        import connections.models as mdls
        return list(mdls.Edge_Stats.objects.all().values('id', 'sdate'))

    @sync_to_async(thread_sensitive=False)
    def del_stat(self, id):
        import connections.models as mdls
        mdls.Edge_Stats.objects.filter(id = id).delete()
    
    async def clear_items(self):
        while True:
            pps = await self.get_pps()

            for pp in pps:
                last_seen = pp["last_seen"].timestamp()
                now = time.time()

                if (last_seen + 300) < now:
                    # Delete.
                    await self.del_pp(pp["ip"], pp["port"], pp["service_ip"], pp["service_port"], pp["dest_ip"])
                    await asyncio.sleep(1)

            vcs = await self.get_vcs()

            for vc in vcs:
                last_seen = vc["last_seen"].timestamp()
                now = time.time()

                if (last_seen + 300) < now:
                    # Delete.
                    await self.del_vc(vc["src_ip"], vc["src_port"], vc["dst_ip"], vc["dst_port"])
                    await asyncio.sleep(1)

            stats = await self.get_stats()

            for stat in stats:
                last_seen = stat["sdate"].timestamp()
                now = time.time()

                if (last_seen + 2678400) < now:
                    # Delete.
                    await self.del_stat(stat["id"])
                    print("Deleting stat with id " + str(stat["id"]))
                    await asyncio.sleep(1)

            print("Clearing items.")
                    
            await asyncio.sleep(1)

    async def start_clear(self):
        while True:
            task = asyncio.create_task(self.clear_items())

            try:
                tasks = await asyncio.gather(task)
            except Exception as e:
                print("[CLEAR] start_clear() :: At least one task failed at gather().")
                print(e)
                print(traceback.format_exc())
                pass

            await asyncio.sleep(30)
    
clear_c = Clear()