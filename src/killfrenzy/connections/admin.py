from django.contrib import admin

from .models import Edge
from .models import Connection
from .models import Edge_Settings
from .models import Whitelist
from .models import Blacklist
from .models import Port_Punch
from .models import Validated_Client

admin.site.register(Edge)
admin.site.register(Edge_Settings)
admin.site.register(Connection)
admin.site.register(Whitelist)
admin.site.register(Blacklist)
admin.site.register(Port_Punch)
admin.site.register(Validated_Client)