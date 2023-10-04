from django.contrib import admin

from core.models import Account, Secret

admin.site.register(Account)
admin.site.register(Secret)
