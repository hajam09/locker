from django.contrib.auth.models import User
from django.db import models

from locker.operations import generalOperations


class Secret(models.Model):
    key = models.BinaryField(editable=False)


class Account(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    secret = models.ForeignKey(Secret, on_delete=models.CASCADE)
    url = models.URLField(max_length=200, blank=True, null=True)
    name = models.CharField(max_length=2048, blank=True, null=True)
    folder = models.CharField(max_length=2048, blank=True, null=True)
    username = models.CharField(max_length=2048, blank=True, null=True)
    email = models.EmailField(max_length=254, blank=True, null=True)
    password = models.CharField(max_length=2048, blank=True, null=True)
    notes = models.TextField(blank=True, null=True)

    class Meta:
        ordering = ('name',)
        verbose_name = 'Account'
        verbose_name_plural = 'Account'

    def __str__(self):
        return self.name

    def getUsername(self):
        return generalOperations.decrypt(self.username, self.secret)

    def getEmail(self):
        return generalOperations.decrypt(self.email, self.secret)

    def getPassword(self):
        return generalOperations.decrypt(self.password, self.secret)
