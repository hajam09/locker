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

    def get_url(self):
        return generalOperations.decrypt(self.url, self.secret) if self.url else ''

    def get_name(self):
        return generalOperations.decrypt(self.name, self.secret) if self.name else ''

    def get_folder(self):
        return generalOperations.decrypt(self.folder, self.secret) if self.folder else ''

    def get_username(self):
        return generalOperations.decrypt(self.username, self.secret) if self.username else ''

    def get_email(self):
        return generalOperations.decrypt(self.email, self.secret) if self.email else ''

    def get_password(self):
        return generalOperations.decrypt(self.password, self.secret) if self.password else ''

    def get_notes(self):
        return generalOperations.decrypt(self.notes, self.secret) if self.notes else ''
