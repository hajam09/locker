from cryptography.fernet import Fernet
from django import forms
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate
from django.contrib.auth import login
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError

from core.models import Account, Secret
from locker.operations import generalOperations


class RegistrationForm(UserCreationForm):
    first_name = forms.CharField(
        label='',
        widget=forms.TextInput(
            attrs={
                'placeholder': 'Firstname'
            }
        )
    )
    last_name = forms.CharField(
        label='',
        widget=forms.TextInput(
            attrs={
                'placeholder': 'Lastname'
            }
        )
    )
    email = forms.EmailField(
        label='',
        widget=forms.EmailInput(
            attrs={
                'placeholder': 'Email'
            }
        )
    )
    password1 = forms.CharField(
        label='',
        strip=False,
        widget=forms.PasswordInput(
            attrs={
                'placeholder': 'Password'
            }
        )
    )
    password2 = forms.CharField(
        label='',
        strip=False,
        widget=forms.PasswordInput(
            attrs={
                'placeholder': 'Confirm Password'
            }
        )
    )

    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'email', 'password1', 'password2')

    USERNAME_FIELD = 'email'

    def clean_email(self):
        email = self.cleaned_data.get('email')

        if User.objects.filter(email=email).exists():
            raise ValidationError('An account already exists for this email address!')

        return email

    def clean_password2(self):
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')

        if password1 and password2 and password1 != password2:
            raise ValidationError('Your passwords do not match!')

        if not generalOperations.isPasswordStrong(password1):
            raise ValidationError('Your password is not strong enough.')

        return password1

    def save(self, commit=True):
        user = User()
        user.username = self.cleaned_data.get('email')
        user.email = self.cleaned_data.get('email')
        user.set_password(self.cleaned_data['password1'])
        user.first_name = self.cleaned_data.get('first_name')
        user.last_name = self.cleaned_data.get('last_name')
        user.is_active = settings.DEBUG

        if commit:
            user.save()
        return user


class LoginForm(forms.ModelForm):
    email = forms.EmailField(
        label='',
        widget=forms.EmailInput(
            attrs={
                'placeholder': 'Email'
            }
        )
    )
    password = forms.CharField(
        label='',
        strip=False,
        widget=forms.PasswordInput(
            attrs={
                'placeholder': 'Password'
            }
        )
    )

    class Meta:
        model = User
        fields = ('email',)

    def __init__(self, request=None, *args, **kwargs):
        self.request = request
        super().__init__(*args, **kwargs)

    def clean_password(self):
        email = self.cleaned_data.get('email')
        password = self.cleaned_data.get('password')

        user = authenticate(username=email, password=password)
        if user:
            login(self.request, user)
            return self.cleaned_data

        raise ValidationError('Username or Password did not match!')


class PasswordResetForm(forms.Form):
    password = forms.CharField(
        label='',
        strip=False,
        widget=forms.PasswordInput(
            attrs={
                'placeholder': 'Password'
            }
        )
    )

    repeatPassword = forms.CharField(
        label='',
        strip=False,
        widget=forms.PasswordInput(
            attrs={
                'placeholder': 'Repeat Password'
            }
        )
    )

    def __init__(self, request=None, user=None, *args, **kwargs):
        self.request = request
        self.user = user
        super(PasswordResetForm, self).__init__(*args, **kwargs)

    def clean(self):
        new_password = self.cleaned_data.get('password')
        confirm_password = self.cleaned_data.get('repeatPassword')

        if new_password != confirm_password:
            messages.error(
                self.request,
                'Your new password and confirm password does not match.'
            )
            raise ValidationError('Your new password and confirm password does not match.')

        if not generalOperations.isPasswordStrong(new_password):
            messages.warning(
                self.request,
                'Your new password is not strong enough.'
            )
            raise ValidationError('Your new password is not strong enough.')

        return self.cleaned_data

    def updatePassword(self):
        new_password = self.cleaned_data.get('password')
        self.user.set_password(new_password)
        self.user.save()


class AccountForm(forms.Form):
    url = forms.URLField(
        label='URL',
        required=False
    )
    name = forms.CharField(
        label='Name',
        required=False
    )
    folder = forms.CharField(
        label='Folder',
        required=False
    )
    username = forms.CharField(
        label='Username',
        required=False
    )
    email = forms.EmailField(
        label='Email',
        required=False
    )
    password = forms.CharField(
        label='Password',
        required=False,
        strip=False
    )
    notes = forms.CharField(
        label='Notes',
        required=False,
        widget=forms.Textarea(attrs={'rows': '5'})
    )

    def __init__(self, *args, **kwargs):
        super(AccountForm, self).__init__(*args, **kwargs)

    def save(self):
        raise NotImplementedError('Please implement save() method')

    def update(self):
        raise NotImplementedError('Please implement update() method')


class AccountCreateForm(AccountForm):

    def __init__(self, request, *args, **kwargs):
        super(AccountCreateForm, self).__init__(*args, **kwargs)
        self.request = request

    def save(self):
        account = Account()
        account.user = self.request.user
        account.secret = Secret.objects.create(key=Fernet.generate_key())

        account.url = generalOperations.encrypt(self.cleaned_data.get('url'), account.secret)
        account.name = generalOperations.encrypt(self.cleaned_data.get('name'), account.secret)
        account.folder = generalOperations.encrypt(self.cleaned_data.get('folder'), account.secret)
        account.username = generalOperations.encrypt(self.cleaned_data.get('username'), account.secret)
        account.email = generalOperations.encrypt(self.cleaned_data.get('email'), account.secret)
        account.password = generalOperations.encrypt(self.cleaned_data.get('password'), account.secret)
        account.notes = generalOperations.encrypt(self.cleaned_data.get('notes'), account.secret)
        account.save()
        return


class AccountUpdateForm(AccountForm):

    def __init__(self, request, account=None, *args, **kwargs):
        super(AccountUpdateForm, self).__init__(*args, **kwargs)
        self.request = request
        self.account = account

        if self.account is None or not isinstance(account, Account):
            raise Exception('Account is none, or is not an instance of Account object.')

        self.initial['url'] = generalOperations.decrypt(account.url, self.account.secret)
        self.initial['name'] = generalOperations.decrypt(account.name, self.account.secret)
        self.initial['folder'] = generalOperations.decrypt(account.folder, self.account.secret)
        self.initial['username'] = generalOperations.decrypt(account.username, self.account.secret)
        self.initial['email'] = generalOperations.decrypt(account.email, self.account.secret)
        self.initial['password'] = generalOperations.decrypt(account.password, self.account.secret)
        self.initial['notes'] = generalOperations.decrypt(account.notes, self.account.secret)

    def update(self):
        self.account.url = generalOperations.encrypt(self.cleaned_data.get('url'), self.account.secret)
        self.account.name = generalOperations.encrypt(self.cleaned_data.get('name'), self.account.secret)
        self.account.folder = generalOperations.encrypt(self.cleaned_data.get('folder'), self.account.secret)
        self.account.username = generalOperations.encrypt(self.cleaned_data.get('username'), self.account.secret)
        self.account.email = generalOperations.encrypt(self.cleaned_data.get('email'), self.account.secret)
        self.account.password = generalOperations.encrypt(self.cleaned_data.get('password'), self.account.secret)
        self.account.notes = generalOperations.encrypt(self.cleaned_data.get('notes'), self.account.secret)
        self.account.save()
        return self.account


class PasswordUpdateForm(forms.Form):
    currentPassword = forms.CharField(
        label='',
        strip=False,
        widget=forms.PasswordInput(
            attrs={
                'placeholder': 'Current password'
            }
        )
    )
    newPassword = forms.CharField(
        label='',
        strip=False,
        widget=forms.PasswordInput(
            attrs={
                'placeholder': 'New password'
            }
        )
    )
    repeatNewPassword = forms.CharField(
        label='',
        strip=False,
        widget=forms.PasswordInput(
            attrs={
                'placeholder': 'Repeat new password'
            }
        )
    )

    def __init__(self, request, *args, **kwargs):
        self.request = request
        self.user = request.user
        super(PasswordUpdateForm, self).__init__(*args, **kwargs)

    def clean(self):
        current_password = self.cleaned_data.get('currentPassword')
        new_password = self.cleaned_data.get('newPassword')
        repeat_new_password = self.cleaned_data.get('repeatNewPassword')

        if current_password and not self.user.check_password(current_password):
            raise ValidationError('Your current password does not match with the account\'s existing password.')

        if new_password and repeat_new_password:
            if new_password != repeat_new_password:
                raise ValidationError('Your new password and confirm password does not match.')

            if not generalOperations.isPasswordStrong(new_password):
                raise ValidationError('Your new password is not strong enough.')

        return self.cleaned_data

    def updatePassword(self):
        new_password = self.cleaned_data.get('newPassword')
        self.user.set_password(new_password)
        self.user.save()
