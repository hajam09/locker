from django import forms
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate
from django.contrib.auth import login
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError

from core.models import Account
from locker.operations import generalOperations
from cryptography.fernet import Fernet

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
            raise ValidationError("An account already exists for this email address!")

        return email

    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")

        if password1 and password2 and password1 != password2:
            raise ValidationError("Your passwords do not match!")

        if not generalOperations.isPasswordStrong(password1):
            raise ValidationError("Your password is not strong enough.")

        return password1

    def save(self, commit=True):
        user = User()
        user.username = self.cleaned_data.get("email")
        user.email = self.cleaned_data.get("email")
        user.set_password(self.cleaned_data["password1"])
        user.first_name = self.cleaned_data.get("first_name")
        user.last_name = self.cleaned_data.get("last_name")
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

        raise ValidationError("Username or Password did not match!")


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
        newPassword = self.cleaned_data.get('password')
        confirmPassword = self.cleaned_data.get('repeatPassword')

        if newPassword != confirmPassword:
            messages.error(
                self.request,
                'Your new password and confirm password does not match.'
            )
            raise ValidationError('Your new password and confirm password does not match.')

        if not generalOperations.isPasswordStrong(newPassword):
            messages.warning(
                self.request,
                'Your new password is not strong enough.'
            )
            raise ValidationError('Your new password is not strong enough.')

        return self.cleaned_data

    def updatePassword(self):
        newPassword = self.cleaned_data.get('password')
        self.user.set_password(newPassword)
        self.user.save()


class AccountForm(forms.Form):
    url = forms.URLField(
        label="URL",
        required=False
    )
    name = forms.CharField(
        label="Name",
        required=False
    )
    folder = forms.CharField(
        label="Folder",
        required=False
    )
    username = forms.CharField(
        label="Username",
        required=False
    )
    email = forms.EmailField(
        label="Email",
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
        widget=forms.Textarea(attrs={"rows": "5"})
    )

    def __init__(self, request, account=None, *args, **kwargs):
        super(AccountForm, self).__init__(*args, **kwargs)
        self.user = request.user
        self.account = account

        if self.account is not None:
            self.initial['url'] = self.account.url
            self.initial['name'] = self.account.name
            self.initial['folder'] = self.account.folder
            self.initial['username'] = self.account.getUsername()
            self.initial['email'] = self.account.getEmail()
            self.initial['password'] = self.account.getPassword()
            self.initial['notes'] = self.account.notes

    def update(self):
        self.account.url = self.cleaned_data.get("url")
        self.account.name = self.cleaned_data.get("name")
        self.account.folder = self.cleaned_data.get("folder")
        self.account.username = self.cleaned_data.get("username")
        self.account.email = self.cleaned_data.get("email")
        self.account.password = self.cleaned_data.get("password")
        self.account.notes = self.cleaned_data.get("notes")

        self.account.save()
        return self.account

    def clean_username(self):
        return generalOperations.encrypt(self.cleaned_data.get("username"), self.account.secret)

    def clean_email(self):
        return generalOperations.encrypt(self.cleaned_data.get("email"), self.account.secret)

    def clean_password(self):
        return generalOperations.encrypt(self.cleaned_data.get("password"), self.account.secret)

    def save(self):
        return Account.objects.create(
            user=self.user,
            url=self.cleaned_data.get("url"),
            name=self.cleaned_data.get("name"),
            folder=self.cleaned_data.get("folder"),
            username=self.cleaned_data.get("username"),
            email=self.cleaned_data.get("email"),
            password=self.cleaned_data.get("password"),
            notes=self.cleaned_data.get("notes"),
        )


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
        currentPassword = self.cleaned_data.get('currentPassword')
        newPassword = self.cleaned_data.get('newPassword')
        repeatNewPassword = self.cleaned_data.get('repeatNewPassword')

        if currentPassword and not self.user.check_password(currentPassword):
            raise ValidationError('Your current password does not match with the account\'s existing password.')

        if newPassword and repeatNewPassword:
            if newPassword != repeatNewPassword:
                raise ValidationError('Your new password and confirm password does not match.')

            if not generalOperations.isPasswordStrong(newPassword):
                raise ValidationError('Your new password is not strong enough.')

        return self.cleaned_data

    def updatePassword(self):
        newPassword = self.cleaned_data.get('newPassword')
        self.user.set_password(newPassword)
        self.user.save()
