import csv
import operator
from functools import reduce
from http import HTTPStatus
from io import StringIO

from cryptography.fernet import Fernet
from django.contrib import messages, auth
from django.core.cache import cache
from django.db import transaction
from django.db.models import Q
from django.http import JsonResponse, HttpResponse
from django.shortcuts import redirect
from django.shortcuts import render

from core.forms import LoginForm, AccountCreateForm, AccountUpdateForm
from core.forms import RegistrationForm
from core.models import Account, Secret
from locker.operations import generalOperations


def login(request):
    if not request.session.session_key:
        request.session.save()

    if request.method == 'POST':
        unique_visitor_id = request.session.session_key

        if cache.get(unique_visitor_id) is not None and cache.get(unique_visitor_id) > 3:
            cache.set(unique_visitor_id, cache.get(unique_visitor_id), 600)

            messages.error(
                request, 'Your account has been temporarily locked out because of too many failed login attempts.'
            )
            return redirect('core:index')

        form = LoginForm(request, request.POST)

        if form.is_valid():
            cache.delete(unique_visitor_id)
            redirect_url = request.GET.get('next')
            if redirect_url:
                return redirect(redirect_url)
            return redirect('core:index')

        if cache.get(unique_visitor_id) is None:
            cache.set(unique_visitor_id, 1)
        else:
            cache.incr(unique_visitor_id, 1)

    else:
        form = LoginForm(request)

    context = {
        'form': form
    }
    return render(request, 'core/login.html', context)


def logout(request):
    auth.logout(request)
    previous_url = request.META.get('HTTP_REFERER')
    if previous_url:
        return redirect(previous_url)
    return redirect('core:login')


def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('core:login')
    else:
        form = RegistrationForm()

    context = {
        'form': form
    }
    return render(request, 'core/register.html', context)


def performComplexSearch(user, query):
    filter_list = []
    attributes_to_search = [
        'url', 'name', 'folder', 'notes'
    ]

    filter_list.append(reduce(operator.or_, [Q(**{'user__id': user.id})]))
    if query and query.strip():
        filter_list.append(reduce(operator.or_, [Q(**{f'{v}__icontains': query}) for v in attributes_to_search]))

    return Account.objects.filter(reduce(operator.and_, filter_list)).distinct()


def index(request):
    if request.method == 'POST':
        if request.GET.get('action') == 'delete_account' and request.GET.get('id') is not None:
            with transaction.atomic():
                account = Account.objects.filter(id=request.GET.get('id')).first()
                if account:
                    account.secret.delete()
                    account.delete()

            response = {
                'success': True,
            }
            return JsonResponse(response, status=HTTPStatus.OK)

    accounts = performComplexSearch(request.user, request.GET.get('query'))
    context = {
        'accounts': accounts
    }
    return render(request, 'core/index.html', context)


def addAccount(request):
    if request.method == 'POST':
        form = AccountCreateForm(request, request.POST)
        if form.is_valid():
            form.save()
            messages.success(
                request,
                'Account added successfully'
            )
            return redirect('core:add-account')
    else:
        form = AccountCreateForm(request)

    context = {
        'form': form
    }
    return render(request, 'core/addAccount.html', context)


def viewAccount(request, id):
    account = Account.objects.get(user=request.user, id=id)
    if request.method == 'POST':
        form = AccountUpdateForm(request, account, request.POST)
        if form.is_valid():
            form.update()
            messages.success(
                request,
                'Account updated successfully'
            )
            return redirect('core:view-account', id=id)
    else:
        form = AccountUpdateForm(request, account)

    context = {
        'form': form
    }
    return render(request, 'core/viewAccount.html', context)


def exportAccount(request):
    response = HttpResponse('text/csv')
    response['Content-Disposition'] = 'attachment; filename=locker_accounts_export.csv'
    writer = csv.writer(response)
    writer.writerow(['name', 'username', 'email', 'password', 'folder', 'notes', 'url'])
    for account in Account.objects.filter(user=request.user):
        writer.writerow(
            [
                account.name,
                account.get_username(),
                account.get_email(),
                account.get_password(),
                account.folder,
                account.notes,
                account.url
            ]
        )

    return response


def importAccount(request):
    if request.method == 'POST':
        if request.POST.get('import-from') == 'locker':
            listOfAccounts = []
            listOfSecrets = []
            file = request.FILES.get('import-file').read().decode('utf-8')
            csvData = csv.reader(StringIO(file), delimiter=',')
            for row in csvData:
                if row != ['name', 'username', 'email', 'password', 'folder', 'notes', 'url']:
                    if Account.objects.filter(url=row[6], name=row[0]).exists():
                        continue

                    secret = Secret(
                        key=Fernet.generate_key()
                    )

                    newAccount = Account(
                        user=request.user,
                        secret=secret,
                        url=row[6],
                        name=row[0],
                        folder=row[4],
                        username=generalOperations.encrypt(row[1], secret),
                        email=generalOperations.encrypt(row[2], secret),
                        password=generalOperations.encrypt(row[3], secret),
                        notes=row[5],
                    )
                    listOfAccounts.append(newAccount)
                    listOfSecrets.append(secret)

            Secret.objects.bulk_create(listOfSecrets)
            Account.objects.bulk_create(listOfAccounts)

            messages.success(
                request,
                'Accounts added successfully from Locker'
            )

        elif request.POST.get('import-from') == 'bitwarden':
            listOfAccounts = []
            listOfSecrets = []

            file = request.FILES.get('import-file').read().decode('utf-8')
            csvData = csv.reader(StringIO(file), delimiter=',')
            for row in csvData:
                if row != ['folder', 'favorite', 'type', 'name', 'notes', 'fields', 'reprompt', 'login_uri',
                           'login_username', 'login_password', 'login_totp']:

                    if Account.objects.filter(url=row[7], name=row[3]).exists():
                        continue

                    secret = Secret(
                        key=Fernet.generate_key()
                    )

                    newAccount = Account(
                        user=request.user,
                        secret=secret,
                        url=row[7],
                        name=row[3],
                        folder=row[0],
                        username=generalOperations.encrypt(row[8], secret),
                        email=generalOperations.encrypt(row[8], secret),
                        password=generalOperations.encrypt(row[9], secret),
                        notes=row[4],
                    )
                    listOfAccounts.append(newAccount)
                    listOfSecrets.append(secret)

            Secret.objects.bulk_create(listOfSecrets)
            Account.objects.bulk_create(listOfAccounts)

            messages.success(
                request,
                'Accounts added successfully from Bitwarden'
            )

        elif request.POST.get('import-from') == 'last-pass':
            listOfAccounts = []
            listOfSecrets = []

            file = request.FILES.get('import-file').read().decode('utf-8')
            csvData = csv.reader(StringIO(file), delimiter=',')
            for row in csvData:
                if row != ['url', 'username', 'password', 'totp', 'extra', 'name', 'grouping', 'fav']:

                    if Account.objects.filter(url=row[0], name=row[5]).exists():
                        continue

                    secret = Secret(
                        key=Fernet.generate_key()
                    )

                    newAccount = Account(
                        user=request.user,
                        secret=secret,
                        url=row[0],
                        name=row[5],
                        folder=row[6],
                        username=generalOperations.encrypt(row[1], secret),
                        email=generalOperations.encrypt(row[1], secret),
                        password=generalOperations.encrypt(row[2], secret),
                        notes=row[4],
                    )
                    listOfAccounts.append(newAccount)
                    listOfSecrets.append(secret)

            Secret.objects.bulk_create(listOfSecrets)
            Account.objects.bulk_create(listOfAccounts)

            messages.success(
                request,
                'Accounts added successfully from Last pass'
            )
    return render(request, 'core/importAccount.html')
