import csv
import operator
from functools import reduce
from http import HTTPStatus
from io import StringIO

from cryptography.fernet import Fernet
from django.contrib import messages, auth
from django.core.cache import cache
from django.db.models import Q
from django.http import JsonResponse, HttpResponse
from django.shortcuts import redirect
from django.shortcuts import render

from core.forms import LoginForm, AccountForm
from core.forms import RegistrationForm
from core.models import Account, Secret
from locker.operations import emailOperations, generalOperations


def login(request):
    if not request.session.session_key:
        request.session.save()

    if request.method == "POST":
        uniqueVisitorId = request.session.session_key

        if cache.get(uniqueVisitorId) is not None and cache.get(uniqueVisitorId) > 3:
            cache.set(uniqueVisitorId, cache.get(uniqueVisitorId), 600)

            messages.error(
                request, 'Your account has been temporarily locked out because of too many failed login attempts.'
            )
            return redirect('accounts:login')

        form = LoginForm(request, request.POST)

        if form.is_valid():
            cache.delete(uniqueVisitorId)
            redirectUrl = request.GET.get('next')
            if redirectUrl:
                return redirect(redirectUrl)
            return redirect('quiz:index-view')

        if cache.get(uniqueVisitorId) is None:
            cache.set(uniqueVisitorId, 1)
        else:
            cache.incr(uniqueVisitorId, 1)

    else:
        form = LoginForm(request)

    context = {
        "form": form
    }
    return render(request, 'core/login.html', context)


def logout(request):
    auth.logout(request)
    previousUrl = request.META.get('HTTP_REFERER')
    if previousUrl:
        return redirect(previousUrl)
    return redirect('core:login')


def register(request):
    if request.method == "POST":
        form = RegistrationForm(request.POST)
        if form.is_valid():
            newUser = form.save()
            emailOperations.sendEmailToActivateAccount(request, newUser)

            messages.info(
                request, 'We\'ve sent you an activation link. Please check your email.'
            )
            return redirect('accounts:login')
    else:
        form = RegistrationForm()

    context = {
        "form": form
    }
    return render(request, 'core/register.html', context)


def performComplexSearch(user, query):
    filterList = []
    attributesToSearch = [
        'url', 'name', 'folder', 'notes'
    ]

    filterList.append(reduce(operator.or_, [Q(**{'user__id': user.id})]))
    if query and query.strip():
        filterList.append(reduce(operator.or_, [Q(**{f'{v}__icontains': query}) for v in attributesToSearch]))

    return Account.objects.filter(reduce(operator.and_, filterList)).distinct()


def index(request):
    if request.method == "POST":
        if request.GET.get("action") == "deleteAccount" and request.GET.get("id") is not None:
            Account.objects.filter(id=request.GET.get("id")).delete()

            response = {
                "success": True,
            }
            return JsonResponse(response, status=HTTPStatus.OK)

    accounts = performComplexSearch(request.user, request.GET.get('query'))
    context = {
        "accounts": accounts
    }
    return render(request, 'core/index.html', context)


def addAccount(request):
    if request.method == "POST":
        form = AccountForm(request, request.POST)
        if form.is_valid():
            form.save()
            messages.success(
                request,
                'Account added successfully'
            )
            return redirect('core:add-account')
    else:
        form = AccountForm(request)

    context = {
        "form": form
    }
    return render(request, 'core/addAccount.html', context)


def viewAccount(request, id):
    account = Account.objects.get(user=request.user, id=id)
    if request.method == "POST":
        form = AccountForm(request, account, request.POST)
        if form.is_valid():
            form.update()
            messages.success(
                request,
                'Account updated successfully'
            )
            return redirect('core:view-account', id=id)
    else:
        form = AccountForm(request, account)

    context = {
        "form": form
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
                account.getUsername(),
                account.getEmail(),
                account.getPassword(),
                account.folder,
                account.notes,
                account.url
            ]
        )

    return response


def importAccount(request):
    if request.method == "POST":
        if request.POST.get("import-from") == "locker":
            listOfAccounts = []
            listOfSecrets = []
            file = request.FILES.get("import-file").read().decode('utf-8')
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

        elif request.POST.get("import-from") == "bitwarden":
            listOfAccounts = []
            listOfSecrets = []

            file = request.FILES.get("import-file").read().decode('utf-8')
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

        elif request.POST.get("import-from") == "last-pass":
            listOfAccounts = []
            listOfSecrets = []

            file = request.FILES.get("import-file").read().decode('utf-8')
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
