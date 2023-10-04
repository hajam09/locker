from django import template
from django.urls import reverse

from locker.base.utils.navigationBar import linkItem, Icon

register = template.Library()


@register.simple_tag
def navigationPanel(request):
    links = [
        linkItem('Home', reverse('core:index'), None),
    ]

    if request.user.is_authenticated:
        links.extend(
            [
                linkItem('Add Account', reverse('core:add-account'), None),
                linkItem('Import Account', reverse('core:import-account'), None),
                linkItem('Export Account', reverse('core:export-account'), None),
                linkItem('Account', '', None, [
                    linkItem('Update password', None, Icon('', '', '0')),
                    linkItem('Logout', reverse('core:logout'), Icon('', '', '0')),
                ]),
            ]
        )
    else:
        links.append(
            linkItem('Login / Register', '', None, [
                linkItem('Register', reverse('core:register'), Icon('', 'fas fa-user-circle', '20')),
                None,
                linkItem('Login', reverse('core:login'), Icon('', 'fas fa-sign-in-alt', '20')),
            ]),
        )
    return links
