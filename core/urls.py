from django.urls import path

from core import views

app_name = 'core'

urlpatterns = [
    path('login/', views.login, name='login'),
    path('register/', views.register, name='register'),
    path('logout/', views.logout, name='logout'),
    path('', views.index, name='index'),
    path('add-account/', views.addAccount, name='add-account'),
    path('view-account/<int:id>/', views.viewAccount, name='view-account'),
    path('import-account/', views.importAccount, name='import-account'),
    path('export-account/', views.exportAccount, name='export-account'),
]
