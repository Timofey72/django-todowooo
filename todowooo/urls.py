"""todowooo URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path
from todo import views
from todo.views import error_404

urlpatterns = [
    path('admin/', admin.site.urls),

    # Auth
    path('signup/', views.signup_user, name='signup_user'),
    path('login/', views.login_user, name='login_user'),
    path('logout/', views.logout_user, name='logout_user'),

    # Todos
    path('', views.home, name='home'),
    path('current/', views.current_todos, name='current_todos'),
    path('completed/', views.completed_todos, name='completed_todos'),
    path('create/', views.create_todo, name='create_todo'),
    path('todo/<int:todo_pk>', views.view_todo, name='view_todo'),
    path('completed/todo/<int:todo_pk>', views.completed_todo, name='completed_todo'),
    path('todo/<int:todo_pk>/complete', views.complete_todo, name='complete_todo'),
    path('completed/todo/<int:todo_pk>/delete', views.delete_completed_todo, name='delete_completed_todo'),
    path('todo/<int:todo_pk>/delete', views.delete_todo, name='delete_todo'),
]

# urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

handler404 = "todo.views.error_404"
handler500 = "todo.views.error_500"
