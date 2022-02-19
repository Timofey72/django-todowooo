from django.shortcuts import render, redirect, get_object_or_404
from django.utils import timezone

from .forms import ToDoForm
from .models import Todo

# Auth
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required

# Error
from django.db import IntegrityError


def home(request):
    return render(request, 'todo/home.html')


def signup_user(request):
    if request.method == 'GET':
        return render(request, 'todo/signup_user.html', {'form': UserCreationForm()})
    else:
        if request.POST['password1'] == request.POST['password2']:
            try:
                user = User.objects.create_user(username=request.POST['username'], password=request.POST['password1'])
                user.save()
                login(request, user)
                return redirect('current_todos')
            except IntegrityError:
                return render(request, 'todo/signup_user.html', {'form': UserCreationForm(),
                                                                 'error': 'That username has already been taken. '
                                                                          'Please choose a new username!'})
        else:
            return render(request, 'todo/signup_user.html', {'form': UserCreationForm(),
                                                             'error': 'Passwords did not match'})


def login_user(request):
    if request.method == 'GET':
        return render(request, 'todo/login_user.html', {'form': AuthenticationForm()})
    else:
        user = authenticate(request, username=request.POST['username'], password=request.POST['password'])
        if user is None:
            return render(request, 'todo/login_user.html', {'form': AuthenticationForm(),
                                                            'error': 'Username and Password did not match'})
        else:
            login(request, user)
            return redirect('current_todos')


@login_required
def logout_user(request):
    if request.method == 'POST':
        logout(request)
    return redirect('home')


@login_required
def current_todos(request):
    todos = Todo.objects.filter(user=request.user, completed__isnull=True, )
    return render(request, 'todo/current_todos.html', {'todos': todos})


@login_required
def completed_todos(request):
    todos = Todo.objects.filter(user=request.user, completed__isnull=False, ).order_by('-completed')
    return render(request, 'todo/completed_todos.html', {'todos': todos})


@login_required
def create_todo(request):
    if request.method == 'GET':
        return render(request, 'todo/create_todo.html', {'form': ToDoForm()})
    else:
        try:
            form = ToDoForm(request.POST)
            new_todo = form.save(commit=False)
            new_todo.user = request.user
            new_todo.save()
            return redirect('current_todos')

        except ValueError:
            return render(request, 'todo/create_todo.html', {'form': ToDoForm(),
                                                             'error': 'Bad data passed in. Try again.'})


@login_required
def view_todo(request, todo_pk):
    todo = get_object_or_404(Todo, pk=todo_pk, user=request.user)
    if request.method == 'GET':
        form = ToDoForm(instance=todo)
        return render(request, 'todo/todo.html', {'todo': todo, 'form': form})
    else:
        try:
            form = ToDoForm(request.POST, instance=todo)
            form.save()
            return redirect('current_todos')
        except ValueError:
            return render(request, 'todo/todo.html', {'todo': todo, 'form': ToDoForm(),
                                                      'error': 'Bad info'})


@login_required
def completed_todo(request, todo_pk):
    todo = get_object_or_404(Todo, pk=todo_pk, user=request.user)
    form = ToDoForm(instance=todo)
    return render(request, 'todo/completed_todo.html', {'todo': todo, 'form': form})


@login_required
def complete_todo(request, todo_pk):
    todo = get_object_or_404(Todo, pk=todo_pk, user=request.user)
    if request.method == 'POST':
        todo.completed = timezone.now()
        todo.save()
        return redirect('current_todos')


@login_required
def delete_todo(request, todo_pk):
    todo = get_object_or_404(Todo, pk=todo_pk, user=request.user)
    if request.method == 'POST':
        todo.delete()
        return redirect('current_todos')


@login_required
def delete_completed_todo(request, todo_pk):
    todo = get_object_or_404(Todo, pk=todo_pk, user=request.user)
    if request.method == 'POST':
        todo.delete()
        return redirect('completed_todos')


@login_required
def error_404(request, exception):
    return render(request, 'error/404.html')


@login_required
def error_500(request):
    return render(request, 'error/500.html')
