from django.shortcuts import render, HttpResponse, redirect
from django.contrib import messages
from .models import *
import bcrypt
def index(request):
	return render(request,'index.html')
    
def login(request):
    if len(users.objects.filter(email=request.POST['email']))>0:
        user=users.objects.get(email=request.POST['email'])
        if user:
            if bcrypt.checkpw(request.POST['pwd'].encode(), user.pwd_hash.encode()):
                request.session['id']=user.first_name
                return redirect('/success')
            else:
                messages.error(request,'you could not be logged in')
                return redirect('/')
        else:
            messages.error(request,'you could not be logged in')
            return redirect('/')
    else:
        messages.error(request,'you could not be logged in')
        return redirect('/')        
def register(request):
    errors = users.objects.basic_validator(request.POST)
    if len(errors)>0:
        for key, value in errors.items():
            messages.error(request, value)
        return redirect('/')
    # redirect the user back to the form to fix the errors
    else:
        pwd_hash=bcrypt.hashpw(request.POST['pwd'].encode(), bcrypt.gensalt())
        users.objects.create(
            first_name=request.POST['first_name'], 
            last_name=request.POST['last_name'], 
            email=request.POST['email'],
            pwd_hash=pwd_hash
        )
        request.session['id']=request.POST['first_name']
        return redirect('/success')
def success(request):
    if 'id' in request.session:
        return render(request, 'success.html')
    else:
        messages.error(request, 'you have to log in or register first')
        return redirect('/')
def logout(request):
    request.session.clear()
    return redirect('/')
