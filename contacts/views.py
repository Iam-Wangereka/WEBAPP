# contacts/views.py

from django.shortcuts import get_object_or_404, render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.core.mail import send_mail
from django.conf import settings
from django.db import IntegrityError
from .models import Contact, UserProfile
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm
from django.contrib import messages
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.utils.encoding import force_str
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.contrib.auth import update_session_auth_hash
from django.template.loader import render_to_string
from django.contrib.auth.views import PasswordResetView
from django.urls import reverse
from django.urls import reverse_lazy
from django.contrib.auth import authenticate, login
from django.http import HttpResponse





class CustomLoginView(LoginView):
    template_name = 'index.html'  # Create a template for login page
    # Add any customizations as needed

class CustomPasswordResetView(PasswordResetView):
    template_name = 'password_reset.html'  # Create a template for password reset page
    # Set the email template here if you want to customize it
    email_template_name = 'password_reset_email.html'  # Create a template for the reset password email
    # Set the URL to which the user will be redirected after the password reset email is sent
    success_url = reverse_lazy('password_reset_done')

def signup(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        email = request.POST['email']
        mobile = request.POST['mobile']
        address = request.POST['address']

        # Check if a user with the same username already exists
        if User.objects.filter(username=username).exists():
            message = "Username is already taken. Please choose a different username."
            return render(request, 'signup.html', {'message': message})

        try:
            # Create a new user account
            user = User.objects.create_user(username=username, password=password, email=email)

            # Create a new contact entry in the database for the user
            Contact.objects.create(username=username, email=email, mobile=mobile, address=address)

            # Log in the user automatically
            user = authenticate(username=username, password=password)
            login(request, user)

            # Redirect to the login page after successful registration
            messages.success(request, "Account successfully created. You can now log in.")
            return redirect('login')
        except IntegrityError:
            message = "An error occurred while creating the user. Please try again."
            return render(request, 'signup.html', {'message': message})

    return render(request, 'signup.html')

def user_login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('contact_details')  # Redirect to the contact details page after successful login
        else:
            # Add an error message to display on the login page
            messages.error(request, 'Invalid username or password. Please try again.')
            return redirect('login')
    else:
        return render(request, 'index.html')
    
def logout_view(request):
    logout(request)
    response = redirect(reverse('login'))
    response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return response  # Redirect to the login page after logout


def forgot_password(request):
    if request.method == 'POST':
        email = request.POST['email']

        # Use filter() instead of get() to retrieve the user
        users = User.objects.filter(email=email)

        if users.exists():
            # Since there may be multiple users with the same email, you can choose the first one
            user = users.first()

            # Generate a password reset token
            token = default_token_generator.make_token(user)
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))

            # Build the reset password URL
            reset_url = request.build_absolute_uri(
                reverse('reset_password', kwargs={'uidb64': uidb64, 'token': token})
            )

            # Render the reset password email template with the reset URL
            subject = 'Reset Your Password'
            message = f"Hello {user.username},\n\nYou have requested to reset your password. Please click the link below to set a new password:\n\n{reset_url}\n\nIf you didn't request a password reset, please ignore this email."
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])

            message = f"A password reset link has been sent to {email}."
            return render(request, 'forgot_password.html', {'message': message})
        else:
            message = "No user with this email exists."
            return render(request, 'forgot_password.html', {'message': message})

    return render(request, 'forgot_password.html')

User = get_user_model()

def reset_password(request, uidb64, token):
    try:
        # Decode the user ID and get the user
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)

        # Check if the token is valid
        if default_token_generator.check_token(user, token):
            if request.method == 'POST':
                new_password = request.POST['new_password']
                confirm_password = request.POST['confirm_password']

                # Check if the new password and confirm password match
                if new_password != confirm_password:
                    messages.error(request, 'Passwords do not match.')
                    return render(request, 'reset_password.html', {'uidb64': uidb64, 'token': token})

                # Set the new password for the user
                user.set_password(new_password)
                user.save()

                # Update the user's session authentication hash to avoid being logged out
                update_session_auth_hash(request, user)

                # Check if the user has a profile and mark the password reset link as used
                try:
                    profile = user.profile
                    profile.password_reset_used = True
                    profile.save()
                except UserProfile.DoesNotExist:
                    # If the profile does not exist, create one
                    profile = UserProfile.objects.create(user=user, password_reset_used=True)

                # Display a success message
                messages.success(request, 'Your password has been successfully reset. You can now log in with your new password.')

                # Redirect the user to the login page
                return redirect('login')
            else:
                # Render the password reset page with the uidb64 and token in the context
                return render(request, 'reset_password.html', {'uidb64': uidb64, 'token': token})
        else:
            # Token is not valid
            messages.error(request, 'Invalid password reset link. Please request a new one.')
            return redirect('forgot_password')
    except User.DoesNotExist:
        # User with the given ID not found
        messages.error(request, 'Invalid password reset link. Please request a new one.')
        return redirect('forgot_password')

from django.shortcuts import render, redirect
from .models import Contact

def contact_details(request):
    if request.method == 'POST':
        user = request.user
        if Contact.objects.filter(user=user).exists():
            message = "Contact details can be filled only once."
            return render(request, 'contact_details.html', {'message': message})

        registration_number = request.POST['registration_number']
        mobile = request.POST['mobile']
        email = request.POST['email']
        address = request.POST['address']

        # Create a new contact entry in the database
        contact = Contact.objects.create(user=user, registration_number=registration_number, mobile=mobile, email=email, address=address)
        contact.save()

        return redirect('contact_list')

    # If it's a GET request, just render the form
    return render(request, 'contact_details.html', {'message': None})

def search_contact(request):
    if request.method == 'POST':
        registration_number = request.POST['registration_number']
        try:
            contact = get_object_or_404(Contact, registration_number=registration_number)
            return render(request, 'existing_contact_details.html', {'contact': contact})
        except User.DoesNotExist:
         messages.error(request, 'Contact with registration number {} does not exist.'.format(registration_number))
        return redirect('search_contact.html')

    return render(request, 'search_contact.html')

def contact_list(request):
    # Add the logic to retrieve the list of contacts and pass it to the template
    contacts = Contact.objects.all()  # Assuming you have a Contact model defined
    return render(request, 'contact_list.html', {'contacts': contacts})

def existing_contact_details(request):
    # Your view logic here
    return HttpResponse("This is the existing_contact_details view.")

@login_required
def delete_contact(request, contact_id):
    # Check if the user is an admin
    if not request.user.is_superuser:
        messages.error(request, 'You do not have permission to delete contacts.')
        return redirect('contact_list')

    if request.method == 'POST':
        # Assuming the contact_id is passed as a parameter in the URL
        # Retrieve the contact to be deleted
        contact = get_object_or_404(Contact, id=contact_id)

        # Delete the contact from the database
        contact.delete()

        messages.success(request, 'Contact deleted successfully.')

        # Redirect the user to the contact list page
        return redirect('contact_list')

    # If it's not a POST request, redirect to the contact list page
    return redirect('contact_list')

