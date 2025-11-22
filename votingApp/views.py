from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.models import User
from .models import UserProfile, Election, Candidate, Vote, VoterRecord, Party
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.utils import timezone  # Import this to check dates
from django.db.models import Q, Count  # Import for complex queries and counting
from django.contrib import messages  # To show success/error messages
import random
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.conf import settings
from django.http import JsonResponse
import time


# --- 1. Home Page ---
# (Added logic for live turnout)
def home_page(request):
    try:
        # Get all users who are verified to vote
        total_voters = UserProfile.objects.filter(is_verified=True).count()
        # Get all records of votes cast in all elections
        total_votes_cast = VoterRecord.objects.count()

        if total_voters > 0:
            turnout = (
                total_votes_cast / (total_voters * Election.objects.count())
            ) * 100  # Simple example
            turnout_percentage = round(turnout, 1)
        else:
            turnout_percentage = 0
    except Exception:
        turnout_percentage = 0

    context = {"turnout_percentage": int(turnout_percentage)}
    return render(request, "votingApp/home.html", context)


def register_page(request):
    context = {"states": UserProfile.StateChoices.choices}

    if request.method == "POST":
        # Get Form Data
        voter_id = request.POST.get("voter_id")  # We treat this as the username
        email = request.POST.get("email")
        pass1 = request.POST.get("password")
        pass2 = request.POST.get("confirm_password")  # New field
        fname = request.POST.get("first_name")
        lname = request.POST.get("last_name")
        age = request.POST.get("age")
        state = request.POST.get("state")

        # --- 1. Basic Checks ---
        if User.objects.filter(username=voter_id).exists():
            context["error"] = "This Voter ID is already registered."
            return render(request, "votingApp/register.html", context)

        if User.objects.filter(email=email).exists():
            context["error"] = "This Email is already registered."
            return render(request, "votingApp/register.html", context)

        # --- 2. Password Matching Check ---
        if pass1 != pass2:
            context["error"] = "Passwords do not match."
            return render(request, "votingApp/register.html", context)

        # --- 3. Password Strength Validation (The "Complicated" Check) ---
        try:
            # This runs the same checks as the "Forgot Password" page
            validate_password(pass1, user=User(username=voter_id))
        except ValidationError as e:
            # If password is weak, show the specific error (e.g., "Password is too short")
            context["error"] = e.messages[0]
            return render(request, "votingApp/register.html", context)

        # --- 4. Create User (If all checks pass) ---
        # We save 'voter_id' into the standard 'username' field
        new_user = User.objects.create_user(
            username=voter_id, password=pass1, email=email, is_active=False
        )
        new_user.first_name = fname
        new_user.last_name = lname
        new_user.save()

        UserProfile.objects.create(user=new_user, age=age, state=state)

        # --- 5. Send OTP (Your existing logic) ---
        otp = random.randint(100000, 999999)
        request.session["verification_otp"] = otp
        request.session["verification_user_id"] = new_user.id
        request.session["otp_creation_time"] = time.time()

        # Use Anymail/Brevo logic here (from previous steps)
        try:
            subject = "Your e-Chayan Account Verification"
            message = f"Your One-Time Password (OTP) for e-Chayan is: {otp}"
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])
        except Exception as e:
            new_user.delete()
            context["error"] = f"Email failed to send: {e}"
            return render(request, "votingApp/register.html", context)

        messages.success(request, "Registration successful! Please verify your email.")
        return redirect("verify_otp")

    return render(request, "votingApp/register.html", context)


def verify_otp_page(request):
    try:
        # Get all session data
        stored_otp = request.session.get("verification_otp")
        user_id = request.session.get("verification_user_id")
        otp_creation_time = request.session.get("otp_creation_time")

        # Check if session is missing
        if not stored_otp or not user_id or not otp_creation_time:
            messages.error(
                request, "Your verification session has expired. Please register again."
            )
            return redirect("register")

        # --- 10-MINUTE TIMEOUT LOGIC ---
        current_time = time.time()
        if (current_time - otp_creation_time) > 600:  # 600 seconds = 10 minutes

            # Delete the unverified user
            try:
                user_to_delete = User.objects.get(id=user_id, is_active=False)
                user_to_delete.delete()  # This will also delete the associated UserProfile
            except User.DoesNotExist:
                pass  # User already deleted or activated, which is fine

            # Clear the expired session
            request.session.flush()

            messages.error(
                request,
                "OTP expired (10 minute limit). Your registration data has been deleted. Please register again.",
            )
            return redirect("register")
        # --- END OF TIMEOUT LOGIC ---

    except KeyError:
        messages.error(request, "Invalid session. Please register again.")
        return redirect("register")

    # Handle the form submission
    if request.method == "POST":
        submitted_otp = request.POST.get("otp")

        if int(submitted_otp) == stored_otp:
            # --- SUCCESS ---
            user = User.objects.get(id=user_id)
            user.is_active = True
            user.save()

            user.userprofile.is_email_verified = True
            user.userprofile.save()

            # Clear the session
            request.session.flush()

            messages.success(request, "Email verified! You can now log in.")
            return redirect("login")
        else:
            return render(
                request,
                "votingApp/verify_otp.html",
                {"error": "Invalid OTP. Please try again."},
            )

    # If GET request, just show the page (it passed the time check)
    return render(request, "votingApp/verify_otp.html")


# REPLACE your login_page with this
def login_page(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        # --- MODIFIED: Check if user exists and is inactive ---
        try:
            user_exists = User.objects.get(username=username)
            if not user_exists.is_active:
                messages.error(
                    request,
                    "This account is not active. Please check your email to verify with OTP.",
                )
                return render(request, "votingApp/login.html")
        except User.DoesNotExist:
            pass  # Let authenticate() handle the "does not exist" error
        # --- End of check ---

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect("dashboard")
        else:
            return render(
                request,
                "votingApp/login.html",
                {"error": "Invalid credentials. Please try again."},
            )

    return render(request, "votingApp/login.html")


# --- 4. Logout Page ---
def logout_page(request):
    logout(request)
    return redirect("home")


# --- 5. Dashboard Page ---
# (HEAVILY UPGRADED to show eligible elections)
@login_required
def dashboard_page(request):
    # --- CRITICAL FIX: Handle Missing Profile ---
    try:
        profile = request.user.userprofile
    except UserProfile.DoesNotExist:
        # If the user exists but has no profile data (common for superusers or old accounts)
        # We redirect them to the profile creation/edit page or logout
        messages.error(
            request, "Your profile is incomplete. Please update your details."
        )
        return redirect("profile")
        # ^ OR use logout(request) and redirect('register') if you prefer
    # --------------------------------------------

    now = timezone.now()

    # 2. Get all active elections
    active_elections = Election.objects.filter(start_time__lte=now, end_time__gte=now)

    # 3. Filter for eligibility (Verified + (National OR correct State))
    eligible_elections_query = active_elections.filter(
        Q(election_type=Election.Electiontype.NATIONAL)
        | Q(election_type=Election.Electiontype.STATE, state=profile.state)
    )

    # 4. Get list of elections this user has ALREADY voted in
    voted_election_ids = VoterRecord.objects.filter(user=request.user).values_list(
        "election_id", flat=True
    )

    eligible_elections = []

    # 5. Process the list
    if profile.is_verified:
        for election in eligible_elections_query:
            if election.id in voted_election_ids:
                election.user_has_voted = True
            else:
                election.user_has_voted = False
            eligible_elections.append(election)

    context = {"user_profile": profile, "eligible_elections": eligible_elections}

    return render(request, "votingApp/voting_dashboard.html", context)



@login_required
def profile_page(request):
    # Get the user and their profile
    user = request.user
    profile = user.userprofile

    # Get the state choices to pass to the template
    states = UserProfile.StateChoices.choices

    # This handles the form submission
    if request.method == "POST":
        # Get data from the form
        first_name = request.POST.get("first_name")
        last_name = request.POST.get("last_name")
        email = request.POST.get("email")
        age_str = request.POST.get("age")
        state = request.POST.get("state")

        # --- Validation ---
        try:
            age = int(age_str)
            if age < 18:
                messages.error(request, "Age must be 18 or older.")
                return redirect("profile")  # Stop and reload the page
        except ValueError:
            messages.error(request, "Invalid age format.")
            return redirect("profile")

        # --- Save Changes ---
        # Update User model
        user.first_name = first_name
        user.last_name = last_name
        user.email = email
        user.save()

        # Update UserProfile model
        profile.age = age
        profile.state = state
        profile.save()

        # --- Show Confirmation ---
        messages.success(request, "Your profile has been updated successfully!")

        # Redirect back to the profile page
        return redirect("profile")

    # This handles the initial page load
    context = {"user": user, "profile": profile, "states": states}
    return render(request, "votingApp/profile.html", context)


# --- 6. Results Page ---
# (HEAVILY UPGRADED to calculate and show results)
def results_page(request):
    now = timezone.now()
    elections = Election.objects.all()
    elections_with_results = []

    for election in elections:
        if election.end_time > now:
            # Election is still active
            election.is_active = True
        else:
            # Election has ended, calculate results
            election.is_active = False
            results_dict = {}
            winner = None
            max_votes = -1

            # Get candidates for this election
            candidates = election.candidates.all()

            # Count votes for each candidate
            for candidate in candidates:
                vote_count = Vote.objects.filter(candidate=candidate).count()
                results_dict[candidate] = vote_count

                if vote_count > max_votes:
                    max_votes = vote_count
                    winner = candidate

            # Sort results by vote count (highest first)
            election.results = dict(
                sorted(results_dict.items(), key=lambda item: item[1], reverse=True)
            )
            election.winner = winner

        elections_with_results.append(election)

    context = {"elections_with_results": elections_with_results}
    return render(request, "votingApp/results.html", context)


# --- 7. NEW VIEW: Cast Vote Page ---
# (This page shows candidates and handles the vote submission)
@login_required
def vote_page(request, election_slug):
    election = get_object_or_404(Election, slug=election_slug)
    profile = request.user.userprofile
    now = timezone.now()

    # --- Security & Logic Checks ---
    # is user's email verified?
    if not profile.is_email_verified:
        messages.error(request, "You must verify your email before you can vote.")
        return redirect("dashboard")
    # 1. Is user verified?
    if not profile.is_verified:
        messages.error(request, "You are not verified to vote.")
        return redirect("dashboard")

    # 2. Is election active?
    if not (election.start_time <= now and election.end_time >= now):
        messages.error(request, "This election is not currently active.")
        return redirect("dashboard")

    # 3. Is user eligible for this election?
    is_eligible = election.election_type == Election.Electiontype.NATIONAL or (
        election.election_type == Election.Electiontype.STATE
        and election.state == profile.state
    )
    if not is_eligible:
        messages.error(request, "You are not eligible for this election.")
        return redirect("dashboard")

    # 4. Has user already voted?
    if VoterRecord.objects.filter(user=request.user, election=election).exists():
        messages.error(request, "You have already voted in this election.")
        return redirect("dashboard")

    # --- Handle the Vote Submission (POST) ---
    if request.method == "POST":
        # Get the ID of the candidate they selected
        candidate_id = request.POST.get("candidate")
        if not candidate_id:
            # Error: User submitted the form without selecting anyone
            messages.error(request, "Please select a candidate.")
            context = {"election": election}
            return render(request, "votingApp/vote_page.html", context)

        selected_candidate = get_object_or_404(Candidate, id=candidate_id)

        # --- CAST THE VOTE ---
        # 1. Create the anonymous Vote
        Vote.objects.create(candidate=selected_candidate, election=election)

        # 2. Create the VoterRecord to prevent double-voting
        VoterRecord.objects.create(user=request.user, election=election)

        messages.success(
            request, f"Your vote for {selected_candidate.name} has been cast!"
        )
        return redirect("dashboard")

    # --- Show the Voting Page (GET) ---
    context = {
        "election": election
    }  # The template will loop through election.candidates
    return render(request, "votingApp/vote_page.html", context)


def candidate_register_page(request):
    elections = Election.objects.all()
    parties = Party.objects.all()
    state_choices = UserProfile.StateChoices.choices

    if request.method == 'POST':
        # Get all data
        username = request.POST.get('username')
        email = request.POST.get('email')
        pass1 = request.POST.get('password')
        pass2 = request.POST.get('confirm_password')
        fname = request.POST.get('first_name')
        lname = request.POST.get('last_name')
        election_id = request.POST.get('election_id')
        constituency_id = request.POST.get('constituency_id')
        selected_state = request.POST.get('state')
        party_mode = request.POST.get('party_select')
        candidate_photo = request.FILES.get('candidate_photo')
        
        # Party Data
        new_party_name = request.POST.get('new_party_name')
        new_party_abbr = request.POST.get('new_party_abbr')
        new_party_symbol = request.FILES.get('new_party_symbol')

        error_context = {
            'elections': elections, 'parties': parties, 'states': state_choices
        }

        # --- VALIDATIONS ---
        if pass1 != pass2:
            error_context['error'] = "Passwords do not match."
            return render(request, 'votingApp/candidate_register.html', error_context)

        try:
            validate_password(pass1, user=User(username=username))
        except ValidationError as e:
            error_context['error'] = e.messages[0] # Show the specific error (e.g., "Too short")
            return render(request, 'votingApp/candidate_register.html', error_context)
        
        if User.objects.filter(username=username).exists():
            error_context['error'] = "Username already taken."
            return render(request, 'votingApp/candidate_register.html', error_context)
        
        if User.objects.filter(email=email).exists():
            error_context['error'] = "Email already registered."
            return render(request, 'votingApp/candidate_register.html', error_context)

        # --- PARTY VALIDATION (The new logic) ---
        selected_party = None
        
        if party_mode == 'existing':
            party_id = request.POST.get('existing_party_id')
            selected_party = Party.objects.get(id=party_id)
            
        elif party_mode == 'new':
            # Check if party name exists BEFORE creating user
            if Party.objects.filter(name=new_party_name).exists():
                error_context['error'] = f"The party '{new_party_name}' already exists. Please choose 'Existing Party'."
                return render(request, 'votingApp/candidate_register.html', error_context)
            
            # If we are here, we will create the party later

        # --- START CREATION ---
        
        # 1. Create User
        user = User.objects.create_user(username=username, email=email, password=pass1, is_active=False)
        user.first_name = fname
        user.last_name = lname
        user.save()
        
        UserProfile.objects.create(user=user, age=25, state=selected_state, is_verified=False)

        # 2. Create Party (if new)
        if party_mode == 'new':
            selected_party = Party.objects.create(
                name=new_party_name,
                abbreviation=new_party_abbr, # Save Abbr
                symbol=new_party_symbol
            )

        # 3. Create Candidate
        is_independent = (party_mode == 'independent')
        
        try:
            election_obj = Election.objects.get(id=election_id)
            # const_obj = ... (If you removed constituency, ignore this)
            
            Candidate.objects.create(
                user=user,
                name=f"{fname} {lname}",
                election=election_obj,
                party=selected_party,
                # constituency=... (If removed, ignore),
                is_independent=is_independent,
                candidate_photo=candidate_photo
            )
        except Exception as e:
            user.delete() # Rollback
            error_context['error'] = f"Error creating profile: {e}"
            return render(request, 'votingApp/candidate_register.html', error_context)

        # 4. OTP Logic (Same as before)
        otp = random.randint(100000, 999999)
        request.session['verification_otp'] = otp
        request.session['verification_user_id'] = user.id
        request.session['otp_creation_time'] = time.time()
        
        try:
            send_mail('Candidate Verification', f'OTP: {otp}', settings.DEFAULT_FROM_EMAIL, [email])
        except Exception as e:
            user.delete()
            error_context['error'] = f'Email failed: {e}'
            return render(request, 'votingApp/candidate_register.html', error_context)

        return redirect('verify_otp')

    context = {'elections': elections, 'parties': parties, 'states': state_choices}
    return render(request, 'votingApp/candidate_register.html', context)

    
def candidate_login(request):
    if request.method == "POST":
        username = request.POST.get("username")
        passw = request.POST.get("password")

        user = authenticate(request, username=username, password=passw)

        if user is not None:
            # 1. Check if they are a candidate
            if hasattr(user, "candidate"):

                # --- ROBUST PROFILE CHECK (Fixes 500 Error) ---
                try:
                    profile = user.userprofile
                except UserProfile.DoesNotExist:
                    messages.error(
                        request, "Critical Error: No User Profile found. Contact Admin."
                    )
                    return render(request, "votingApp/candidate_login.html")
                # ----------------------------------------------

                # 2. Check if Admin has verified them
                if not profile.is_verified:
                    messages.error(
                        request,
                        "Your candidacy is pending approval. Please wait for Admin verification.",
                    )
                    return render(request, "votingApp/candidate_login.html")

                # 3. Check if Email is verified (OTP)
                if not profile.is_email_verified:
                    messages.error(request, "Please verify your email first.")
                    return render(request, "votingApp/candidate_login.html")

                # If all checks pass, log them in
                login(request, user)
                return redirect("candidate_dashboard")
            else:
                messages.error(request, "User is not a registered candidate.")
        else:
            messages.error(request, "Invalid username or password.")

    return render(request, "votingApp/candidate_login.html")


@login_required
def candidate_dashboard(request):
    candidate = request.user.candidate

    if request.method == "POST":
        choice = request.POST.get("party_choice")  # independent, existing, new

        if choice == "independent":
            candidate.party = None
            candidate.save()
            messages.success(request, "You are now an Independent candidate.")

        elif choice == "existing":
            party_id = request.POST.get("existing_party_id")
            if party_id:
                candidate.party = Party.objects.get(id=party_id)
                candidate.save()
                messages.success(request, f"Joined {candidate.party.name}.")

        elif choice == "new":
            new_party_name = request.POST.get("new_party_name")
            if new_party_name:
                # Create new party if it doesn't exist
                party, created = Party.objects.get_or_create(name=new_party_name)
                candidate.party = party
                candidate.save()
                messages.success(request, f"Created and joined party: {party.name}")

        # --- THE FIX IS HERE ---
        # Correct: Redirect to the URL name, without 'request'
        return redirect('candidate_dashboard')

    # Pass all parties to template for the dropdown
    parties = Party.objects.all()
    return render(
        request,
        "votingApp/candidate_dashboard.html",
        {"candidate": candidate, "parties": parties},
    )