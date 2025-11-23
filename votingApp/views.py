from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.models import User
from .models import UserProfile, Election, Candidate, Vote, VoterRecord, Party
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from django.db.models import Q, Count
from django.contrib import messages
import random
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.conf import settings
from django.http import JsonResponse
import time
import re # Required for password complexity checks

# --- HELPER: Generate Unique Voter ID ---
def generate_unique_voter_id(state_code):
    state_map = {
        "AP": "AND", "AR": "ARN", "AS": "ASM", "BR": "BIH", "CT": "CHT",
        "GA": "GOA", "GJ": "GUJ", "HR": "HAR", "HP": "HIM", "JH": "JHA",
        "KA": "KAR", "KL": "KER", "MP": "MDP", "MH": "MAH", "MN": "MNP",
        "ML": "MEG", "MZ": "MIZ", "NL": "NAG", "OR": "ODI", "PB": "PUN",
        "RJ": "RAJ", "SK": "SIK", "TN": "TND", "TG": "TEL", "TR": "TRI",
        "UP": "UTP", "UK": "UTK", "WB": "WBE", "DL": "DEL",
    }
    prefix = state_map.get(state_code, state_code).upper()
    while True:
        numbers = random.randint(1000000, 9999999)
        new_id = f"{prefix}{numbers}"
        if not User.objects.filter(username=new_id).exists():
            return new_id

# --- HELPER: Check Password Complexity ---
def check_password_complexity(password):
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not re.search(r'[A-Z]', password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r'\d', password):
        return "Password must contain at least one number."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return "Password must contain at least one special character (e.g. @, #, $)."
    return None

def get_election_details(request):
    election_id = request.GET.get("election_id")
    if election_id:
        try:
            election = Election.objects.get(id=election_id)
            return JsonResponse({
                "type": election.election_type,
                "state": election.state,
            })
        except Election.DoesNotExist:
            return JsonResponse({"error": "Election not found"}, status=404)
    return JsonResponse({"error": "Invalid request"}, status=400)


# --- 1. Home Page ---
def home_page(request):
    try:
        total_voters = UserProfile.objects.filter(is_verified=True).count()
        total_votes_cast = VoterRecord.objects.count()
        if total_voters > 0:
            turnout = (total_votes_cast / (total_voters * Election.objects.count())) * 100
            turnout_percentage = round(turnout, 1)
        else:
            turnout_percentage = 0
    except Exception:
        turnout_percentage = 0
    context = {"turnout_percentage": turnout_percentage}
    return render(request, "votingApp/home.html", context)


# --- 2. Voter Registration ---
def register_page(request):
    context = {"states": UserProfile.StateChoices.choices, "active_tab": "voter"}
    
    # Pass candidate data in case they switch tabs
    context['elections'] = Election.objects.all()
    context['parties'] = Party.objects.all()

    if request.method == "POST":
        email = request.POST.get("email")
        pass1 = request.POST.get("password")
        pass2 = request.POST.get("confirm_password")
        fname = request.POST.get("first_name")
        lname = request.POST.get("last_name")
        age = request.POST.get("age")
        state = request.POST.get("state")

        if User.objects.filter(email=email).exists():
            context["error"] = "This Email is already registered."
            return render(request, "votingApp/register.html", context)

        if pass1 != pass2:
            context["error"] = "Passwords do not match."
            return render(request, "votingApp/register.html", context)
            
        # --- 1. Check Custom Complexity (Capital, Number, Special Char) ---
        complexity_error = check_password_complexity(pass1)
        if complexity_error:
            context["error"] = complexity_error
            return render(request, "votingApp/register.html", context)

        # --- Generate ID ---
        generated_voter_id = generate_unique_voter_id(state)

        # --- 2. Check Django Validators (Common Password, User Similarity) ---
        try:
            validate_password(pass1, user=User(username=generated_voter_id))
        except ValidationError as e:
            context["error"] = " ".join(e.messages)
            return render(request, "votingApp/register.html", context)

        new_user = User.objects.create_user(
            username=generated_voter_id, 
            password=pass1, 
            email=email, 
            is_active=False
        )
        new_user.first_name = fname
        new_user.last_name = lname
        new_user.save()

        UserProfile.objects.create(user=new_user, age=age, state=state)

        otp = random.randint(100000, 999999)
        request.session["verification_otp"] = otp
        request.session["verification_user_id"] = new_user.id
        request.session["otp_creation_time"] = time.time()

        try:
            send_mail(
                "Your e-Chayan OTP", 
                f"OTP: {otp}\nYour Voter ID is: {generated_voter_id}", 
                settings.DEFAULT_FROM_EMAIL, 
                [email]
            )
        except Exception as e:
            new_user.delete()
            context["error"] = f"Email failed: {e}"
            return render(request, "votingApp/register.html", context)

        messages.success(request, f"Registration successful! Your Voter ID is {generated_voter_id}. Check email for OTP.")
        return redirect("verify_otp")

    return render(request, "votingApp/register.html", context)


# --- 3. OTP Verification ---
def verify_otp_page(request):
    try:
        stored_otp = request.session.get("verification_otp")
        user_id = request.session.get("verification_user_id")
        otp_creation_time = request.session.get("otp_creation_time")

        if not stored_otp or not user_id or not otp_creation_time:
            messages.error(request, "Session expired.")
            return redirect("register")

        if (time.time() - otp_creation_time) > 600:
            try:
                User.objects.get(id=user_id, is_active=False).delete()
            except User.DoesNotExist:
                pass
            request.session.flush()
            messages.error(request, "OTP expired. Please register again.")
            return redirect("register")
    except KeyError:
        return redirect("register")

    if request.method == "POST":
        submitted_otp = request.POST.get("otp")
        if int(submitted_otp) == stored_otp:
            user = User.objects.get(id=user_id)
            user.is_active = True
            user.save()
            user.userprofile.is_email_verified = True
            user.userprofile.save()
            request.session.flush()
            
            messages.success(request, "Email verified! You can now log in.")
            return redirect("login")
        else:
            return render(request, "votingApp/verify_otp.html", {"error": "Invalid OTP."})
    return render(request, "votingApp/verify_otp.html")


# --- 4. Voter Login ---
def login_page(request):
    context = {"active_tab": "voter"}
    if request.method == "POST":
        login_input = request.POST.get("username") # Could be ID or Email
        password = request.POST.get("password")
        
        username_to_auth = login_input
        if "@" in login_input:
            try:
                user_obj = User.objects.get(email=login_input)
                username_to_auth = user_obj.username
            except User.DoesNotExist:
                pass

        try:
            user_exists = User.objects.get(username=username_to_auth)
            if not user_exists.is_active:
                messages.error(request, "Account inactive. Verify email first.")
                return render(request, "votingApp/login.html", context)
        except User.DoesNotExist:
            pass
        
        user = authenticate(request, username=username_to_auth, password=password)
        if user is not None:
            login(request, user)
            return redirect("dashboard")
        else:
            context["error"] = "Invalid credentials."
            return render(request, "votingApp/login.html", context)
    return render(request, "votingApp/login.html", context)


# --- 5. Logout ---
def logout_page(request):
    logout(request)
    return redirect("home")


# --- 6. Voter Dashboard ---
@login_required
def dashboard_page(request):
    try:
        profile = request.user.userprofile
    except UserProfile.DoesNotExist:
        logout(request)
        messages.error(request, "Profile missing. Please register again.")
        return redirect("register")

    now = timezone.now()
    active_elections = Election.objects.filter(start_time__lte=now, end_time__gte=now)
    
    eligible_elections_query = active_elections.filter(
        Q(election_type=Election.Electiontype.NATIONAL) | 
        Q(election_type=Election.Electiontype.STATE, state=profile.state)
    )
    
    voted_election_ids = VoterRecord.objects.filter(user=request.user).values_list("election_id", flat=True)
    
    eligible_elections = []
    if profile.is_verified:
        for election in eligible_elections_query:
            if election.id in voted_election_ids:
                election.user_has_voted = True
            else:
                election.user_has_voted = False
            eligible_elections.append(election)

    context = {"user_profile": profile, "eligible_elections": eligible_elections}
    return render(request, "votingApp/voting_dashboard.html", context)


# --- 7. Profile Page ---
@login_required
def profile_page(request):
    user = request.user
    try:
        profile = user.userprofile
    except UserProfile.DoesNotExist:
        profile = UserProfile.objects.create(user=user, age=18, state='MH')

    states = UserProfile.StateChoices.choices

    if request.method == "POST":
        user.first_name = request.POST.get("first_name")
        user.last_name = request.POST.get("last_name")
        user.email = request.POST.get("email")
        user.save()
        
        try:
            profile.age = int(request.POST.get("age"))
            if profile.age < 18:
                messages.error(request, "Age must be 18+")
                return redirect("profile")
        except ValueError:
            pass
            
        profile.state = request.POST.get("state")
        
        if 'profile_photo' in request.FILES:
            profile.profile_photo = request.FILES['profile_photo']
            
        profile.save()
        messages.success(request, "Profile Updated.")
        return redirect("profile")

    context = {"user": user, "profile": profile, "states": states}
    return render(request, "votingApp/profile.html", context)


# --- 8. Results Page ---
def results_page(request):
    now = timezone.now()
    elections = Election.objects.all()
    elections_with_results = []
    for election in elections:
        if election.end_time > now:
            election.is_active = True
        else:
            election.is_active = False
            results_dict = {}
            winner = None
            max_votes = -1
            candidates = election.candidates.all()
            for candidate in candidates:
                vote_count = Vote.objects.filter(candidate=candidate).count()
                results_dict[candidate] = vote_count
                if vote_count > max_votes:
                    max_votes = vote_count
                    winner = candidate
            election.results = dict(sorted(results_dict.items(), key=lambda item: item[1], reverse=True))
            election.winner = winner
        elections_with_results.append(election)
    return render(request, "votingApp/results.html", {"elections_with_results": elections_with_results})


# --- 9. Vote Page ---
@login_required
def vote_page(request, election_slug):
    election = get_object_or_404(Election, slug=election_slug)
    try:
        profile = request.user.userprofile
    except UserProfile.DoesNotExist:
        messages.error(request, "Profile error.")
        return redirect("dashboard")

    now = timezone.now()

    if not profile.is_email_verified:
        messages.error(request, "Verify email first.")
        return redirect("dashboard")
    if not profile.is_verified:
        messages.error(request, "Not verified by Admin.")
        return redirect("dashboard")
    if not (election.start_time <= now and election.end_time >= now):
        messages.error(request, "Election closed.")
        return redirect("dashboard")
    
    is_eligible = election.election_type == Election.Electiontype.NATIONAL or (
        election.election_type == Election.Electiontype.STATE and election.state == profile.state
    )
    if not is_eligible:
        messages.error(request, "Not eligible.")
        return redirect("dashboard")
        
    if VoterRecord.objects.filter(user=request.user, election=election).exists():
        messages.error(request, "Already voted.")
        return redirect("dashboard")

    if request.method == "POST":
        candidate_id = request.POST.get("candidate")
        if not candidate_id:
            messages.error(request, "Select a candidate.")
            return render(request, "votingApp/vote_page.html", {"election": election})
        
        selected_candidate = get_object_or_404(Candidate, id=candidate_id)
        Vote.objects.create(candidate=selected_candidate, election=election)
        VoterRecord.objects.create(user=request.user, election=election)
        messages.success(request, "Vote Cast Successfully!")
        return redirect("dashboard")

    return render(request, "votingApp/vote_page.html", {"election": election})


# --- 10. Candidate Registration ---
def candidate_register_page(request):
    elections = Election.objects.all()
    parties = Party.objects.all()
    state_choices = UserProfile.StateChoices.choices

    context = {
        'elections': elections, 
        'parties': parties, 
        'states': state_choices, 
        'active_tab': 'candidate'
    }

    if request.method == 'POST':
        email = request.POST.get('email')
        pass1 = request.POST.get('password')
        pass2 = request.POST.get('confirm_password')
        fname = request.POST.get('first_name')
        lname = request.POST.get('last_name')
        election_id = request.POST.get('election_id')
        
        # Determine State
        election_obj = Election.objects.get(id=election_id)
        if election_obj.election_type == Election.Electiontype.STATE:
            selected_state = election_obj.state
        else:
            selected_state = request.POST.get('state')

        party_mode = request.POST.get('party_select')
        candidate_photo = request.FILES.get('candidate_photo')
        
        # Party Data
        new_party_name = request.POST.get('new_party_name')
        new_party_abbr = request.POST.get('new_party_abbr')
        new_party_symbol = request.FILES.get('new_party_symbol')

        if pass1 != pass2:
            context['error'] = "Passwords do not match."
            return render(request, 'votingApp/register.html', context)
        
        if User.objects.filter(email=email).exists():
            context['error'] = "Email already registered."
            return render(request, 'votingApp/register.html', context)

        # --- 1. Check Custom Complexity ---
        complexity_error = check_password_complexity(pass1)
        if complexity_error:
            context["error"] = complexity_error
            return render(request, "votingApp/register.html", context)

        # --- Generate ID ---
        generated_voter_id = generate_unique_voter_id(selected_state)

        # --- 2. Check Django Validators ---
        try:
            validate_password(pass1, user=User(username=generated_voter_id))
        except ValidationError as e:
            context['error'] = " ".join(e.messages)
            return render(request, 'votingApp/register.html', context)
        
        # --- PARTY CHECK ---
        selected_party = None
        if party_mode == 'existing':
            selected_party = Party.objects.get(id=request.POST.get('existing_party_id'))
        elif party_mode == 'new':
            if Party.objects.filter(name=new_party_name).exists():
                context['error'] = f"Party '{new_party_name}' exists."
                return render(request, 'votingApp/register.html', context)
            if new_party_abbr and Party.objects.filter(abbreviation=new_party_abbr).exists():
                context['error'] = f"Abbreviation '{new_party_abbr}' exists."
                return render(request, 'votingApp/register.html', context)

        # --- CREATE ---
        user = User.objects.create_user(
            username=generated_voter_id, # Use generated ID 
            email=email, 
            password=pass1, 
            is_active=False
        )
        user.first_name = fname
        user.last_name = lname
        user.save()
        
        UserProfile.objects.create(
            user=user, 
            age=25, 
            state=selected_state, 
            is_verified=False,
            profile_photo=candidate_photo # Save photo to user profile too for sidebar
        )

        if party_mode == 'new':
            selected_party = Party.objects.create(name=new_party_name, abbreviation=new_party_abbr, symbol=new_party_symbol)

        try:
            Candidate.objects.create(
                user=user,
                name=f"{fname} {lname}",
                election=election_obj,
                party=selected_party,
                is_independent=(party_mode == 'independent'),
                candidate_photo=candidate_photo
            )
        except Exception as e:
            user.delete()
            context['error'] = f"Error: {e}"
            return render(request, 'votingApp/register.html', context)

        otp = random.randint(100000, 999999)
        request.session['verification_otp'] = otp
        request.session['verification_user_id'] = user.id
        request.session['otp_creation_time'] = time.time()
        
        try:
            send_mail(
                'Candidate Verification', 
                f'OTP: {otp}\nYour Candidate ID is: {generated_voter_id}', 
                settings.DEFAULT_FROM_EMAIL, 
                [email]
            )
        except Exception as e:
            user.delete()
            context['error'] = f"Email Error: {e}"
            return render(request, 'votingApp/register.html', context)

        messages.success(request, f"Registration successful! Your Candidate ID is {generated_voter_id}. Verify email.")
        return redirect('verify_otp')

    return render(request, 'votingApp/register.html', context)


# --- 11. Candidate Login ---
def candidate_login(request):
    context = {"active_tab":"candidate"}
    if request.method == "POST":
        username = request.POST.get("username")
        passw = request.POST.get("password")
        
        username_to_auth = username
        if "@" in username:
            try:
                user_obj = User.objects.get(email=username)
                username_to_auth = user_obj.username
            except User.DoesNotExist:
                pass
        
        user = authenticate(request, username=username_to_auth, password=passw)

        if user is not None:
            if hasattr(user, "candidate"):
                try:
                    profile = user.userprofile
                except UserProfile.DoesNotExist:
                    context['error'] = "Critical Error: No Profile."
                    return render(request, "votingApp/login.html", context)

                if not profile.is_verified:
                    context['error'] = "Pending Admin Approval."
                    return render(request, "votingApp/login.html", context)
                if not profile.is_email_verified:
                    context['error'] = "Verify Email First."
                    return render(request, "votingApp/login.html", context)

                login(request, user)
                return redirect("candidate_dashboard")
            else:
                context['error'] = "Not a registered candidate."
                return render(request, "votingApp/login.html", context)
        else:
            context['error'] = "Invalid credentials."
            return render(request, "votingApp/login.html", context)
            
    return render(request, "votingApp/login.html", context)


# --- 12. Candidate Dashboard ---
@login_required
def candidate_dashboard(request):
    try:
        candidate = request.user.candidate
    except:
        return redirect('dashboard') 

    if request.method == "POST":
        choice = request.POST.get("party_choice")
        
        if choice == "independent":
            candidate.party = None
            candidate.is_independent = True
            candidate.save()
            messages.success(request, "You are now Independent.")

        elif choice == "existing":
            party_id = request.POST.get("existing_party_id")
            if party_id:
                candidate.party = Party.objects.get(id=party_id)
                candidate.is_independent = False
                candidate.save()
                messages.success(request, f"Joined {candidate.party.name}.")

        elif choice == "new":
            new_party_name = request.POST.get("new_party_name")
            new_party_abbr = request.POST.get("new_party_abbr")
            new_party_symbol = request.FILES.get("new_party_symbol")
            
            if new_party_name:
                if Party.objects.filter(name=new_party_name).exists():
                    messages.error(request, "Party name exists.")
                    return redirect('candidate_dashboard')
                if new_party_abbr and Party.objects.filter(abbreviation=new_party_abbr).exists():
                    messages.error(request, "Abbreviation exists.")
                    return redirect('candidate_dashboard')
                
                party = Party.objects.create(
                    name=new_party_name, 
                    abbreviation=new_party_abbr,
                    symbol=new_party_symbol
                )
                candidate.party = party
                candidate.is_independent = False
                candidate.save()
                messages.success(request, f"Created {party.name}.")

        return redirect('candidate_dashboard')

    parties = Party.objects.all()
    return render(request, "votingApp/candidate_dashboard.html", {"candidate": candidate, "parties": parties})