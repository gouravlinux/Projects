from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.models import User
from .models import UserProfile, Election, Candidate, Vote, VoterRecord
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

    context = {"turnout_percentage": turnout_percentage}
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


# --- ADD THIS NEW VIEW ---
# In votingApp/views.py


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
    now = timezone.now()
    profile = request.user.userprofile

    # 1. Get all active elections
    active_elections = Election.objects.filter(start_time__lte=now, end_time__gte=now)

    # 2. Filter for eligibility (Verified + (National OR correct State))
    eligible_elections_query = active_elections.filter(
        Q(election_type=Election.Electiontype.NATIONAL)
        | Q(election_type=Election.Electiontype.STATE, state=profile.state)
    )

    # 3. Get list of elections this user has ALREADY voted in
    voted_election_ids = VoterRecord.objects.filter(user=request.user).values_list(
        "election_id", flat=True
    )

    eligible_elections = []

    # 4. Process the list to add the 'user_has_voted' status
    if profile.is_verified:  # Only show elections if user is verified
        for election in eligible_elections_query:
            if election.id in voted_election_ids:
                election.user_has_voted = True
            else:
                election.user_has_voted = False
            eligible_elections.append(election)

    context = {
        "user_profile": profile,  # This is for the "Your Profile" card
        "eligible_elections": eligible_elections,  # For the "Available Elections" list
    }

    # --- FIXED Template Path ---
    return render(request, "votingApp/voting_dashboard.html", context)


# At the bottom of votingApp/views.py

# from django.contrib import messages


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
