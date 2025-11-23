from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    path("",views.home_page, name = "home"),
    path("register/", views.register_page, name = 'register'),
    path("login/", views.login_page, name = 'login'),
    path("logout/", views.logout_page, name = 'logout'),
    path("dashboard/", views.dashboard_page, name = 'dashboard'),
    path("results/", views.results_page, name = 'results'),
    path('vote/<slug:election_slug>/', views.vote_page, name='vote_page'),
    path('profile/', views.profile_page, name='profile'),
    path('verify-otp/', views.verify_otp_page, name='verify_otp'),
    # ... your other paths ...
    path('verify-otp/', views.verify_otp_page, name='verify_otp'),
    
    # --- ADD ALL THESE PATHS FOR PASSWORD RESET ---
    path('password-reset/', 
         auth_views.PasswordResetView.as_view(
             template_name='votingApp/password_reset_form.html'
         ), 
         name='password_reset'),
    
    path('password-reset/done/', 
         auth_views.PasswordResetDoneView.as_view(
             template_name='votingApp/password_reset_done.html'
         ), 
         name='password_reset_done'),
         
    path('password-reset-confirm/<uidb64>/<token>/', 
         auth_views.PasswordResetConfirmView.as_view(
             template_name='votingApp/password_reset_confirm.html'
         ), 
         name='password_reset_confirm'),
         
    path('password-reset-complete/', 
         auth_views.PasswordResetCompleteView.as_view(
             template_name='votingApp/password_reset_complete.html'
         ), 
         name='password_reset_complete'),
    
    path('register/candidate/', views.candidate_register_page, name='candidate_register'),
    path('login/candidate/', views.candidate_login, name='candidate_login'),
    path('dashboard/candidate/',views.candidate_dashboard, name='candidate_dashboard'),
    path('ajax/election-details/', views.get_election_details, name='ajax_election_details'),
]
