from django.contrib import admin
from .models import Candidate, Election, Party, Vote, VoterRecord, UserProfile

# Register your models here.

admin.site.register(UserProfile)
admin.site.register(Election)
admin.site.register(Party)
admin.site.register(Candidate)
admin.site.register(Vote)
admin.site.register(VoterRecord)


