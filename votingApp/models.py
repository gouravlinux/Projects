from django.db import models
from django.contrib.auth.models import User
from django.utils.text import slugify
from django.core.validators import MinValueValidator, MaxValueValidator 


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    age = models.IntegerField(
        default=1, validators=[MinValueValidator(18), MaxValueValidator(100)]
    )

    class StateChoices(models.TextChoices):
        ANDHRA_PRADESH = "AP", "Andhra Pradesh"
        ARUNACHAL_PRADESH = "AR", "Arunachal Pradesh"
        ASSAM = "AS", "Assam"
        BIHAR = "BR", "Bihar"
        CHHATTISGARH = "CT", "Chhattisgarh"
        GOA = "GA", "Goa"
        GUJARAT = "GJ", "Gujarat"
        HARYANA = "HR", "Haryana"
        HIMACHAL_PRADESH = "HP", "Himachal Pradesh"
        JHARKHAND = "JH", "Jharkhand"
        KARNATAKA = "KA", "Karnataka"
        KERALA = "KL", "Kerala"
        MADHYA_PRADESH = "MP", "Madhya Pradesh"
        MAHARASHTRA = "MH", "Maharashtra"

    state = models.CharField(max_length=2, choices=StateChoices.choices)
    is_verified = models.BooleanField(default=False)


class Election(models.Model):
    class Electiontype(models.TextChoices):
        NATIONAL = "N", "National"
        STATE = "S", "State"

    name = models.CharField(max_length=200)
    slug = models.SlugField(
        unique=True,
        blank=True,
        help_text="A unique URL-friendly name. Will be auto-generated from the name.",
    )
    description = models.TextField(blank=True)
    election_type = models.CharField(max_length=1, choices=Electiontype.choices)
    state = models.CharField(
        max_length=2,
        choices=UserProfile.StateChoices.choices,
        blank=True,
        null=True,
        help_text="Only required for State elections.",
    )
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name


class Party(models.Model):
    name = models.CharField(max_length=100, unique=True)
    symbol = models.ImageField(
        upload_to="party_symbols/", help_text="Party logo or symbol"
    )

    def __str__(self):
        return self.name


class Candidate(models.Model):
    name = models.CharField(max_length=200)
    election = models.ForeignKey(
        Election, on_delete=models.CASCADE, related_name="candidates"
    )
    party = models.ForeignKey(Party, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return self.name


class Vote(models.Model):
    candidate = models.ForeignKey(Candidate, on_delete=models.CASCADE)
    election = models.ForeignKey(Election, on_delete=models.CASCADE)

    def __str__(self):
        return f"A vote for {self.candidate.name} in {self.election.name}"


class VoterRecord(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    election = models.ForeignKey(Election, on_delete=models.CASCADE)

    class Meta:
        unique_together = ("user", "election")

    def __str__(self):
        return f"{self.user.username} voted in {self.election.name}"
