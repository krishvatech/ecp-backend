"""
Initial migration for the organizations app.

Creates the Organization model with a many-to-many relationship to
members and a foreign key to the owner.
"""
from django.db import migrations, models
import django.db.models.deletion
from django.conf import settings


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Organization",
            fields=[
                ("id", models.BigAutoField(primary_key=True, serialize=False)),
                ("name", models.CharField(max_length=255, unique=True)),
                ("slug", models.SlugField(blank=True, max_length=255, unique=True)),
                ("description", models.TextField(blank=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("owner", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="owned_organizations", to=settings.AUTH_USER_MODEL)),
                ("members", models.ManyToManyField(blank=True, related_name="organizations", to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]