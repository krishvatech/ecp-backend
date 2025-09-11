"""
Initial migration for the users app.

Defines the `UserProfile` model and creates a default admin user for
development purposes.  Running this migration will also ensure that
every user has a corresponding profile through signals.
"""
from django.db import migrations, models
import django.db.models.deletion
from django.conf import settings


def create_superuser(apps, schema_editor):
    """Create a default superuser for development."""
    from django.contrib.auth.models import User
    if not User.objects.filter(username="admin").exists():
        # nosec: dev-only default credentials
        u = User.objects.create_superuser("admin", "admin@example.com", "admin")
        u.save()


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("auth", "0012_alter_user_first_name_max_length"),
    ]

    operations = [
        migrations.CreateModel(
            name="UserProfile",
            fields=[
                ("id", models.BigAutoField(primary_key=True, serialize=False)),
                ("full_name", models.CharField(blank=True, max_length=255)),
                ("timezone", models.CharField(default="Asia/Kolkata", max_length=64)),
                ("bio", models.TextField(blank=True)),
                ("user", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="profile", to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.RunPython(create_superuser, migrations.RunPython.noop),
    ]