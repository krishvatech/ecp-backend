"""
Initial migration for the analytics app.

Creates the MetricDaily model with fields for aggregating usage
metrics by date, organization and event.  Enforces a unique
constraint on (organization, event, date) to prevent duplicate
rows.
"""
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("organizations", "0001_initial"),
        ("events", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="MetricDaily",
            fields=[
                ("id", models.BigAutoField(primary_key=True, serialize=False)),
                ("date", models.DateField()),
                ("message_count", models.PositiveIntegerField(default=0)),
                ("resource_count", models.PositiveIntegerField(default=0)),
                ("registrations_count", models.PositiveIntegerField(default=0)),
                ("purchases_count", models.PositiveIntegerField(default=0)),
                ("revenue_cents", models.BigIntegerField(default=0)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "organization",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="metric_dailies",
                        to="organizations.organization",
                    ),
                ),
                (
                    "event",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="metric_dailies",
                        to="events.event",
                    ),
                ),
            ],
            options={"ordering": ["-date"]},
        ),
        migrations.AlterUniqueTogether(
            name="metricdaily",
            unique_together={("organization", "event", "date")},
        ),
    ]
