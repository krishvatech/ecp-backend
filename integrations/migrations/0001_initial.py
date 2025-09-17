"""
Initial migration for the integrations app.

Creates tables for IntegrationConfig and SyncLog.  Configs are
unique per organization and integration type.  Sync logs index on
organization, integration type and creation time to speed up
queries.
"""
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("organizations", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="IntegrationConfig",
            fields=[
                ("id", models.BigAutoField(primary_key=True, serialize=False)),
                (
                    "type",
                    models.CharField(choices=[("hubspot", "HubSpot")], max_length=50),
                ),
                ("enabled", models.BooleanField(default=False)),
                (
                    "secrets",
                    models.JSONField(
                        blank=True,
                        default=dict,
                        help_text="Sensitive credentials (e.g. API tokens) for the integration.",
                    ),
                ),
                (
                    "settings",
                    models.JSONField(
                        blank=True,
                        default=dict,
                        help_text="Non-sensitive configuration values (e.g. property mappings).",
                    ),
                ),
                (
                    "created_at",
                    models.DateTimeField(auto_now_add=True),
                ),
                (
                    "updated_at",
                    models.DateTimeField(auto_now=True),
                ),
                (
                    "organization",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="integration_configs",
                        to="organizations.organization",
                    ),
                ),
            ],
            options={"ordering": ["-created_at"]},
        ),
        migrations.AlterUniqueTogether(
            name="integrationconfig",
            unique_together={("organization", "type")},
        ),
        migrations.CreateModel(
            name="SyncLog",
            fields=[
                ("id", models.BigAutoField(primary_key=True, serialize=False)),
                (
                    "integration_type",
                    models.CharField(max_length=50),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[("success", "Success"), ("failed", "Failed")],
                        max_length=20,
                    ),
                ),
                (
                    "payload_snippet",
                    models.TextField(blank=True, help_text="Partial payload sent to the integration."),
                ),
                (
                    "error",
                    models.TextField(blank=True, help_text="Error message if the sync failed."),
                ),
                (
                    "created_at",
                    models.DateTimeField(auto_now_add=True),
                ),
                (
                    "updated_at",
                    models.DateTimeField(auto_now=True),
                ),
                (
                    "organization",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="integration_sync_logs",
                        to="organizations.organization",
                    ),
                ),
            ],
            options={"ordering": ["-created_at"]},
        ),
        migrations.AddIndex(
            model_name="synclog",
            index=models.Index(
                fields=["organization", "integration_type", "created_at"],
                name="integrations_synclog_org_inttype_created_idx",
            ),
        ),
    ]
