"""
Initial migration for the activity_feed app.

Defines the ``FeedItem`` model and its indexes.  Feed items record
actions within the platform, linking to organizations, events, users
and arbitrary targets via Django’s generic foreign keys.
"""
from django.db import migrations, models
import django.db.models.deletion
from django.conf import settings

class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("contenttypes", "0002_remove_content_type_name"),
        ("organizations", "0001_initial"),
        ("events", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="FeedItem",
            fields=[
                ("id", models.BigAutoField(primary_key=True, serialize=False)),
                ("organization", models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="feed_items",
                    to="organizations.organization",
                )),
                ("event", models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="feed_items",
                    to="events.event",
                )),
                ("actor", models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="activity_feed_items",
                    to=settings.AUTH_USER_MODEL,
                )),
                ("verb", models.CharField(max_length=255)),
                ("target_content_type", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="feed_items",
                    to="contenttypes.contenttype",
                )),
                ("target_object_id", models.PositiveIntegerField()),
                ("metadata", models.JSONField(default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
            options={"ordering": ["-created_at"]},
        ),
        migrations.AddIndex(
            model_name="feeditem",
            index=models.Index(
                fields=["organization", "event", "created_at"],
                name="activity_fe_org_event_created",
            ),
        ),
    ]
