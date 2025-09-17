"""
Initial migration for the content app.

Creates the ``Resource`` model with fields to store files, links and
videos associated with organizations and optionally events.  Also
defines a composite index to support common filtering use cases.
"""
from django.db import migrations, models
import django.db.models.deletion
from django.conf import settings
import django.contrib.postgres.fields

class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("organizations", "0001_initial"),
        ("events", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Resource",
            fields=[
                ("id", models.BigAutoField(primary_key=True, serialize=False)),
                ("title", models.CharField(max_length=255)),
                ("description", models.TextField(blank=True)),
                ("type", models.CharField(
                    choices=[("file", "File"), ("link", "Link"), ("video", "Video")],
                    max_length=10,
                )),
                ("file", models.FileField(blank=True, null=True, upload_to="resources/files/")),
                ("link_url", models.URLField(blank=True)),
                ("video_url", models.URLField(blank=True)),
                ("tags", django.contrib.postgres.fields.ArrayField(
                    base_field=models.CharField(max_length=50),
                    default=list,
                    blank=True,
                    size=None,
                )),
                ("is_published", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("organization", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="resources",
                    to="organizations.organization",
                )),
                ("event", models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="resources",
                    to="events.event",
                )),
                ("uploaded_by", models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="uploaded_resources",
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={"ordering": ["-created_at"]},
        ),
        migrations.AddIndex(
            model_name="resource",
            index=models.Index(
                fields=["organization", "event", "type", "is_published"],
                name="content_res_org_event_type_published",
            ),
        ),
    ]
