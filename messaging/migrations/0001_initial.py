"""
Initial migration for the messaging app.

Defines the Conversation and Message models with necessary constraints
and indexes to enforce uniqueness and optimize queries.
"""
from django.db import migrations, models
import django.db.models.deletion
import django.contrib.postgres.fields


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("users", "0002_alter_userprofile_id_linkedinaccount"),
    ]

    operations = [
        migrations.CreateModel(
            name="Conversation",
            fields=[
                ("id", models.BigAutoField(primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("user1", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="conversations_as_user1",
                    to="users.user",
                )),
                ("user2", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="conversations_as_user2",
                    to="users.user",
                )),
            ],
            options={},
        ),
        migrations.AddConstraint(
            model_name="conversation",
            constraint=models.UniqueConstraint(
                fields=("user1", "user2"),
                name="unique_conversation_users",
            ),
        ),
        migrations.AddIndex(
            model_name="conversation",
            index=models.Index(
                fields=["user1", "user2"],
                name="messaging_conversation_user1_user2_idx",
            ),
        ),
        migrations.CreateModel(
            name="Message",
            fields=[
                ("id", models.BigAutoField(primary_key=True, serialize=False)),
                ("body", models.TextField()),
                ("attachments", django.contrib.postgres.fields.ArrayField(
                    base_field=models.JSONField(),
                    default=list,
                    blank=True,
                    size=None,
                )),
                ("is_read", models.BooleanField(default=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("conversation", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="messages",
                    to="messaging.conversation",
                )),
                ("sender", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="sent_messages",
                    to="users.user",
                )),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
        migrations.AddIndex(
            model_name="message",
            index=models.Index(
                fields=["conversation", "created_at"],
                name="messaging_message_conversation_created_at_idx",
            ),
        ),
    ]
