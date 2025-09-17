"""
Initial migration for the payments app.

Creates the TicketPlan and TicketPurchase tables with the necessary
indexes and fields for managing paid ticketing.  The purchase
table references events, users and plans and stores the Stripe
PaymentIntent identifier and purchase status.
"""
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("organizations", "0001_initial"),
        ("events", "0001_initial"),
        migrations.swappable_dependency("auth.User"),
    ]

    operations = [
        migrations.CreateModel(
            name="TicketPlan",
            fields=[
                ("id", models.BigAutoField(primary_key=True, serialize=False)),
                ("name", models.CharField(max_length=255)),
                (
                    "price_cents",
                    models.PositiveIntegerField(help_text="Ticket price in cents"),
                ),
                (
                    "currency",
                    models.CharField(default="usd", max_length=10),
                ),
                (
                    "stripe_price_id",
                    models.CharField(
                        blank=True,
                        help_text="Corresponding Stripe Price identifier",
                        max_length=255,
                    ),
                ),
                ("is_active", models.BooleanField(default=True)),
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
                        related_name="ticket_plans",
                        to="organizations.organization",
                    ),
                ),
            ],
            options={"ordering": ["-created_at"]},
        ),
        migrations.AddIndex(
            model_name="ticketplan",
            index=models.Index(fields=["organization", "is_active"], name="payments_ticketplan_org_active_idx"),
        ),
        migrations.CreateModel(
            name="TicketPurchase",
            fields=[
                ("id", models.BigAutoField(primary_key=True, serialize=False)),
                (
                    "stripe_payment_intent_id",
                    models.CharField(
                        blank=True,
                        help_text="Associated Stripe PaymentIntent identifier",
                        max_length=255,
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "Pending"),
                            ("succeeded", "Succeeded"),
                            ("failed", "Failed"),
                        ],
                        default="pending",
                        max_length=10,
                    ),
                ),
                (
                    "amount_cents",
                    models.PositiveIntegerField(
                        help_text="Charged amount in cents"
                    ),
                ),
                (
                    "currency",
                    models.CharField(max_length=10),
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
                    "event",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="ticket_purchases",
                        to="events.event",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="ticket_purchases",
                        to="auth.user",
                    ),
                ),
                (
                    "plan",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="purchases",
                        to="payments.ticketplan",
                    ),
                ),
            ],
            options={"ordering": ["-created_at"]},
        ),
        migrations.AddIndex(
            model_name="ticketpurchase",
            index=models.Index(
                fields=["event", "user", "status"],
                name="payments_ticketpurchase_event_user_status_idx",
            ),
        ),
    ]
