from django.contrib.auth import get_user_model
from rest_framework.test import APITransactionTestCase

from community.models import Community
from groups.models import Group
from groups.serializers import GroupSerializer


User = get_user_model()


class GroupShortDescriptionAndWordLimitTests(APITransactionTestCase):
    """
    Covers the short headline field and the 2000-word description rule without
    touching existing group permissions, membership or sync behaviour.
    """

    def setUp(self):
        self.owner = User.objects.create_user(
            username="short-desc-owner",
            email="short-desc-owner@example.com",
            password="pass1234",
        )
        self.community = Community.objects.create(
            name="Short Description Test Community",
            owner=self.owner,
        )

    def _group(self, **overrides):
        values = {
            "name": "AI Community",
            "description": "Long detailed community information.",
            "community": self.community,
            "owner": self.owner,
            "created_by": self.owner,
            "visibility": Group.VISIBILITY_PUBLIC,
            "join_policy": Group.JOIN_OPEN,
        }
        values.update(overrides)
        return Group.objects.create(**values)

    def test_short_description_defaults_to_blank_for_existing_groups(self):
        group = self._group()

        group.refresh_from_db()
        self.assertEqual(group.short_description, "")
        self.assertIn("short_description", GroupSerializer(group).data)
        self.assertEqual(GroupSerializer(group).data["short_description"], "")

    def test_short_description_is_optional_on_create(self):
        serializer = GroupSerializer(data={
            "name": "No Headline Group",
            "description": "Still valid without a headline.",
            "visibility": Group.VISIBILITY_PUBLIC,
            "join_policy": Group.JOIN_OPEN,
        })

        self.assertTrue(serializer.is_valid(), serializer.errors)

    def test_short_description_round_trips_through_serializer(self):
        group = self._group()
        serializer = GroupSerializer(
            group,
            data={"short_description": "Connecting AI professionals worldwide"},
            partial=True,
        )

        self.assertTrue(serializer.is_valid(), serializer.errors)
        serializer.save()
        group.refresh_from_db()

        self.assertEqual(group.short_description, "Connecting AI professionals worldwide")
        self.assertEqual(
            GroupSerializer(group).data["short_description"],
            "Connecting AI professionals worldwide",
        )

    def test_description_at_the_word_limit_is_accepted(self):
        serializer = GroupSerializer(data={
            "name": "At The Limit",
            "description": " ".join(["word"] * Group.DESCRIPTION_MAX_WORDS),
            "visibility": Group.VISIBILITY_PUBLIC,
            "join_policy": Group.JOIN_OPEN,
        })

        self.assertTrue(serializer.is_valid(), serializer.errors)

    def test_description_above_the_word_limit_is_rejected(self):
        serializer = GroupSerializer(data={
            "name": "Too Wordy",
            "description": " ".join(["word"] * (Group.DESCRIPTION_MAX_WORDS + 1)),
            "visibility": Group.VISIBILITY_PUBLIC,
            "join_policy": Group.JOIN_OPEN,
        })

        self.assertFalse(serializer.is_valid())
        self.assertEqual(
            [str(m) for m in serializer.errors["description"]],
            ["Description cannot exceed 2000 words."],
        )

    def test_long_character_description_under_the_word_limit_is_accepted(self):
        # The limit is words, not characters: one very long token still passes.
        serializer = GroupSerializer(data={
            "name": "One Long Word",
            "description": "x" * 20000,
            "visibility": Group.VISIBILITY_PUBLIC,
            "join_policy": Group.JOIN_OPEN,
        })

        self.assertTrue(serializer.is_valid(), serializer.errors)

    def test_existing_over_limit_description_still_loads_and_can_be_edited(self):
        group = self._group(
            description=" ".join(["legacy"] * (Group.DESCRIPTION_MAX_WORDS + 500)),
        )

        # Reading is untouched by the write-time rule.
        self.assertIn("description", GroupSerializer(group).data)

        # An unrelated partial update does not re-validate the stored value.
        serializer = GroupSerializer(
            group,
            data={"short_description": "Legacy group headline"},
            partial=True,
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)
        serializer.save()

        group.refresh_from_db()
        self.assertEqual(group.short_description, "Legacy group headline")
