from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from rest_framework.test import APIClient

from users.models import (
    Education,
    EducationDocument,
    Experience,
    MembershipDocument,
    ProfileCertification,
    ProfileCertificationDocument,
    ProfileMembership,
    ProfileTraining,
    TrainingDocument,
)


class ProfileRecordSoftDeleteTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="profile-owner",
            email="profile-owner@example.com",
            password="Password123!",
        )
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def test_education_soft_delete_preserves_document(self):
        education = Education.objects.create(
            user=self.user,
            school="Example University",
            degree="MBA",
        )
        document = EducationDocument.objects.create(
            education=education,
            file=SimpleUploadedFile("degree.pdf", b"degree-proof"),
        )

        response = self.client.delete(
            f"/api/auth/me/educations/{education.id}/",
            {"reason": "Removed from public profile"},
            format="json",
        )

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.data["deletion_type"], "soft")
        self.assertFalse(Education.objects.filter(id=education.id).exists())

        retained = Education.all_objects.get(id=education.id)
        self.assertTrue(retained.is_deleted)
        self.assertEqual(retained.deleted_by_id, self.user.id)
        self.assertEqual(retained.deletion_reason, "Removed from public profile")
        self.assertTrue(EducationDocument.objects.filter(id=document.id).exists())

    def test_all_supported_profile_records_are_retained(self):
        records = [
            (
                Experience.objects.create(
                    user=self.user,
                    community_name="Example Company",
                    position="Director",
                ),
                "experiences",
                Experience,
            ),
            (
                ProfileTraining.objects.create(
                    user=self.user,
                    program_title="Leadership Programme",
                    provider="Example Institute",
                ),
                "trainings",
                ProfileTraining,
            ),
            (
                ProfileCertification.objects.create(
                    user=self.user,
                    certification_name="Certified Professional",
                    issuing_organization="Example Board",
                ),
                "certifications",
                ProfileCertification,
            ),
            (
                ProfileMembership.objects.create(
                    user=self.user,
                    organization_name="Example Association",
                    role_type="Member",
                ),
                "memberships",
                ProfileMembership,
            ),
        ]

        for record, route, model in records:
            response = self.client.delete(
                f"/api/auth/me/{route}/{record.id}/",
                {},
                format="json",
            )
            self.assertEqual(response.status_code, 200, response.content)
            self.assertFalse(model.objects.filter(id=record.id).exists())
            self.assertTrue(model.all_objects.get(id=record.id).is_deleted)

    def test_training_certification_and_membership_documents_remain(self):
        training = ProfileTraining.objects.create(
            user=self.user,
            program_title="Course",
            provider="Provider",
        )
        training_doc = TrainingDocument.objects.create(
            training=training,
            file=SimpleUploadedFile("training.pdf", b"training-proof"),
        )
        certification = ProfileCertification.objects.create(
            user=self.user,
            certification_name="Certificate",
            issuing_organization="Issuer",
        )
        certification_doc = ProfileCertificationDocument.objects.create(
            certification=certification,
            file=SimpleUploadedFile("certificate.pdf", b"certificate-proof"),
        )
        membership = ProfileMembership.objects.create(
            user=self.user,
            organization_name="Association",
        )
        membership_doc = MembershipDocument.objects.create(
            membership=membership,
            file=SimpleUploadedFile("membership.pdf", b"membership-proof"),
        )

        for route, record in [
            ("trainings", training),
            ("certifications", certification),
            ("memberships", membership),
        ]:
            response = self.client.delete(
                f"/api/auth/me/{route}/{record.id}/",
                {},
                format="json",
            )
            self.assertEqual(response.status_code, 200, response.content)

        self.assertTrue(TrainingDocument.objects.filter(id=training_doc.id).exists())
        self.assertTrue(ProfileCertificationDocument.objects.filter(id=certification_doc.id).exists())
        self.assertTrue(MembershipDocument.objects.filter(id=membership_doc.id).exists())
