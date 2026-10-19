"""IPDT-773 — tests for the signed signup proof (prototype)."""
import time

from django.test import TestCase, override_settings

from users.signup_proof import issue_signup_proof, verify_signup_proof


@override_settings(SIGNUP_PROOF_SECRET="unit-test-key", SIGNUP_PROOF_TTL_SECONDS=300)
class SignupProofTests(TestCase):
    def test_valid_proof_roundtrips(self):
        proof = issue_signup_proof("Member@Example.com", operation="signup", client_id="abc")
        r = verify_signup_proof(proof, email="member@example.com", operation="signup", client_id="abc")
        self.assertTrue(r.valid)
        self.assertEqual(r.payload["em"], "member@example.com")

    def test_tampered_payload_rejected(self):
        proof = issue_signup_proof("a@example.com", client_id="abc")
        head, payload_b64, sig = proof.split(".")
        # Flip a character in the payload; signature must no longer match.
        bad_payload = payload_b64[:-1] + ("A" if payload_b64[-1] != "A" else "B")
        r = verify_signup_proof(f"{head}.{bad_payload}.{sig}", email="a@example.com", client_id="abc")
        self.assertFalse(r.valid)
        self.assertEqual(r.reason, "bad_signature")

    def test_expired_proof_rejected(self):
        proof = issue_signup_proof("a@example.com", client_id="abc", ttl_seconds=1)
        r = verify_signup_proof(proof, email="a@example.com", client_id="abc", now=int(time.time()) + 10)
        self.assertFalse(r.valid)
        self.assertEqual(r.reason, "expired")

    def test_email_binding_enforced(self):
        proof = issue_signup_proof("a@example.com", client_id="abc")
        r = verify_signup_proof(proof, email="other@example.com", client_id="abc")
        self.assertFalse(r.valid)
        self.assertEqual(r.reason, "email_mismatch")

    def test_client_binding_enforced(self):
        proof = issue_signup_proof("a@example.com", client_id="abc")
        r = verify_signup_proof(proof, email="a@example.com", client_id="different")
        self.assertFalse(r.valid)
        self.assertEqual(r.reason, "client_mismatch")

    def test_operation_binding_enforced(self):
        proof = issue_signup_proof("a@example.com", operation="signup", client_id="abc")
        r = verify_signup_proof(proof, email="a@example.com", operation="password_reset", client_id="abc")
        self.assertFalse(r.valid)
        self.assertEqual(r.reason, "op_mismatch")

    def test_nonce_replay_prevention_hook(self):
        # Replay protection is PENDING a shared store; the hook contract is
        # verified here with an in-memory consumer: first use ok, replay rejected.
        proof = issue_signup_proof("a@example.com", client_id="abc")
        seen = set()

        def consume(jti, exp):
            if jti in seen:
                return False
            seen.add(jti)
            return True

        first = verify_signup_proof(proof, email="a@example.com", client_id="abc", consume_nonce=consume)
        replay = verify_signup_proof(proof, email="a@example.com", client_id="abc", consume_nonce=consume)
        self.assertTrue(first.valid)
        self.assertFalse(replay.valid)
        self.assertEqual(replay.reason, "replayed")

    def test_malformed_proof_rejected(self):
        self.assertFalse(verify_signup_proof("garbage", email="a@example.com").valid)
        self.assertFalse(verify_signup_proof("", email="a@example.com").valid)

    def test_future_issued_proof_rejected(self):
        proof = issue_signup_proof("a@example.com", client_id="abc")
        # Evaluate as if "now" is well before issuance (iat far in the future).
        r = verify_signup_proof(proof, email="a@example.com", client_id="abc", now=int(time.time()) - 600)
        self.assertFalse(r.valid)
        self.assertEqual(r.reason, "future_issued")


@override_settings(SIGNUP_PROOF_SECRET="")
class SignupProofNoSecretTests(TestCase):
    def test_issue_requires_dedicated_secret(self):
        from users.signup_proof import SignupProofConfigError
        with self.assertRaises(SignupProofConfigError):
            issue_signup_proof("a@example.com", client_id="abc")
