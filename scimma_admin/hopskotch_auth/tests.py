from django.test import TestCase
from django.contrib.auth import get_user_model
import json
from .models import SCRAMCredentials, SCRAMAlgorithm, new_credentials, delete_credentials

from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned

class TestSCRAMGeneration(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create(username="admin", email="admin@email.com")

    def test_credential_generation_sha256(self):
        password = "admin-secret"
        salt = b'2z6zo9xma93c5art4afp5tubr'
        want = b"salt=Mno2em85eG1hOTNjNWFydDRhZnA1dHVicg==,stored_key=S/mR1wYGMoSUC7Av4Kqbuiit96ZTeXGsfZuR7cUfbxM=,server_key=Ap6C1LoBF0qOOvYulwH5f3oog1VlsxF4fosugF+lTVQ=,iterations=4096"
        have = SCRAMCredentials.generate(
            owner=self.user,
            username="",
            password=password,
            alg=SCRAMAlgorithm.SHA256,
            salt=salt,
        )
        self.assertEqual(have.string_encoding, want)

    def test_credential_generation_sha512(self):
        password = "admin-secret"
        salt = b'ejkufgc04s6u1n5fkqzhl2ypy'
        want = b"salt=ZWprdWZnYzA0czZ1MW41ZmtxemhsMnlweQ==,stored_key=SKtYXmLy0BEeLkj1aiunNFMw6ZlBA16DcJY5SpJ0WDJafANNp4QP+XDgZmkCwO7vhzxbK5FxgCa8lKfNRF0TBw==,server_key=JxzpmkDoCqp5lIpzAH+Djt2gxgG4dQw1Ox2Vkf/awx7PWk19JCimZGbKnPyOedd+aHCH0Xsv0gjXC6UM7LbElg==,iterations=4096"
        have = SCRAMCredentials.generate(
            owner=self.user,
            username="",
            password=password,
            alg=SCRAMAlgorithm.SHA512,
            salt=salt,
        )
        self.assertEqual(have.string_encoding, want)

class TestCredentialDeletion(TestCase):
    def setUp(self):
        self.user1 = get_user_model().objects.create(username="user1", email="user1@email.com")
        self.user2 = get_user_model().objects.create(username="user2", email="user2@email.com")
        self.user3 = get_user_model().objects.create(username="user3", email="user3@email.com")

        self.user1_creds1 = new_credentials(self.user1)
        self.user1_creds2 = new_credentials(self.user1)
        self.user2_creds1 = new_credentials(self.user2)

    def test_delete_credentials(self):
        delete_credentials(self.user1, self.user1_creds1.username)
        remaining_creds = self.user1.scramcredentials_set.all()
        self.assertEqual(len(remaining_creds), 1, "only 1 set of credentials should remain for user 1")
        self.assertEqual(remaining_creds[0].username, self.user1_creds2.username)

        delete_credentials(self.user1, self.user1_creds2.username)
        remaining_creds = self.user1.scramcredentials_set.all()
        self.assertEqual(len(remaining_creds), 0, "no credentials should remain for user 1")

        delete_credentials(self.user2, self.user2_creds1.username)
        remaining_creds = self.user2.scramcredentials_set.all()
        self.assertEqual(len(remaining_creds), 0, "no credentials should remain for user 2")


    def test_cant_delete_other_users_creds(self):
        with self.assertRaises(ObjectDoesNotExist):
            delete_credentials(self.user1, self.user2_creds1.username)
        with self.assertRaises(ObjectDoesNotExist):
            delete_credentials(self.user2, self.user1_creds1.username)
        with self.assertRaises(ObjectDoesNotExist):
            delete_credentials(self.user2, self.user1_creds2.username)
        with self.assertRaises(ObjectDoesNotExist):
            delete_credentials(self.user3, self.user1_creds1.username)

    def test_cant_delete_unknown_creds(self):
        with self.assertRaises(ObjectDoesNotExist):
            delete_credentials(self.user1, "missing")
        with self.assertRaises(ObjectDoesNotExist):
            delete_credentials(self.user2, "missing")
        with self.assertRaises(ObjectDoesNotExist):
            delete_credentials(self.user3, "missing")
