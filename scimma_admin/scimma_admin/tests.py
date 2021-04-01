from django.test import TestCase, Client
from django.contrib.auth import get_user_model

class TestBaseRoutes(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create(username="user", email="user@email.com")
        self.client = Client()

    def test_health_check(self):
        response = self.client.get("/health_check/")
        self.assertEqual(response.status_code, 200)

    def test_base_url_goes_to_hopauth_index(self):
        # When you go to the root path:

        # 1. A logged-in user should get a 200, and be presented with the
        # hopskotch auth index.
        self.client.force_login(self.user)
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "hopskotch_auth/index.html")

        # 2. A logged-out user should get redirected, and asked to log in.
        anonymous_client = Client()
        response = anonymous_client.get("/")
        self.assertRedirects(response, "/hopauth/login?next=/")
