from django.test import TestCase

import json
from . import credgen

class TestSCRAMGeneration(TestCase):
    def test_credential_generation_sha256(self):
        password = "admin-secret"
        salt = b'2z6zo9xma93c5art4afp5tubr'
        want = b"salt=Mno2em85eG1hOTNjNWFydDRhZnA1dHVicg==,stored_key=S/mR1wYGMoSUC7Av4Kqbuiit96ZTeXGsfZuR7cUfbxM=,server_key=Ap6C1LoBF0qOOvYulwH5f3oog1VlsxF4fosugF+lTVQ=,iterations=4096"
        have = credgen.SCRAMCredentials(password, credgen.SCRAMAlgorithm.SHA256, salt=salt).serialize()
        self.assertEqual(have, want)

    def test_credential_generation_sha512(self):
        password = "admin-secret"
        salt = b'ejkufgc04s6u1n5fkqzhl2ypy'
        want = b"salt=ZWprdWZnYzA0czZ1MW41ZmtxemhsMnlweQ==,stored_key=SKtYXmLy0BEeLkj1aiunNFMw6ZlBA16DcJY5SpJ0WDJafANNp4QP+XDgZmkCwO7vhzxbK5FxgCa8lKfNRF0TBw==,server_key=JxzpmkDoCqp5lIpzAH+Djt2gxgG4dQw1Ox2Vkf/awx7PWk19JCimZGbKnPyOedd+aHCH0Xsv0gjXC6UM7LbElg==,iterations=4096"
        have = credgen.SCRAMCredentials(password, credgen.SCRAMAlgorithm.SHA512, salt=salt).serialize()
        self.assertEqual(have, want)
