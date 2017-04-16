import oauth

from django.contrib.auth.models import User

SECRET_SIZE = 32
VERIFIER_SIZE = 10


def generate_random(length=SECRET_SIZE):
    return User.objects.make_random_password(length=length)


class DataStore(oauth.OAuthDataStore):
    """Layer between Python OAuth and Django database."""
    def __init__(self, oauth_request):
        self.signature = oauth_request.parameters.get('oauth_signature', None)
        self.timestamp = oauth_request.parameters.get('oauth_timestamp', None)
        self.scope = oauth_request.parameters.get('scope', 'all')

    def lookup_consumer(self, key):
        pass

    def lookup_token(self, token_type, token):
        pass

    def lookup_nonce(self, oauth_consumer, oauth_token, nonce):
        pass

    def fetch_request_token(self, oauth_consumer, oauth_callback):
        pass

    def fetch_access_token(self, oauth_consumer, oauth_token, oauth_verifier):
        pass

    def authorize_request_token(self, oauth_token, user):
        if oauth_token.key == self.request_token.key:
            # authorize the request token in the store
            self.request_token.is_approved = True
            self.request_token.user = user
            self.request_token.verifier = generate_random(VERIFIER_SIZE)
            self.request_token.save()
            return self.request_token
        return None
