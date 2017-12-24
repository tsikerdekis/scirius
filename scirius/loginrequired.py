from django.http import HttpResponseRedirect
from django.conf import settings
from re import compile
import logging
import pickle
import time

# Track activity of logged users
logger = logging.getLogger('authentication-log')
hdlr = logging.FileHandler('/var/log/scirius.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.INFO)

EXEMPT_URLS = [compile(settings.LOGIN_URL.lstrip('/'))]
if hasattr(settings, 'LOGIN_EXEMPT_URLS'):
    EXEMPT_URLS += [compile(expr) for expr in settings.LOGIN_EXEMPT_URLS]

class LoginRequiredMiddleware:
    """
    Middleware that requires a user to be authenticated to view any page other
    than LOGIN_URL. Exemptions to this requirement can optionally be specified
    in settings via a list of regular expressions in LOGIN_EXEMPT_URLS (which
    you can copy from your urls.py).


    Requires authentication middleware and template context processors to be
    loaded. You'll get an error if they aren't.
    """
    def process_request(self, request):
        assert hasattr(request, 'user'), "The Login Required middleware\
 requires authentication middleware to be installed. Edit your\
 MIDDLEWARE_CLASSES setting to insert\
 'django.contrib.auth.middlware.AuthenticationMiddleware'. If that doesn't\
 work, ensure your TEMPLATE_CONTEXT_PROCESSORS setting includes\
 'django.core.context_processors.auth'."
        if not request.user.is_authenticated():
            path = request.path_info.lstrip('/')
            if not any(m.match(path) for m in EXEMPT_URLS):
                return HttpResponseRedirect(settings.LOGIN_URL + path)
        else:
            self.log_user(request.user)

    def log_user(self, user):
        try:
            pkl_file = open('/var/lib/scirius/db/data.pkl', 'rb')
            users_logged = pickle.load(pkl_file)
            pkl_file.close()
        except:
            users_logged = dict()
        if users_logged.get(user, 0) == 0:
            logger.info(user)
            users_logged[user] = time.time()
        elif time.time() - users_logged.get(user, 0) > 60:
            logger.info(user)
            users_logged[user] = time.time()
        output = open('/var/lib/scirius/db/data.pkl', 'wb')
        pickle.dump(users_logged, output)
        output.close()

