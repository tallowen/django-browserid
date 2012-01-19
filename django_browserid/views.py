from django.conf import settings
from django.contrib import auth
from django.http import HttpResponseRedirect
from django.views.generic.base import View

from django_browserid.forms import BrowserIDForm
from django_browserid.auth import get_audience


class Verify(View):
    """
    This view provides common functionality for handling the browserID callback

    Any view can be subclassed specifically the handle user view. The most
    common usage will look like this:

    from django_browserid.views import Verify
    ...
    class BrowserID_Verify(Verify):
        def handle_user(self, request, user):
            ...
            ...
            (custom user handling)
            return redirect

    In your urls.py put:

    from views import BrowserID_Verify

    urlpatterns = patterns('',
        ...
        url('^browserid/verify/', BrowserID_Verify.as_view(), name='browserid_verify')
        ...
    )
    """

    def post(self, request):
        """
        Handles the return post request from the browserID form and puts
        interesting variables into the class. If everything checks out, then
        we call handle_user to decide how to handle a valid user
        """

        self.redirect_to = getattr(settings, 'LOGIN_REDIRECT_URL', '/')
        self.redirect_to_failure = getattr(
                settings, 'LOGIN_REDIRECT_URL_FAILURE', '/')

        form = BrowserIDForm(data=request.POST)
        if form.is_valid():
            self.assertion = form.cleaned_data['assertion']
            self.user = auth.authenticate(assertion=self.assertion,
                                          audience=get_audience(self.request))
            if self.user and self.user.is_active:
                return self.handle_user(request, self.user)

        return HttpResponseRedirect(self.redirect_to_failure)

    def store_user_in_session(self):
        """
        Stores assertion and audience in a session so they can be authenticated
        after a redirect
        """
        self.request.session['assertion'] = self.assertion
        self.request.session['audience'] = get_audience(self.request)

    def handle_user(self, request, user):
        """
        This view takes an authenticated user and logs them in. This view
        should be subclassed to accomplish more complicated behavior
        """
        auth.login(request, user)
        return HttpResponseRedirect(self.redirect_to)


def get_authenticated_user(request):
    """
    Pulls an assertion and audience out of a session and returns an
    authenticated user.

    Use this method in a view you redirect to in handle_user.
    """
    assertion = request.session.get('assertion')
    audience = request.session.get('audience')
    if not (assertion and audience):
        return None

    return auth.authenticate(assertion=assertion, audience=audience)
