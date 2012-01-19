from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.contrib import auth
from django.http import HttpResponseRedirect
from django.shortcuts import redirect
from django.views.generic.edit import BaseFormView

from django_browserid.forms import BrowserIDForm
from django_browserid.auth import get_audience


class Verify(BaseFormView):
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
    form_class = BrowserIDForm
    failure_url = getattr(settings, 'LOGIN_REDIRECT_URL_FAILURE', '/')
    success_url = getattr(settings, 'LOGIN_REDIRECT_URL', '/')

    def handle_user(self, request, user):
        """
        This view takes an authenticated user and logs them in. This view
        should be subclassed to accomplish more complicated behavior
        """
        auth.login(request, user)
        return HttpResponseRedirect(self.get_success_url())

    def form_valid(self, form):
        """
        Handles the return post request from the browserID form and puts
        interesting variables into the class. If everything checks out, then
        we call handle_user to decide how to handle a valid user
        """
        self.assertion = form.cleaned_data['assertion']
        self.audience = get_audience(self.request)
        self.user = auth.authenticate(
                assertion=self.assertion,
                audience=self.audience)

        if self.user and self.user.is_active:
            return self.handle_user(self.request, self.user)

        return HttpResponseRedirect(self.get_failure_url())

    def store_user_in_session(self):
        """
        Stores assertion and audience in a session so they can be authenticated
        after a redirect
        """
        self.request.session['assertion'] = self.assertion
        self.request.session['audience'] = self.audience

    def get_failure_url(self):
        if self.failure_url:
            url = self.failure_url
        else:
            raise ImproperlyConfigured(
                "No URL to redirect to. Provide a failure_url.")
        return url

    def get(self, *args, **kwargs):
        return redirect('/')

    def form_invalid(self, *args, **kwargs):
        return redirect(self.get_failure_url())


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
