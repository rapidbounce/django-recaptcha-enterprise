import logging
import os
import socket
import sys
import warnings

from django import forms
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.exceptions import ValidationError
from django.utils.encoding import force_text
from django.utils.translation import ugettext_lazy as _

# from captcha import client
from captcha._compat import HTTPError, urlencode
from captcha.constants import TEST_PRIVATE_KEY, TEST_PUBLIC_KEY
from captcha.widgets import ReCaptchaV2Checkbox, ReCaptchaBase, ReCaptchaV3
from google.cloud import recaptchaenterprise_v1

logger = logging.getLogger(__name__)

RECAPTCHA_ACTION = "login"

if settings.RECAPTCHA_CREDENTIALS_JSON and settings.RECAPTCHA_PUBLIC_KEY:
    client = recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient.from_service_account_info(
        settings.RECAPTCHA_CREDENTIALS_JSON
    )
else:
    client = None


def create_assessment(token):
    """Create an assessment to analyze the risk of a UI action.
    Args:
    projectID: GCloud Project ID
    recaptchaSiteKey: Site key obtained by registering a domain/app to use recaptcha services.
    token: The token obtained from the client on passing the recaptchaSiteKey.
    recaptchaAction: Action name corresponding to the token.
    Return:
    bool: True if successful.
    """
    project_id = settings.PROJECT_ID
    recaptcha_site_key = settings.RECAPTCHA_PUBLIC_KEY
    recaptcha_action = RECAPTCHA_ACTION

    # Set the properties of the event to be tracked.
    event = recaptchaenterprise_v1.Event(expected_action=recaptcha_action)
    event.site_key = recaptcha_site_key
    event.token = token

    assessment = recaptchaenterprise_v1.Assessment()
    assessment.event = event

    project_name = f"projects/{project_id}"

    # Build the assessment request.
    request = recaptchaenterprise_v1.CreateAssessmentRequest()
    request.assessment = assessment
    request.parent = project_name

    response = client.create_assessment(request)
    print(response)
    # Check if the token is valid.
    if not response.token_properties.valid:
        logger.info(
            "The CreateAssessment call failed because the token was "
            + "invalid for for the following reasons: "
            + str(response.token_properties.invalid_reason)
        )
        return None
    return True

class ReCaptchaField(forms.CharField):
    widget = ReCaptchaV2Checkbox
    default_error_messages = {
        "captcha_invalid": _("Error verifying reCAPTCHA, please try again."),
        "captcha_error": _("Error verifying reCAPTCHA, please try again."),
    }

    def __init__(self, public_key=None, private_key=None, *args, **kwargs):
        """
        ReCaptchaField can accepts attributes which is a dictionary of
        attributes to be passed to the ReCaptcha widget class. The widget will
        loop over any options added and create the RecaptchaOptions
        JavaScript variables as specified in
        https://developers.google.com/recaptcha/docs/display#render_param
        """
        super(ReCaptchaField, self).__init__(*args, **kwargs)

        if not isinstance(self.widget, ReCaptchaBase):
            raise ImproperlyConfigured(
                "captcha.fields.ReCaptchaField.widget"
                " must be a subclass of captcha.widgets.ReCaptchaBase"
            )

        # reCAPTCHA fields are always required.
        self.required = True

        # Setup instance variables.
        self.private_key = private_key or getattr(
            settings, "RECAPTCHA_PRIVATE_KEY", TEST_PRIVATE_KEY
        )
        self.public_key = public_key or getattr(
            settings, "RECAPTCHA_PUBLIC_KEY", TEST_PUBLIC_KEY
        )

        # Update widget attrs with data-sitekey.
        self.widget.attrs["data-sitekey"] = self.public_key

    def get_remote_ip(self):
        f = sys._getframe()
        while f:
            request = f.f_locals.get("request")
            if request:
                remote_ip = request.META.get("REMOTE_ADDR", "")
                forwarded_ip = request.META.get("HTTP_X_FORWARDED_FOR", "")
                ip = remote_ip if not forwarded_ip else forwarded_ip
                return ip
            f = f.f_back

    def validate(self, value):
        super(ReCaptchaField, self).validate(value)

        try:
            check_captcha = create_assessment(value)
            print(check_captcha)
        except HTTPError:  # Catch timeouts, etc
            raise ValidationError(
                self.error_messages["captcha_error"], code="captcha_error"
            )

        if not check_captcha:
            logger.error(
                "ReCAPTCHA validation failed."
            )
            raise ValidationError(
                self.error_messages["captcha_invalid"], code="captcha_invalid"
            )

        required_score = self.widget.attrs.get("required_score")