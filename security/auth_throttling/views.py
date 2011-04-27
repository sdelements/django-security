# Copyright (c) 2011, SD Elements. See ../LICENSE.txt for details.

import logging

from django.contrib.auth.models import User
from django.http import Http404, HttpResponseRedirect
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_http_methods

from security.auth_throttling import reset_counters

logger = logging.getLogger(__name__)


@never_cache
@require_http_methods(["POST"])
def reset_username_throttle(request, user_id=None, redirect_url="/"):
    if not request.user.is_superuser:
        raise Http404
    try:
        username = User.objects.get(id=user_id).username 
    except:
        logger.error("Couldn't find username for user id %s." % user_id)
        raise Http404()
    reset_counters(username=username)
    logger.info("Authentication throttling reset for user id %s." % user_id)
    # TODO: Sanitize redirect_url, even though it's coming from an admin?
    return HttpResponseRedirect(redirect_url)

