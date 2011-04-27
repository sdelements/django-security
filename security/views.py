# Copyright (c) 2011, SD Elements. See LICENSE.txt for details.

from django.http import HttpResponseForbidden


def require_ajax(view):
    """
    A view decorator which ensures that the request being proccessed
    by view is an AJAX request. We return a 403 error if the request
    is not an AJAX request.
    """
    def check_ajax(request, *args, **kwargs):
        if request.is_ajax():
            return view(request, *args, **kwargs)
        else:
            return HttpResponseForbidden()
    return check_ajax

