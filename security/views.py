# Copyright (c) 2011, SD Elements. See LICENSE.txt for details.

import json

from django.http import HttpResponseForbidden, HttpResponse
from django.views.decorators.csrf import csrf_exempt

import logging
log = logging.getLogger(__name__)

ACCEPTABLE_CONTENT_TYPES = ['application/json', 'application/csp-report']


def require_ajax(view):
    """
    A view decorator which ensures that the request being processed
    by view is an AJAX request. We return a 403 error if the request
    is not an AJAX request.
    """
    def check_ajax(request, *args, **kwargs):
        if request.is_ajax():
            return view(request, *args, **kwargs)
        else:
            return HttpResponseForbidden()

    return check_ajax


@csrf_exempt
def csp_report(request, csp_save=False, csp_log=True):
    """
    .. _csp_report:

    Collect Content Security Policy reports from browsers. This view has
    two optional keyword arguments:

        ``csp_save``    if True, reports will be saved as ``CspReport`` objects
                        in database; this table is registered with Django
                        Admin, so they can be later viewed in admin console.

        ``csp_log``     if True, reports will be logged through Django logging
                        facility under ``security`` class

    By default only logging is enabled. To collect reports, this view needs to
    be added to project's urls.py. Examples:

    Default mode, only logger enable, no database logging:

        ``url(r'^csp-report/$', security.views.csp_report),``

    Logger and database enabled:

        ``url(r'^csp-report/$', security.views.csp_report,
        kwargs={'csp_save':True,'csp_log':True}),``
    """

    # http://www.w3.org/TR/CSP/#sample-violation-report
    if not request.method == 'POST':
        log.debug('Unexpect CSP report method %s', request.method)
        return HttpResponseForbidden()

    content_type = request.META.get('CONTENT_TYPE', None)
    if content_type not in ACCEPTABLE_CONTENT_TYPES:
        log.debug('Missing CSP report Content-Type %s', request.META)
        return HttpResponseForbidden()

    try:
        csp_dict = json.loads(request.body)
    except ValueError:
        log.debug('Cannot JSON decode CSP report %s', request.body)
        return HttpResponseForbidden()

    if 'csp-report' not in csp_dict:
        log.debug('Invalid CSP report structure %s', csp_dict)
        return HttpResponseForbidden()

    report = csp_dict['csp-report']
    reporting_ip = request.META['REMOTE_ADDR']
    reporting_ua = request.META['HTTP_USER_AGENT']

    # log message about received CSP violation to Django log
    if csp_log:
        log.warn(
            'Content Security Policy violation: '
            '%s, reporting IP %s, user agent %s',
            report, reporting_ip, reporting_ua
        )

    # save received CSP violation to database
    if csp_save:
        from security.models import CspReport
        csp_report = CspReport(
            document_uri=report.get('document-uri'),
            referrer=report.get('referrer'),
            blocked_uri=report.get('blocked-uri'),
            violated_directive=report.get('violated-directive'),
            original_policy=report.get('original-policy'),
            sender_ip=reporting_ip,
            user_agent=reporting_ua,
        )

        csp_report.save()

    # return 204 No Content to the client
    # per http://www.w3.org/TR/CSP/#report-uri
    # "Note: The user agent ignores the fetched resource"
    resp = HttpResponse()
    resp.status_code = 204

    return resp
