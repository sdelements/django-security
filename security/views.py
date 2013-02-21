# Copyright (c) 2011, SD Elements. See LICENSE.txt for details.

from django.http import HttpResponseForbidden, HttpResponse
from django.utils import simplejson as json
from django.views.decorators.csrf import csrf_exempt

import logging
log = logging.getLogger(__name__)

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

@csrf_exempt
def csp_report(request, csp_save=False, csp_log=True):
    """
    Collect Content Security Policy reports from browsers. If csp_save is True
    save them in CspReport class. If csp_log is True log them through Django
    logger. By default only logging is enabled.
    """

    # http://www.w3.org/TR/CSP/#sample-violation-report
    if not request.method == 'POST':
        log.debug('Unexpect CSP report method {0}'.format(request.method))
        return HttpResponseForbidden()

    if (not request.META.has_key('CONTENT_TYPE')) or request.META['CONTENT_TYPE'] != 'application/json':
        log.debug('Missing CSP report Content-Type {0}'.format(request.META))
        return HttpResponseForbidden()

    try:
        csp_dict = json.loads(request.body)
    except:
        log.debug('Cannot JSON decode CSP report {0}'.format(request.body))
        return HttpResponseForbidden()

    if not csp_dict.has_key('csp-report'):
        log.debug('Invalid CSP report structure {0}'.format(csp_dict))
        return HttpResponseForbidden()

    report = csp_dict['csp-report']

    # log message about received CSP violation to Django log
    if csp_log:
        log.warn('Content Security Policy violation: {0}'.format(report))

    # save received CSP violation to database
    if csp_save:
        csp_report = CspReport(document_uri=report['document-uri'], referrer=report['referrer'],
            blocked_uri=report['blocker-uri'], violated_directive=report['violated-directive'],
            original_policy=report['original-policy'], sender_ip=request.META['REMOTE_ADDR'])

        csp_report.save()

    # return 204 No Content to the client
    # per http://www.w3.org/TR/CSP/#report-uri
    # "Note: The user agent ignores the fetched resource"
    resp = HttpResponse()
    resp.status_code = 204

    return resp

