# Copyright (c) 2011, SD Elements. See LICENSE.txt for details.

from django.http import HttpResponseForbidden, HttpResponse
from django.utils import simplejson as json

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

def csp_report(request):
    """
    Accept Content Security Policy reports from browsers and store them in CspReport objects.
    """

    # http://www.w3.org/TR/CSP/#sample-violation-report
    if not request.method == 'POST':
        return HttpResponseForbidden()

    if not request.META.has_key('CONTENT_TYPE') or request.META['CONTENT_TYPE'] != 'application/json':
        return HttpResponseForbidden()

    try:
        csp_dict = json.loads(request.body)
    except:
        return HttpResponseForbidden()

    if not csp_dict.has_key('csp-report'):
        return HttpResponseForbidden()

    report = csp_dict['csp-report']

    csp_report = CspReport(document_uri=report['document-uri'], referrer=report['referrer'],
            blocked_uri=report['blocker-uri'], violated_directive=report['violated-directive'],
            original_policy=report['original-policy'], sender_ip=request.META['REMOTE_ADDR'])

    csp_report.save()

    resp = HttpResponse()
    resp.status = 204 # 204 No Contento

    return respo
    

