import json
from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from django.db.models import Count, Q
from datetime import timedelta

from .models import Email, ScanLog
from .ml_engine import classify_email


def dashboard(request):
    total = Email.objects.count()
    phishing = Email.objects.filter(status='phishing').count()
    suspicious = Email.objects.filter(status='suspicious').count()
    safe = Email.objects.filter(status='safe').count()

    recent_threats = Email.objects.filter(
        status__in=['phishing', 'suspicious']
    ).order_by('-received_at')[:6]

    recent_alerts = ScanLog.objects.filter(
        level__in=['warning', 'danger']
    ).order_by('-timestamp')[:5]

    # Trend data: last 7 days
    today = timezone.now().date()
    trend = []
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        p = Email.objects.filter(
            received_at__date=day, status='phishing'
        ).count()
        s = Email.objects.filter(
            received_at__date=day, status='suspicious'
        ).count()
        trend.append({'day': day.strftime('%a'), 'phishing': p, 'suspicious': s})

    context = {
        'total': total,
        'phishing': phishing,
        'suspicious': suspicious,
        'safe': safe,
        'recent_threats': recent_threats,
        'recent_alerts': recent_alerts,
        'trend_json': json.dumps(trend),
    }
    return render(request, 'detector/dashboard.html', context)


def inbox(request):
    status_filter = request.GET.get('status', 'all')
    search = request.GET.get('q', '')

    emails = Email.objects.all()
    if status_filter != 'all':
        emails = emails.filter(status=status_filter)
    if search:
        emails = emails.filter(
            Q(sender__icontains=search) | Q(subject__icontains=search)
        )

    context = {
        'emails': emails,
        'status_filter': status_filter,
        'search': search,
        'total_count': emails.count(),
    }
    return render(request, 'detector/inbox.html', context)


def email_detail(request, pk):
    email = get_object_or_404(Email, pk=pk)
    if not email.is_read:
        email.is_read = True
        email.save()
    return render(request, 'detector/email_detail.html', {'email': email})


def analytics(request):
    total = Email.objects.count()
    phishing = Email.objects.filter(status='phishing').count()
    suspicious = Email.objects.filter(status='suspicious').count()
    safe = Email.objects.filter(status='safe').count()

    top_senders = Email.objects.filter(
        status='phishing'
    ).values('sender_domain').annotate(
        count=Count('id')
    ).order_by('-count')[:8]

    today = timezone.now().date()
    monthly = []
    for i in range(29, -1, -1):
        day = today - timedelta(days=i)
        p = Email.objects.filter(received_at__date=day, status='phishing').count()
        monthly.append({'day': day.strftime('%b %d'), 'count': p})

    context = {
        'total': total,
        'phishing': phishing,
        'suspicious': suspicious,
        'safe': safe,
        'detection_rate': round(phishing / total * 100, 1) if total else 0,
        'top_senders': top_senders,
        'monthly_json': json.dumps(monthly),
    }
    return render(request, 'detector/analytics.html', context)


def settings_view(request):
    return render(request, 'detector/settings.html')


def scan_email(request):
    if request.method == 'POST':
        sender = request.POST.get('sender', '').strip()
        subject = request.POST.get('subject', '').strip()
        body = request.POST.get('body', '').strip()
        attachment = request.POST.get('attachment_name', '').strip()

        if not sender or not subject or not body:
            return render(request, 'detector/scan.html',
                          {'error': 'Sender, subject and body are required.'})

        result = classify_email(sender, subject, body, attachment=attachment)

        email = Email.objects.create(
            sender=sender,
            sender_domain=result['sender_domain'],
            subject=subject,
            body=body,
            status=result['status'],
            risk_score=result['risk_score'],
            text_score=result['text_score'],
            url_score=result['url_score'],
            metadata_score=result['metadata_score'],
            attachment_score=result['attachment_score'],
            extracted_urls=result['extracted_urls'],
            has_attachment=bool(attachment),
            attachment_name=attachment,
            why_flagged=result['why_flagged'],
        )

        ScanLog.objects.create(
            email=email,
            level='danger' if result['status'] == 'phishing'
            else 'warning' if result['status'] == 'suspicious' else 'info',
            message=f"Email scanned: {result['status'].upper()} "
                    f"(score {round(result['risk_score']*100)}%) — {subject[:60]}"
        )

        return redirect('email_detail', pk=email.pk)

    return render(request, 'detector/scan.html')


# ── API endpoints ─────────────────────────────────────────────────────────────

def api_stats(request):
    total = Email.objects.count()
    return JsonResponse({
        'total': total,
        'phishing': Email.objects.filter(status='phishing').count(),
        'suspicious': Email.objects.filter(status='suspicious').count(),
        'safe': Email.objects.filter(status='safe').count(),
    })


@csrf_exempt
@require_http_methods(['POST'])
def api_scan(request):
    try:
        data = json.loads(request.body)
        result = classify_email(
            sender=data.get('sender', ''),
            subject=data.get('subject', ''),
            body=data.get('body', ''),
            attachment=data.get('attachment', ''),
        )
        return JsonResponse(result)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)


def api_recent_alerts(request):
    alerts = ScanLog.objects.filter(
        level__in=['warning', 'danger']
    ).order_by('-timestamp')[:10]
    return JsonResponse({
        'alerts': [
            {
                'message': a.message,
                'level': a.level,
                'time': a.timestamp.strftime('%H:%M'),
            }
            for a in alerts
        ]
    })
