import threading
from django.contrib import messages
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import login, logout
from django.shortcuts import render, redirect
from .models import Scan
from django.contrib.auth.decorators import login_required
from datetime import datetime

from .scanner import run_full_scan


@login_required
def scan_list(request):
    scans = Scan.objects.all()
    filter_query = request.GET.get('filter', '')
    if filter_query:
        scans = scans.filter(target__icontains=filter_query)

    context = {'scans': scans}
    return render(request, 'scans/scan_list.html', context)

@login_required

def start_scan(request):
    if request.method == 'POST':
        target = request.POST.get('target')
        scan = Scan.objects.create(target=target, scan_type="Full Scan", status="Queued")

        def background_task():
            print(f"[Scanner] Starting background scan for: {target}")
            scan.status = "In Progress"
            scan.save()
            try:
                result = run_full_scan(target)
                print(f"[Scanner] Result from run_full_scan: {result}")

                scan.vuln_critical = result.get("critical", 0)
                scan.vuln_high = result.get("high", 0)
                scan.vuln_medium = result.get("medium", 0)
                scan.vuln_low = result.get("low", 0)
                scan.vuln_info = result.get("info", 0)
                scan.status = "Completed"
                print(f"[Scanner] Scan for {target} completed. Saving to DB.")
            except Exception as e:
                print(f"[Scanner ERROR] Exception during scan: {e}")
                scan.status = "Failed"
            scan.save()

        threading.Thread(target=background_task).start()
        print(f"[Scanner] Scan thread started for: {target}")
        return redirect('scan_list')

def register_view(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)  # автологин после регистрации
            return redirect('login')  # перенаправление на главную страницу
    else:
        form = UserCreationForm()
    return render(request, 'auth/register.html', {'form': form})

def logout_view(request):
    logout(request)
    return redirect('login')



