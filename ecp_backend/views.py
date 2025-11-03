from django.conf import settings
from django.shortcuts import redirect

def index(request):
    # Logged in? send to your app home (dashboard)
    if request.user.is_authenticated:
        return redirect(settings.AUTH_HOME_URL)
    # Not logged in? send to your SPA landing (no frontend changes needed)
    return redirect(settings.FRONTEND_URL)