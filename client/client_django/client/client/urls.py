from django.conf.urls import url, include
from django.contrib import admin
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.conf.urls.static import static
from django.conf import settings

from . import views
from accounts import views as accounts_views

urlpatterns = [
    url(r'^admin/', admin.site.urls),

    url(r'^accounts/', include('accounts.urls')),

    url(r'^$', accounts_views.login_view, name="home"),
]

urlpatterns += staticfiles_urlpatterns()
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
