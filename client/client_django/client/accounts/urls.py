from django.conf.urls import url
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.conf.urls.static import static
from django.conf import settings
from django.urls import path
from . import views

app_name = 'accounts'

urlpatterns = [
    url(r'^signup/$', views.signup_view, name="signup"),
    url(r'^login/$', views.login_view, name="login"),
    url(r'^logout/$', views.logout_view, name="logout"),
    url(r'^main/$', views.login_user, name="main"),
    url(r'^send_view/$', views.send_view, name="send_view"),
    url(r'^send/$', views.send, name="send"),
    url(r'^download/$', views.download, name="download"),
    url(r'^main_view$', views.main_view, name="main_view"),
    url(r'^uploaded_file_view(?P<userId>\d+)/', views.uploaded_file_view, name="uploaded_file_view"),
    url(r'^downloaded_file_view(?P<userId>\d+)/', views.downloaded_file_view, name="downloaded_file_view"),
    url(r'^receipt_view(?P<userId>\d+)/', views.receipt_view, name="receipt_view"),
    url(r'^all_file_view(?P<userId>\d+)/', views.all_file_view, name="all_file_view"),
    url(r'^request_download(?P<fileId>\d+)/(?P<userId>\d+)/', views.request_download, name="request_download"),
    url(r'^request_abort(?P<fileId>\d+)/(?P<userId>\d+)/', views.request_abort, name="request_abort"),
    url(r'^abort/$', views.abort, name="abort"),
    # path('downloadfile/', views.file_response, name="downloadfile"),
    # url(r'^downloadfile(?P<file_name>.*)/$', views.downloadfile, name="downloadfile"),
    url(r'^downloadfile(?P<fileId>\d+)/', views.downloadfile, name="downloadfile"),
]

urlpatterns += staticfiles_urlpatterns()
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
