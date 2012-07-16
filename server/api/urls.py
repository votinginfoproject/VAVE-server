from django.conf.urls.defaults import patterns, url

urlpatterns = patterns('server.api.views',
    (r'^data/upload-request/(?P<filename>.+)?$', 'request_upload'),
)
