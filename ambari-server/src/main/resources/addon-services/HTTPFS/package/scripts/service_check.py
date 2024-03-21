from resource_management import *
from resource_management.libraries.functions.curl_krb_request import curl_krb_request
import urllib2
import time
from urllib2 import HTTPError

class HttpFS_service_check(Script):
    def service_check(self, env):
        import params
        env.set_params(params)
        Logger.info("Checking HttpFS service")
        uri = format("http://{params.httpfs_server_host}:{params.httpfs_server_port}/webhdfs/v1/tmp/?op=LISTSTATUS&user.name={params.smoke_user}")
        if params.smoke_user_principal is not None and params.smoke_user_keytab is not None and params.security_enabled:
          response, errmsg, time_millis = curl_krb_request(params.tmp_dir, params.smoke_user_keytab,
                                                         params.smoke_user_principal, uri, "httpfs_service_check",
                                                         params.kinit_path_local, False, None, params.smoke_user)


        else:
          start_time = time.time()
          try:
            response = urllib2.urlopen(uri, timeout=5)
            response_code = response.getcode()
            errmsg = ''
            time_millis = time.time() - start_time
          except HTTPError, httpError:
            time_millis = time.time() - start_time
            errmsg = str(httpError)
            Logger.error("Cannot access HttpFS on: {0}. Error : {1}".format(uri, errmsg))
            #return 1

        if not errmsg:
            Logger.error("Cannot access HttpFS on: {0}. Error : {1}".format(uri, errmsg))
            return 1
        Logger.info("Checking HttpFS service ({0}ms) - DONE".format(time_millis))

if __name__ == "__main__":
    HttpFS_service_check().execute()
