from __future__ import division
from __future__ import absolute_import
import requests
from requests.exceptions import HTTPError
from io import open
try:
    from urllib.parse import urlencode, quote
except:
    from urllib import urlencode, quote
import json
import math
from random import uniform
import time
from collections import OrderedDict
from sseclient import SSEClient
import threading
import socket
from oauth2client.service_account import ServiceAccountCredentials
from gcloud import storage


def initialize_app(config):
    return Firebase(config)


class Firebase(object):
    u""" Firebase Interface """
    def __init__(self, config):
        self.api_key = config[u"apiKey"]
        self.auth_domain = config[u"authDomain"]
        self.database_url = config[u"databaseURL"]
        self.storage_bucket = config[u"storageBucket"]
        self.credentials = None
        self.access_token = None
        if config.get(u"serviceAccount"):
            self.service_account = config[u"serviceAccount"]
            scopes = [
                u'https://www.googleapis.com/auth/firebase.database',
                u'https://www.googleapis.com/auth/userinfo.email',
                u"https://www.googleapis.com/auth/cloud-platform"
            ]
            self.credentials = ServiceAccountCredentials.from_json_keyfile_name(
                config[u"serviceAccount"], scopes)
            self.access_token = self.credentials.get_access_token()
        self.requests = requests.Session()
        adapter = requests.adapters.HTTPAdapter(max_retries=3)
        for scheme in (u'http://', u'https://'):
            self.requests.mount(scheme, adapter)

    def auth(self):
        return Auth(self.api_key, self.requests)

    def database(self):
        return Database(
            self.access_token, self.api_key, self.database_url, self.requests)

    def storage(self):
        return Storage(self.credentials, self.storage_bucket, self.requests)


class Auth(object):
    u""" Authentication Service """
    def __init__(self, api_key, requests):
        self.api_key = api_key
        self.current_user = None
        self.requests = requests

    def sign_in_with_email_and_password(self, email, password):
        request_ref = u"https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword?key={0}".format(self.api_key)
        headers = {u"content-type": u"application/json; charset=UTF-8"}
        data = json.dumps(
            {u"email": email,
             u"password": password,
             u"returnSecureToken": True})
        request_object = requests.post(request_ref, headers=headers, data=data)
        raise_detailed_error(request_object)
        self.current_user = request_object.json()
        return request_object.json()

    def get_account_info(self, id_token):
        request_ref = u"https://www.googleapis.com/identitytoolkit/v3/relyingparty/getAccountInfo?key={0}".format(self.api_key)
        headers = {u"content-type": u"application/json; charset=UTF-8"}
        data = json.dumps({u"idToken": id_token})
        request_object = requests.post(request_ref, headers=headers, data=data)
        raise_detailed_error(request_object)
        return request_object.json()

    def send_email_verification(self, id_token):
        request_ref = u"https://www.googleapis.com/identitytoolkit/v3/relyingparty/getOobConfirmationCode?key={0}".format(self.api_key)
        headers = {u"content-type": u"application/json; charset=UTF-8"}
        data = json.dumps({u"requestType": u"VERIFY_EMAIL", u"idToken": id_token})
        request_object = requests.post(request_ref, headers=headers, data=data)
        raise_detailed_error(request_object)
        return request_object.json()

    def send_password_reset_email(self, email):
        request_ref = u"https://www.googleapis.com/identitytoolkit/v3/relyingparty/getOobConfirmationCode?key={0}".format(self.api_key)
        headers = {u"content-type": u"application/json; charset=UTF-8"}
        data = json.dumps({u"requestType": u"PASSWORD_RESET", u"email": email})
        request_object = requests.post(request_ref, headers=headers, data=data)
        raise_detailed_error(request_object)
        return request_object.json()

    def verify_password_reset_code(self, reset_code, new_password):
        request_ref = u"https://www.googleapis.com/identitytoolkit/v3/relyingparty/resetPassword?key={0}".format(self.api_key)
        headers = {u"content-type": u"application/json; charset=UTF-8"}
        data = json.dumps(
            {u"oobCode": reset_code, u"newPassword": new_password})
        request_object = requests.post(request_ref, headers=headers, data=data)
        raise_detailed_error(request_object)
        return request_object.json()

    def create_user_with_email_and_password(self, email, password):
        request_ref = u"https://www.googleapis.com/identitytoolkit/v3/relyingparty/signupNewUser?key={0}".format(self.api_key)
        headers = {
            u"content-type": u"application/json; charset=UTF-8"}
        data = json.dumps({
            u"email": email, u"password": password, u"returnSecureToken": True})
        request_object = requests.post(request_ref, headers=headers, data=data)
        raise_detailed_error(request_object)
        return request_object.json()


class Database(object):
    u""" Database Service """
    def __init__(self, access_token, api_key, database_url, requests):

        if not database_url.endswith(u'/'):
            url = u''.join([database_url, u'/'])
        else:
            url = database_url

        self.access_token = access_token
        self.api_key = api_key
        self.database_url = url
        self.requests = requests

        self.path = u""
        self.build_query = {}
        self.last_push_time = 0
        self.last_rand_chars = []

    def order_by_child(self, order):
        self.build_query[u"orderBy"] = order
        return self

    def start_at(self, start):
        self.build_query[u"startAt"] = start
        return self

    def end_at(self, end):
        self.build_query[u"endAt"] = end
        return self

    def equal_to(self, equal):
        self.build_query[u"equalTo"] = equal
        return self

    def limit_to_first(self, limit_first):
        self.build_query[u"limitToFirst"] = limit_first
        return self

    def limit_to_last(self, limit_last):
        self.build_query[u"limitToLast"] = limit_last
        return self

    def shallow(self):
        self.build_query[u"shallow"] = True
        return self

    def child(self, *args):
        new_path = u"/".join(args)
        if self.path:
            self.path += u"/{}".format(new_path)
        else:
            if new_path.startswith(u"/"):
                new_path = new_path[1:]
            self.path = new_path
        return self

    def build_request_url(self, token):
        parameters = {}
        if token:
            parameters[u'auth'] = token
        for param in list(self.build_query):
            if type(self.build_query[param]) is unicode:
                parameters[param] = quote(u'"' + self.build_query[param] + u'"')
            else:
                parameters[param] = self.build_query[param]
        # reset path and build_query for next query
        request_ref = u'{0}{1}.json?{2}'.format(
            self.database_url, self.path, urlencode(parameters))
        self.path = u""
        self.build_query = {}
        return request_ref

    def build_headers(self, token):
        headers = {u"content-type": u"application/json; charset=UTF-8"}
        if not token and self.access_token:
            headers[u'Authorization'] = u'Bearer ' + self.access_token.access_token
        return headers

    def get(self, token=None):
        build_query = self.build_query
        query_key = self.path.split(u"/")[-1]
        request_ref = self.build_request_url(token)
        # headers
        headers = self.build_headers(token)
        # do request
        request_object = self.requests.get(request_ref, headers=headers)
        raise_detailed_error(request_object)
        request_dict = request_object.json()

        # if primitive or simple query return
        if not isinstance(request_dict, dict):
            return PyreResponse(request_dict, query_key)
        if not build_query:
            return PyreResponse(
                convert_to_pyre(request_dict.items()), query_key)
        # return keys if shallow
        if build_query.get(u"shallow"):
            return PyreResponse(request_dict.keys(), query_key)
        # otherwise sort
        sorted_response = None
        if build_query.get(u"orderBy"):
            if build_query[u"orderBy"] == u"$key":
                sorted_response = sorted(
                    request_dict.items(), key=lambda item: item[0])
            else:
                sorted_response = sorted(
                    request_dict.items(),
                    key=lambda item: item[1][build_query[u"orderBy"]])
        return PyreResponse(
            convert_to_pyre(sorted_response), query_key)

    def push(self, data, token=None):
        request_ref = self.check_token(self.database_url, self.path, token)
        self.path = u""
        headers = self.build_headers(token)
        request_object = self.requests.post(request_ref,
                                            headers=headers,
                                            data=json.dumps(data))
        raise_detailed_error(request_object)
        return request_object.json()

    def set(self, data, token=None):
        request_ref = self.check_token(self.database_url, self.path, token)
        self.path = u""
        headers = self.build_headers(token)
        request_object = self.requests.put(request_ref,
                                           headers=headers,
                                           data=json.dumps(data))
        raise_detailed_error(request_object)
        return request_object.json()

    def update(self, data, token=None):
        request_ref = self.check_token(self.database_url, self.path, token)
        self.path = u""
        headers = self.build_headers(token)
        request_object = self.requests.patch(request_ref,
                                             headers=headers,
                                             data=json.dumps(data))
        raise_detailed_error(request_object)
        return request_object.json()

    def remove(self, token=None):
        request_ref = self.check_token(self.database_url, self.path, token)
        self.path = u""
        headers = self.build_headers(token)
        request_object = self.requests.delete(request_ref, headers=headers)
        raise_detailed_error(request_object)
        return request_object.json()

    def stream(self, stream_handler, token=None):
        request_ref = self.build_request_url(token)
        return Stream(request_ref, stream_handler)

    def check_token(self, database_url, path, token):
        if token:
            return u'{0}{1}.json?auth={2}'.format(database_url, path, token)
        else:
            return u'{0}{1}.json'.format(database_url, path)

    def generate_key(self):
        push_chars = u'-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz'
        now = int(time.time() * 1000)
        duplicate_time = now == self.last_push_time
        self.last_push_time = now
        time_stamp_chars = [0] * 8
        for i in reversed(xrange(0, 8)):
            time_stamp_chars[i] = push_chars[now % 64]
            now = math.floor(now / 64)
        new_id = u"".join(time_stamp_chars)
        if not duplicate_time:
            for i in xrange(0, 12):
                self.last_rand_chars.append(math.floor(uniform(0, 1) * 64))
        else:
            for i in xrange(0, 11):
                if self.last_rand_chars[i] == 63:
                    self.last_rand_chars[i] = 0
                self.last_rand_chars[i] += 1
        for i in xrange(0, 12):
            new_id += push_chars[self.last_rand_chars[i]]
        return new_id

    def sort(self, origin, by_key):
        # unpack pyre objects
        pyres = origin.each()
        new_list = []
        for pyre in pyres:
            new_list.append(pyre.item)
        # sort
        data = sorted(dict(new_list).items(), key=lambda item: item[1][by_key])
        return PyreResponse(convert_to_pyre(data), origin.key())


class Storage(object):
    u""" Storage Service """
    def __init__(self, credentials, storage_bucket, requests):
        self.storage_bucket = u"https://firebasestorage.googleapis.com/v0/b/" + storage_bucket
        self.credentials = credentials
        self.requests = requests
        self.path = u""
        if credentials:
            client = storage.Client(credentials=credentials,
                                    project=storage_bucket)
            self.bucket = client.get_bucket(storage_bucket)

    def child(self, *args):
        new_path = u"/".join(args)
        if self.path:
            self.path += u"/{}".format(new_path)
        else:
            if new_path.startswith(u"/"):
                new_path = new_path[1:]
            self.path = new_path
        return self

    def put(self, file, token=None):
        # reset path
        path = self.path
        self.path = None
        if token:
            if isinstance(file, unicode):
                file_object = open(file, u'rb')
            else:
                file_object = file
            request_ref = self.storage_bucket + u"/o?name={0}".format(path)
            headers = {u"Authorization": u"Firebase "+token}
            request_object = self.requests.put(
                request_ref, headers=headers, data=file_object)
            raise_detailed_error(request_object)
            return request_object.json()
        elif self.credentials:
            blob = self.bucket.blob(path)
            if isinstance(file, unicode):
                return blob.upload_from_filename(filename=file)
            else:
                return blob.upload_from_file(file_obj=file)

    def delete(self, name):
        self.bucket.delete_blob(name)

    def get(self):
        # remove leading backlash
        path = self.path
        self.path = None
        if path.startswith(u'/'):
            path = path[1:]
        return self.bucket.get_blob(path)

    def list_files(self):
        return self.bucket.list_blobs()


def raise_detailed_error(request_object):
    try:
        request_object.raise_for_status()
    except HTTPError, e:
        # raise detailed error message
        raise HTTPError(e, request_object.text)


def convert_to_pyre(items):
    pyre_list = []
    for item in items:
        pyre_list.append(Pyre(item))
    return pyre_list


class PyreResponse(object):
    def __init__(self, pyres, query_key):
        self.pyres = pyres
        self.query_key = query_key

    def val(self):
        if isinstance(self.pyres, list):
            # unpack pyres into OrderedDict
            pyre_list = []
            for pyre in self.pyres:
                pyre_list.append((pyre.key(), pyre.val()))
            return OrderedDict(pyre_list)
        else:
            # return primitive or simple query results
            return self.pyres

    def key(self):
        return self.query_key

    def each(self):
        if isinstance(self.pyres, list):
            return self.pyres


class Pyre(object):
    def __init__(self, item):
        self.item = item

    def val(self):
        return self.item[1]

    def key(self):
        return self.item[0]


class ClosableSSEClient(SSEClient):
    def __init__(self, *args, **kwargs):
        self.should_connect = True
        super(ClosableSSEClient, self).__init__(*args, **kwargs)

    def _connect(self):
        if self.should_connect:
            super(ClosableSSEClient, self)._connect()
        else:
            raise StopIteration()

    def close(self):
        self.should_connect = False
        self.retry = 0
        self.resp.raw._fp.fp.raw._sock.shutdown(socket.SHUT_RDWR)
        self.resp.raw._fp.fp.raw._sock.close()


class Stream(object):
    def __init__(self, url, stream_handler):
        self.url = url
        self.stream_handler = stream_handler
        self.sse = None
        self.thread = None
        self.start()

    def start(self):
        self.thread = threading.Thread(target=self.start_stream,
                                       args=(self.url, self.stream_handler))
        self.thread.start()
        return self

    def start_stream(self, url, stream_handler):
        self.sse = ClosableSSEClient(url)
        for msg in self.sse:
            msg_data = json.loads(msg.data)
            # don't return initial data
            if msg_data:
                msg_data[u"event"] = msg.event
                stream_handler(msg_data)

    def close(self):
        self.sse.close()
        self.thread.join()
        return self
