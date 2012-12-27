#include <v8.h>
#include <node.h>
#include <string.h>
#include <stdlib.h>
#include <sys/file.h>
#include <stdio.h>
#include <crypt.h>
#include <security/pam_appl.h>

#ifndef NODE_MAX_SALT_LEN
#define NODE_MAX_SALT_LEN 2
#endif

#define REQ_FUN_ARG(I, VAR)                                             \
  if (args.Length() <= (I) || !args[I]->IsFunction())                   \
    return ThrowException(Exception::TypeError(                         \
                  String::New("Argument " #I " must be a function")));  \
  Local<Function> VAR = Local<Function>::Cast(args[I]);


using namespace node;
using namespace v8;

static Handle<Value> MkstempAsync(const Arguments&);
static void Mkstemp(eio_req *);
static int AfterMkstemp(eio_req *);
static Handle<Value> FlockAsync(const Arguments&);
static void Flock(eio_req *);
static int  AfterFlock(eio_req *);
static Handle<Value> PAMAuthAsync(const Arguments&);
static void PAMAuth(eio_req *);
static int AfterPAMAuth(eio_req *);
static Handle<Value> CryptAsync(const Arguments&);
static Handle<Value> CryptSync(const Arguments&);
static void Crypt(eio_req *);
static int AfterCrypt(eio_req *);
extern "C" void init(Handle<Object>);

extern "C" {

    struct pam_response *reply;

    int null_conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr) {

        *resp = reply;
        return PAM_SUCCESS;

    }                       

    static struct pam_conv conv = { null_conv, NULL };

    const char* ToCString(const v8::String::Utf8Value& value) {
        return *value ? *value : "<string conversion failed>";
    }               

    int _pam_authenticate(const char *service, const char *username, const char *password) {

        pam_handle_t *pamh = NULL;
        int retval = pam_start(service, username, &conv, &pamh);

        if (retval == PAM_SUCCESS) {

            reply = (struct pam_response *) malloc(sizeof(struct pam_response));
            reply[0].resp = (char *) password;
            reply[0].resp_retcode = 0;

            retval = pam_authenticate(pamh, 0);
            pam_end(pamh, PAM_SUCCESS);

        }

        return retval;

    }
}

struct mkstemp_baton {
	char *strtemplate;
	int fd;
	bool result;
	Persistent<Function> cb;
};

struct flock_baton {
	int fd;
	bool result;
	Persistent<Function> cb;
};

struct pam_baton {
	bool result;
	const char *service;
	const char *username;
	const char *password;
	Persistent<Function> cb;
};
struct crypt_baton {
  char *passwd;
  char *salt;
	char *result;
	Persistent<Function> cb;
};


static Handle<Value> MkstempAsync(const Arguments& args) {

	HandleScope scope;
	const char *usage = "usage: mkstemp(template, callback)";

	if (args.Length() != 2)
		return ThrowException(Exception::Error(String::New(usage)));

	if (!args[0]->IsString())
		return ThrowException(Exception::TypeError(String::New("First argument must be a string")));

	REQ_FUN_ARG(1, cb);

	mkstemp_baton *baton = (mkstemp_baton *) malloc(sizeof(struct mkstemp_baton));

	String::Utf8Value strtemplate(args[0]);
	baton->strtemplate = strdup(ToCString(strtemplate));
	baton->cb = Persistent<Function>::New(cb);
	baton->result = false;

	eio_custom(Mkstemp, EIO_PRI_DEFAULT, AfterMkstemp, baton);
	ev_ref(EV_DEFAULT_UC);
	return scope.Close(Undefined());

}

static Handle<Value> FlockAsync(const Arguments& args) {

	HandleScope scope;
	const char *usage = "usage: flock(fd, callback)";

	if (args.Length() != 2)
		return ThrowException(Exception::Error(String::New(usage)));

	if (!args[0]->IsInt32())
		return ThrowException(Exception::TypeError(String::New("First argument must be a file descriptor")));

	REQ_FUN_ARG(1, cb);

	flock_baton *baton = (flock_baton *) malloc(sizeof(struct flock_baton));

	baton->fd = args[0]->Int32Value();
	baton->cb = Persistent<Function>::New(cb);
	baton->result = false;

	eio_custom(Flock, EIO_PRI_DEFAULT, AfterFlock, baton);
	ev_ref(EV_DEFAULT_UC);
	return scope.Close(Undefined());

}

static Handle<Value> PAMAuthAsync(const Arguments& args) {

	HandleScope scope;
	const char *usage = "usage: pamauth(service, username, password, callback)";

	if (args.Length() != 4)
		return ThrowException(Exception::Error(String::New(usage)));

	REQ_FUN_ARG(3, cb);

	pam_baton *baton = new pam_baton();
	baton->result = false;

	String::Utf8Value service(args[0]);
	String::Utf8Value username(args[1]);
	String::Utf8Value password(args[2]);

	baton->service = strdup(ToCString(service));
	baton->username = strdup(ToCString(username));
	baton->password = strdup(ToCString(password));
	baton->cb = Persistent<Function>::New(cb);

	eio_custom(PAMAuth, EIO_PRI_DEFAULT, AfterPAMAuth, baton);
	ev_ref(EV_DEFAULT_UC);
	return scope.Close(Undefined());

}

static Handle<Value> CryptSync(const Arguments& args) {
  HandleScope scope;
  const char *usage = "usage: cryptSync(password [, salt ])";
  char salt[NODE_MAX_SALT_LEN + 1];
  bool salt_def = false;
  bool valid_call = false;
  
  strncpy(salt, "$1$", NODE_MAX_SALT_LEN);
  if (args.Length() == 1) {
    valid_call = true;
	}
  if (args.Length() == 2) {
    valid_call = true;
    salt_def = true;
  }
  if (!valid_call)
		return ThrowException(Exception::Error(String::New(usage)));

String::Utf8Value password(args[0]);
  if (salt_def) {
    String::Utf8Value salt_arg(args[1]);
    strncpy(salt, ToCString(salt_arg), NODE_MAX_SALT_LEN);
  }
  char *result = crypt(ToCString(password),salt);
  return scope.Close(String::New(result));
}

static Handle<Value> CryptAsync(const Arguments& args) {

  HandleScope scope;
	const char *usage = "usage: crypt(password [, salt ], callback)";
  char salt[NODE_MAX_SALT_LEN + 1];
  bool salt_def = false;
  bool valid_call = false;
  int cbid = 2;
  //salt[0] = salt[NODE_MAX_SALT_LEN] = '\0';
  strncpy(salt, "$1$", NODE_MAX_SALT_LEN);
	if (args.Length() == 2) {
    valid_call = true;
    cbid = 1;
	}
  if (args.Length() == 3) {
    valid_call = true;
    salt_def = true;
    cbid = 2;
  }
  if (!valid_call)
		return ThrowException(Exception::Error(String::New(usage)));

	REQ_FUN_ARG(cbid, cb);

	crypt_baton *baton = new crypt_baton();
	baton->result = false;

	String::Utf8Value password(args[0]);
  if (salt_def) {
    String::Utf8Value salt_arg(args[1]);
    strncpy(salt, ToCString(salt_arg), NODE_MAX_SALT_LEN);
  }
  baton->salt = strdup(salt);
  

	baton->passwd = strdup(ToCString(password));
  
	baton->cb = Persistent<Function>::New(cb);

	eio_custom(Crypt, EIO_PRI_DEFAULT, AfterCrypt, baton);
	ev_ref(EV_DEFAULT_UC);
	return scope.Close(Undefined());

}

static void Mkstemp(eio_req *req) {

	struct mkstemp_baton * baton = (struct mkstemp_baton *)req->data;
	int fd = mkstemp(baton->strtemplate);

	if (fd == -1)
		baton->result = false;

	else {

		baton->fd = fd;
		baton->result = true;

	}
}

static void Flock(eio_req *req) {

	struct flock_baton * baton = (struct flock_baton *)req->data;

	if (flock(baton->fd, LOCK_EX | LOCK_NB) == -1)
		baton->result = false;
	else
		baton->result = true;

}

static void PAMAuth(eio_req *req) {

	struct pam_baton* baton = (struct pam_baton*) req->data;
	char *service = strdup(baton->service);
	char *username = strdup(baton->username);
	char *password = strdup(baton->password);
	int retval = _pam_authenticate(service, username, password);

	if (retval == PAM_SUCCESS)
		baton->result = true;

}
static void Crypt(eio_req *req) {
  
  struct crypt_baton* baton = (struct crypt_baton*) req->data;
  //struct crypt_data buffer;
	char *passwd = strdup(baton->passwd);
  char *salt = strdup(baton->salt);
		baton->result = crypt(passwd, salt);

}

static int AfterMkstemp(eio_req *req) {

	HandleScope scope;
	ev_unref(EV_DEFAULT_UC);
	struct mkstemp_baton * baton = (struct mkstemp_baton *)req->data;
	Handle<Value> argv[3];

	if (baton->result) {

		argv[0] = Null();
		argv[1] = Integer::New(baton->fd);
		argv[2] = String::New(baton->strtemplate);

	} else {

		argv[0] = True();
		argv[1] = Null();
		argv[2] = Null();

	}

	TryCatch try_catch;
	baton->cb->Call(Context::GetCurrent()->Global(), 3, argv);

	if (try_catch.HasCaught())
		FatalException(try_catch);

	baton->cb.Dispose();
	delete baton;
    return 0;

}

static int AfterFlock(eio_req *req) {

	HandleScope scope;
	ev_unref(EV_DEFAULT_UC);
	struct flock_baton * baton = (struct flock_baton *)req->data;
	Local<Value> argv[1];

	if (baton->result)
		argv[0] = Local<Boolean>::New(True());
	else
		argv[0] = Local<Boolean>::New(False());

	TryCatch try_catch;
	baton->cb->Call(Context::GetCurrent()->Global(), 1, argv);

	if (try_catch.HasCaught())
		FatalException(try_catch);

	baton->cb.Dispose();
	delete baton;
    return 0;

}

static int AfterPAMAuth(eio_req *req) {

	HandleScope scope;
	ev_unref(EV_DEFAULT_UC);
	pam_baton *baton = static_cast<pam_baton *>(req->data);

	Local<Value> argv[1];

	if (baton->result)
		argv[0] = Local<Boolean>::New(True());
	else
		argv[0] = Local<Boolean>::New(False());

	TryCatch try_catch;

	baton->cb->Call(Context::GetCurrent()->Global(), 1, argv);

	if (try_catch.HasCaught())
		FatalException(try_catch);

	baton->cb.Dispose();
	delete baton;
    return 0;

}

static int AfterCrypt(eio_req *req) {

  HandleScope scope;
	ev_unref(EV_DEFAULT_UC);
	crypt_baton *baton = static_cast<crypt_baton *>(req->data);

	Local<Value> argv[1];

	if (baton->result) {
		argv[0] = Local<Boolean>::New(True());
    argv[1] = String::New(baton->result);
	}
	else
		argv[0] = Local<Boolean>::New(False());

	TryCatch try_catch;

	baton->cb->Call(Context::GetCurrent()->Global(), 2, argv);

	if (try_catch.HasCaught())
		FatalException(try_catch);

	baton->cb.Dispose();
	delete baton;
    return 0;

}

extern "C" void init (Handle<Object> target) {

	HandleScope scope;
	NODE_SET_METHOD(target, "flock", FlockAsync);
	NODE_SET_METHOD(target, "pamauth", PAMAuthAsync);
	NODE_SET_METHOD(target, "mkstemp", MkstempAsync);
  NODE_SET_METHOD(target, "crypt", CryptAsync);
  NODE_SET_METHOD(target, "cryptSync", CryptSync);

}
