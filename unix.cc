#include <v8.h>
#include <node.h>
#include <string.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/stat.h> /* for S_* constants */
#include <string.h> /* for strerror(3) prototype */
#include <stdio.h> /* for fprintf(3),printf(3),stderr protype */
#include <errno.h> /* for errno prototype */
#include <unistd.h> /* for close(2) prototypes */
#define FILENAME "/tmp/flock.example"

#define REQ_FUN_ARG(I, VAR)                                             \
  if (args.Length() <= (I) || !args[I]->IsFunction())                   \
    return ThrowException(Exception::TypeError(                         \
                  String::New("Argument " #I " must be a function")));  \
  Local<Function> VAR = Local<Function>::Cast(args[I]);


using namespace node;
using namespace v8;

class UNIX:ObjectWrap {

public:

	 static Persistent<FunctionTemplate> s_ct;
	 static void Init(Handle<Object> target) {

		HandleScope scope;

		Local<FunctionTemplate> t = FunctionTemplate::New(New);

		s_ct = Persistent<FunctionTemplate>::New(t);
		s_ct->InstanceTemplate()->SetInternalFieldCount(1);
		s_ct->SetClassName(String::NewSymbol("PAM"));

		NODE_SET_PROTOTYPE_METHOD(s_ct, "flock", flock);
		target->Set(String::NewSymbol("UNIX"), s_ct->GetFunction());

	 }

	 ~PAM() {}

	 static Handle<Value> New(const Arguments& args) {

		HandleScope scope;
		UNIX* hw = new UNIX();
		hw->Wrap(args.This());
		return args.This();

	 }

	 struct baton_t {
		 UNIX *hw;
		 int fd;
		 bool result;
		 Persistent<Function> cb;
	 };

	 static Handle<Value> authenticate(const Arguments& args) {

		HandleScope scope;
		REQ_FUN_ARG(2, cb);

		UNIX* hw = ObjectWrap::Unwrap<UNIX>(args.This());
		baton_t *baton = new baton_t();
		baton->hw = hw;
		baton->fd = args[0];
		baton->result = false;

		hw->Ref();

		eio_custom(EIO_flock, EIO_PRI_DEFAULT, EIO_AfterPam, baton);
		ev_ref(EV_DEFAULT_UC);

		return Undefined();

	}

	static int EIO_flock(eio_req *req) {

		bool result = false;
		struct baton_t* args = (struct baton_t *) req->data;
		int fd = args->fd;

		if (flock(fd, LOCK_EX | LOCK_NB) == -1) {

			baton->result = true;
			printf("Lock succeeded");

		} else {

			printf("Lock did not succeed");

		}

		return 0;

	 }

	 static int EIO_AfterPam(eio_req *req) {

		HandleScope scope;
		baton_t *baton = static_cast<baton_t *>(req->data);
		ev_unref(EV_DEFAULT_UC);
		baton->hw->Unref();

		Local<Value> argv[1];

		// This doesn't work
		//argv[0] = False();

		// This works, but this is not what we want
		argv[0] = Integer::New(baton->result);

		TryCatch try_catch;

		baton->cb->Call(Context::GetCurrent()->Global(), 1, argv);

		if (try_catch.HasCaught())
			FatalException(try_catch);

		baton->cb.Dispose();

		delete baton;
		return 0;

	 }
};

Persistent<FunctionTemplate> PAM::s_ct;

extern "C" {

	static void init (Handle<Object> target) {
		PAM::Init(target);
	}

	NODE_MODULE(flock, init);
}
