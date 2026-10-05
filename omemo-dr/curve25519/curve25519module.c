/* tell python that PyArg_ParseTuple(t#) means Py_ssize_t, not int */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#if (PY_VERSION_HEX < 0x02050000)
	typedef int Py_ssize_t;
#endif

#include <bytesobject.h>
#define y "y"

int curve25519_sign(unsigned char* signature_out,
                    const unsigned char* curve25519_privkey,
                    const unsigned char* msg, const unsigned long msg_len,
                    const unsigned char* random);

int curve25519_verify(const unsigned char* signature,
                      const unsigned char* curve25519_pubkey,
                      const unsigned char* msg, const unsigned long msg_len);


int curve25519_donna(char *mypublic,
                     const char *secret, const char *basepoint);


int xed25519_sign(unsigned char* signature_out,
                  const unsigned char* curve25519_privkey,
                  const unsigned char* msg, const unsigned long msg_len,
                  const unsigned char* random);

int ed25519_verify(const unsigned char* signature,
                   const unsigned char* ed_pubkey,
                   const unsigned char* msg, const unsigned long msg_len);

void convert_curve_to_ed_pubkey(unsigned char* ed_pubkey,
                                const unsigned char* curve_pubkey);

void convert_ed_to_curve_pubkey(unsigned char* ed_pubkey,
                                const unsigned char* curve_pubkey);


static PyObject *
calculateSignature(PyObject *self, PyObject *args)
{
    const char *random;
    const char *privatekey;
    const char *message;
    char signature[64];
    Py_ssize_t randomlen, privatekeylen, messagelen;

    if (!PyArg_ParseTuple(args, y"#"y"#"y"#:generate",&random, &randomlen, &privatekey, &privatekeylen, &message, &messagelen))
        return NULL;
     if (privatekeylen != 32) {
        PyErr_SetString(PyExc_ValueError, "private key must be 32-byte string" );
        return NULL;
    }
    if (randomlen != 64) {
        PyErr_SetString(PyExc_ValueError, "random must be 64-byte string");
        return NULL;
    }

    xed25519_sign((unsigned char *)signature, (unsigned char *)privatekey, 
                  (unsigned char *)message, messagelen, (unsigned char *)random);

   return PyBytes_FromStringAndSize((char *)signature, 64);
}

static PyObject *
verifySignatureCurve(PyObject *self, PyObject *args)
{
    const char *publickey;
    const char *message;
    const char *signature;

    Py_ssize_t publickeylen, messagelen, signaturelen;

    if (!PyArg_ParseTuple(args, y"#"y"#"y"#:verify", &publickey, &publickeylen, &message, &messagelen, &signature, &signaturelen))
        return NULL;

    if (publickeylen != 32) {
        PyErr_SetString(PyExc_ValueError, "publickey must be 32-byte string");
        return NULL;
    }
    if (signaturelen != 64) {
        PyErr_SetString(PyExc_ValueError, "signature must be 64-byte string");
        return NULL;
    }


    int result = curve25519_verify((unsigned char *)signature,
                                   (unsigned char *)publickey, 
                                   (unsigned char *)message,
                                   messagelen);

    return Py_BuildValue("i", result);

}

static PyObject *
verifySignatureEd(PyObject *self, PyObject *args)
{
    const char *publickey;
    const char *message;
    const char *signature;

    Py_ssize_t publickeylen, messagelen, signaturelen;

    if (!PyArg_ParseTuple(args, y"#"y"#"y"#:verify", &publickey, &publickeylen, &message, &messagelen, &signature, &signaturelen))
        return NULL;

    if (publickeylen != 32) {
        PyErr_SetString(PyExc_ValueError, "publickey must be 32-byte string");
        return NULL;
    }
    if (signaturelen != 64) {
        PyErr_SetString(PyExc_ValueError, "signature must be 64-byte string");
        return NULL;
    }

    int result = ed25519_verify((unsigned char *)signature,
                                (unsigned char *)publickey, 
                                (unsigned char *)message,
                                messagelen);

    return Py_BuildValue("i", result);

}

static PyObject *
generatePrivateKey(PyObject *self, PyObject *args)
{
    char *random;
    Py_ssize_t randomlen;

    if(!PyArg_ParseTuple(args, y"#:clamp", &random, &randomlen)) {
        return NULL;
    }

    if(randomlen != 32) {
        PyErr_SetString(PyExc_ValueError, "random must be 32-byte string");
        return NULL;
    }
    random[0] &= 248;
    random[31] &= 127;
    random[31] |= 64;

    return PyBytes_FromStringAndSize((char *)random, 32);
}

static PyObject *
generatePublicKey(PyObject *self, PyObject *args)
{
    const char *private;
    char mypublic[32];
    char basepoint[32] = {9};
    Py_ssize_t privatelen;
    if (!PyArg_ParseTuple(args, y"#:makepublic", &private, &privatelen))
        return NULL;
    if (privatelen != 32) {
        PyErr_SetString(PyExc_ValueError, "input must be 32-byte string");
        return NULL;
    }
    curve25519_donna(mypublic, private, basepoint);
    return PyBytes_FromStringAndSize((char *)mypublic, 32);
}

static PyObject *
calculateAgreement(PyObject *self, PyObject *args)
{
    const char *myprivate, *theirpublic;
    char shared_key[32];
    Py_ssize_t myprivatelen, theirpubliclen;
    if (!PyArg_ParseTuple(args, y"#"y"#:generate",
                          &myprivate, &myprivatelen, &theirpublic, &theirpubliclen))
        return NULL;
    if (myprivatelen != 32) {
        PyErr_SetString(PyExc_ValueError, "input must be 32-byte string");
        return NULL;
    }
    if (theirpubliclen != 32) {
        PyErr_SetString(PyExc_ValueError, "input must be 32-byte string");
        return NULL;
    }
    curve25519_donna(shared_key, myprivate, theirpublic);
    return PyBytes_FromStringAndSize((char *)shared_key, 32);
}


static PyObject *
convertCurveToEdPubkey(PyObject *self, PyObject *args)
{

    PyObject *obj;
    const char *publickey;
    unsigned char *ed;

    Py_ssize_t publickeylen;

    if (!PyArg_ParseTuple(args, y"#:convert", &publickey, &publickeylen))
        return NULL;

    if (publickeylen != 32) {
        PyErr_SetString(PyExc_ValueError, "input must be 32-byte string");
        return NULL;
    }

    ed = (unsigned char *) malloc(32);

    convert_curve_to_ed_pubkey(ed, (unsigned char *)publickey);

    obj = PyBytes_FromStringAndSize((char *)ed, 32);
    free(ed);

    return obj;

}

static PyObject *
convertEdToCurvePubkey(PyObject *self, PyObject *args)
{

    PyObject *obj;
    const char *publickey;
    unsigned char *ed;

    Py_ssize_t publickeylen;

    if (!PyArg_ParseTuple(args, y"#:convert", &publickey, &publickeylen))
        return NULL;

    if (publickeylen != 32) {
        PyErr_SetString(PyExc_ValueError, "input must be 32-byte string");
        return NULL;
    }

    ed = (unsigned char *) malloc(32);

    convert_ed_to_curve_pubkey(ed, (unsigned char *)publickey);

    obj = PyBytes_FromStringAndSize((char *)ed, 32);
    free(ed);

    return obj;

}


static PyMethodDef
curve25519_functions[] = {
    {"calculateSignature", calculateSignature, METH_VARARGS, "random+privatekey+message->signature"},
    {"verifySignatureCurve", verifySignatureCurve, METH_VARARGS, "publickey+message+signature->valid"},
    {"verifySignatureEd", verifySignatureEd, METH_VARARGS, "publickey+message+signature->valid"},
    {"generatePrivateKey", generatePrivateKey, METH_VARARGS, "data->private"},
    {"generatePublicKey", generatePublicKey, METH_VARARGS, "private->public"},
    {"calculateAgreement", calculateAgreement, METH_VARARGS, "private+public->shared"},
    {"convertCurveToEdPubkey", convertCurveToEdPubkey, METH_VARARGS, "public->public"},
    {"convertEdToCurvePubkey", convertEdToCurvePubkey, METH_VARARGS, "public->public"},
    {NULL, NULL, 0, NULL},
};



static struct PyModuleDef
curve25519_module = {
    PyModuleDef_HEAD_INIT,
    "_curve",
    NULL,
    0,
    curve25519_functions,
};

PyObject *
PyInit__curve(void)
{
    return PyModule_Create(&curve25519_module);
}

