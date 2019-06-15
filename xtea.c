//#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>

#define DELTA (0x9E3779B9)
#define DEFAULT_CYCLES (32)


// Signature: *k[4], *k[2], num_cycles
static PyObject * xtea_encrypt_int(PyObject *self, PyObject *args, PyObject *kwargs) {
    const uint32_t k[4];
    uint32_t v0, v1, sum=0;
    unsigned int num_cycles = DEFAULT_CYCLES;
    unsigned int i;

    if(!PyArg_ParseTuple(args, "(IIII)(II)|I",
                         &k[0], &k[1], &k[2], &k[3], &v0, &v1, &num_cycles)) return NULL;

    for (i=0; i < num_cycles; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
        sum += DELTA;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum>>11) & 3]);
    }
    PyObject *v0r = PyLong_FromUnsignedLongLong(v0);
    PyObject *v1r = PyLong_FromUnsignedLongLong(v1);

    return PyTuple_Pack(2, v0r, v1r);
};


static PyObject* xtea_decrypt_int(PyObject *self, PyObject *args) {
    const uint32_t k[4];
    uint32_t v0, v1, sum;
    unsigned int num_cycles = DEFAULT_CYCLES;
    unsigned int i;

    if(!PyArg_ParseTuple(args, "(IIII)(II)|I",
                         &k[0], &k[1], &k[2], &k[3], &v0, &v1, &num_cycles)) return NULL;

    sum = DELTA * num_cycles;

    for (i=0; i < num_cycles; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum>>11) & 3]);
        sum -= DELTA;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
    }

    PyObject *v0r = PyLong_FromUnsignedLong(v0);
    PyObject *v1r = PyLong_FromUnsignedLong(v1);

    return PyTuple_Pack(2, v0r, v1r);
};


static PyMethodDef XteaMethods[] = {
    {"encrypt_int", (PyCFunction) xtea_encrypt_int, METH_VARARGS, "Encrypt a single xtea block."},
    {"decrypt_int", (PyCFunction) xtea_decrypt_int, METH_VARARGS, "Decrypt a single xtea block."},
    {NULL, NULL, 0, NULL}
};


static struct PyModuleDef xteamodule = {
    PyModuleDef_HEAD_INIT,
    "_xtea",
    NULL,
    -1,
    XteaMethods
};

PyMODINIT_FUNC
PyInit__xtea() {
    return PyModule_Create(&xteamodule);
}
