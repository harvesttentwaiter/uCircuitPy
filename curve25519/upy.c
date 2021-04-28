// Include the header file to get access to the MicroPython API
#include "py/dynruntime.h"

#include "curve25519.h"


/* pip install pyelftools
clamp
	secret[0] &= 248;
	secret[31] = (secret[31] & 127) | 64;

// */

STATIC mp_obj_t genpub(mp_obj_t sec) {
    mp_buffer_info_t secB;
    mp_get_buffer_raise(sec, &secB, MP_BUFFER_READ);
        
    uint8_t *pub = m_new(uint8_t, 32);

    curve25519_generate_public(pub, secB.buf);

    return mp_obj_new_bytearray_by_ref(32, pub);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(genpub_obj, genpub);


STATIC mp_obj_t exchange(mp_obj_t mySec, mp_obj_t peerPub) {
    mp_buffer_info_t mySecB;
    mp_get_buffer_raise(mySec, &mySecB, MP_BUFFER_READ);
    mp_buffer_info_t peerPubB;
    mp_get_buffer_raise(peerPub, &peerPubB, MP_BUFFER_READ);

    uint8_t *shared = m_new(uint8_t, 32); //MP_ARRAY_SIZE(signature));
        
    curve25519(shared, mySecB.buf, peerPubB.buf);

    return mp_obj_new_bytearray_by_ref(32, shared);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(exchange_obj, exchange);

// This is the entry point and is called when the module is imported
mp_obj_t mpy_init(mp_obj_fun_bc_t *self, size_t n_args, size_t n_kw, mp_obj_t *args) {
    // This must be first, it sets up the globals dict and other things
    MP_DYNRUNTIME_INIT_ENTRY

    // Make the functions available in the module's namespace
    mp_store_global(MP_QSTR_exchange, MP_OBJ_FROM_PTR(&exchange_obj));
    mp_store_global(MP_QSTR_genpub, MP_OBJ_FROM_PTR(&genpub_obj));


    // This must be last, it restores the globals dict
    MP_DYNRUNTIME_INIT_EXIT
}
