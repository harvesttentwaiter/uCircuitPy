/* This example demonstrates the following features in a native module:
    - defining simple functions exposed to Python
    - defining local, helper C functions
    - defining constant integers and strings exposed to Python
    - getting and creating integer objects
    - creating Python lists
    - raising exceptions
    - allocating memory
    - BSS and constant data (rodata)
    - relocated pointers in rodata
*/

// Include the header file to get access to the MicroPython API
#include "py/dynruntime.h"

/*
// BSS (zero) data
uint16_t data16[4];

// Constant data (rodata)
const uint8_t table8[] = { 0, 1, 1, 2, 3, 5, 8, 13 };
const uint16_t table16[] = { 0x1000, 0x2000 };

// Constant data pointing to BSS/constant data
uint16_t *const table_ptr16a[] = { &data16[0], &data16[1], &data16[2], &data16[3] };
const uint16_t *const table_ptr16b[] = { &table16[0], &table16[1] };

// A simple function that adds its 2 arguments (must be integers)
STATIC mp_obj_t add(mp_obj_t x_in, mp_obj_t y_in) {
    mp_int_t x = mp_obj_get_int(x_in);
    mp_int_t y = mp_obj_get_int(y_in);
    return mp_obj_new_int(x + y);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(add_obj, add);

// A local helper function (not exposed to Python)
STATIC mp_int_t fibonacci_helper(mp_int_t x) {
    if (x < MP_ARRAY_SIZE(table8)) {
        return table8[x];
    } else {
        return fibonacci_helper(x - 1) + fibonacci_helper(x - 2);
    }
}

// A function which computes Fibonacci numbers
STATIC mp_obj_t fibonacci(mp_obj_t x_in) {
    mp_int_t x = mp_obj_get_int(x_in);
    if (x < 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("can't compute negative Fibonacci number"));
    }
    return mp_obj_new_int(fibonacci_helper(x));
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(fibonacci_obj, fibonacci);

// A function that accesses the BSS data
STATIC mp_obj_t access(size_t n_args, const mp_obj_t *args) {
    if (n_args == 0) {
        // Create a list holding all items from data16
        mp_obj_list_t *lst = MP_OBJ_TO_PTR(mp_obj_new_list(MP_ARRAY_SIZE(data16), NULL));
        for (int i = 0; i < MP_ARRAY_SIZE(data16); ++i) {
            lst->items[i] = mp_obj_new_int(data16[i]);
        }
        return MP_OBJ_FROM_PTR(lst);
    } else if (n_args == 1) {
        // Get one item from data16
        mp_int_t idx = mp_obj_get_int(args[0]) & 3;
        return mp_obj_new_int(data16[idx]);
    } else {
        // Set one item in data16 (via table_ptr16a)
        mp_int_t idx = mp_obj_get_int(args[0]) & 3;
        *table_ptr16a[idx] = mp_obj_get_int(args[1]);
        return mp_const_none;
    }
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(access_obj, 0, 2, access);

// A function that allocates memory and creates a bytearray
STATIC mp_obj_t make_array(void) {
    uint16_t *ptr = m_new(uint16_t, MP_ARRAY_SIZE(table_ptr16b));
    for (int i = 0; i < MP_ARRAY_SIZE(table_ptr16b); ++i) {
        ptr[i] = *table_ptr16b[i];
    }
    return mp_obj_new_bytearray_by_ref(sizeof(uint16_t) * MP_ARRAY_SIZE(table_ptr16b), ptr);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_0(make_array_obj, make_array);


STATIC mp_obj_t uhashlib_sha256_update(mp_obj_t self_in, mp_obj_t arg) {
    mp_obj_hash_t *self = MP_OBJ_TO_PTR(self_in);
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(arg, &bufinfo, MP_BUFFER_READ);
    mbedtls_sha256_update_ret((mbedtls_sha256_context *)&self->state, 
    * bufinfo.buf, bufinfo.len);
    return mp_const_none;
}


// */

#include "orlp/src/ed25519.h"

//#include "src/ge.h"
//#include "src/sc.h"


STATIC mp_obj_t sign(mp_obj_t pub, mp_obj_t sec, mp_obj_t msg) {
    mp_buffer_info_t pubB;
    mp_get_buffer_raise(pub, &pubB, MP_BUFFER_READ);
    mp_buffer_info_t secB;
    mp_get_buffer_raise(sec, &secB, MP_BUFFER_READ);
    mp_buffer_info_t msgB;
    mp_get_buffer_raise(msg, &msgB, MP_BUFFER_READ);

    //unsigned char signature[64];
    uint8_t *sig = m_new(uint8_t, 64); //MP_ARRAY_SIZE(signature));
        
    /* create signature on the message with the keypair */
    ed25519_sign(sig, (const unsigned char*)msgB.buf, msgB.len, 
		(const unsigned char*)pubB.buf, (const unsigned char*)secB.buf);

    return mp_obj_new_bytearray_by_ref(64, sig);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(sign_obj, sign);

STATIC mp_obj_t verify(mp_obj_t pub, mp_obj_t sig, mp_obj_t msg) {
    mp_buffer_info_t pubB;
    mp_get_buffer_raise(pub, &pubB, MP_BUFFER_READ);
    mp_buffer_info_t sigB;
    mp_get_buffer_raise(sig, &sigB, MP_BUFFER_READ);
    mp_buffer_info_t msgB;
    mp_get_buffer_raise(msg, &msgB, MP_BUFFER_READ);
        
    int rv;
    rv = ed25519_verify(sigB.buf, (const unsigned char*)msgB.buf, msgB.len, 
		(const unsigned char*)pubB.buf);

	if (rv) {
		return mp_obj_new_int(rv);
	} else {
		return mp_const_none;
	}
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(verify_obj, verify);

/*
import features1
import ubinascii
pub=ubinascii.unhexlify('c2acd61aafc7ef8b7c98cf433289969a10af72f94f50ac5f28aaed3dab6429ca')
sec=ubinascii.unhexlify('3045a8208b908626b555ff4cf9af0a7c6bb1821560329c60a94ff52fd3f2955a5e874dd57f43dee016adfcbd9741e134162af86cc34ed084535936b17c6b5dbb')
gold=ubinascii.unhexlify('06468f4e23ff9450bf182b78b90e3458e40b1c13a2b591d488aa95698c50a1a9fde52b9602c6455ea47f51961fc70c0b35a7167591337efa3046af747bc95504')
features1.sign(pub,sec,b'binky55')
features1.verify(pub,gold,b'binky55')
features1.verify(pub,gold,b'binky56')
*/


// This is the entry point and is called when the module is imported
mp_obj_t mpy_init(mp_obj_fun_bc_t *self, size_t n_args, size_t n_kw, mp_obj_t *args) {
    // This must be first, it sets up the globals dict and other things
    MP_DYNRUNTIME_INIT_ENTRY

    // Messages can be printed as usualy
    mp_printf(&mp_plat_print, "ed25519 initialising module self=%p\n", self);

    // Make the functions available in the module's namespace
    //mp_store_global(MP_QSTR_add, MP_OBJ_FROM_PTR(&add_obj));
    //mp_store_global(MP_QSTR_fibonacci, MP_OBJ_FROM_PTR(&fibonacci_obj));
    //mp_store_global(MP_QSTR_access, MP_OBJ_FROM_PTR(&access_obj));
    mp_store_global(MP_QSTR_sign, MP_OBJ_FROM_PTR(&sign_obj));
    mp_store_global(MP_QSTR_verify, MP_OBJ_FROM_PTR(&verify_obj));

	// sign char *pub, char *sec, char *msg
	//verify(char *pub, char *sig, char *msg)

    // Add some constants to the module's namespace
    //mp_store_global(MP_QSTR_VAL, MP_OBJ_NEW_SMALL_INT(42));
    //mp_store_global(MP_QSTR_MSG, MP_OBJ_NEW_QSTR(MP_QSTR_HELLO_MICROPYTHON));

    // This must be last, it restores the globals dict
    MP_DYNRUNTIME_INIT_EXIT
}
