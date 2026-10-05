
#include "fe.h"
#include "crypto_additions.h"

void convert_curve_to_ed_pubkey(unsigned char* ed_pubkey,
                                const unsigned char* curve_pubkey) {
    fe u;
    fe y;

    fe_frombytes(y, curve_pubkey);
    fe_edy_to_montx(u, y);
    fe_tobytes(ed_pubkey, u);

}


void convert_ed_to_curve_pubkey(unsigned char* ed_pubkey,
                                const unsigned char* curve_pubkey) {
    fe u;
    fe y;

    fe_frombytes(y, curve_pubkey);
    fe_montx_to_edy(u, y);
    fe_tobytes(ed_pubkey, u);

}
