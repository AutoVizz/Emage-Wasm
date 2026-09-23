#include <openjpeg.h>

extern "C" {

struct opj_j2k;
struct opj_event_mgr;

// OpenJPEG's internal marker dispatcher (src/lib/openjp2/j2k.c) declares the
// SEC/INSEC handlers in its marker table when USE_JPSEC is defined. The body
// of each marker segment (everything after the 2-byte length field) is handed
// to us; the stream cursor already points past the whole segment.
//
// Security zones are never acted upon here: an encrypted codestream arrives at
// the decoder with its payload already decrypted by jpsec_aes.c (layout
// documented in jpsec_aes.h). OpenJPEG only needs these entries to accept and
// skip the segments so header + codestream parsing can proceed.
OPJ_BOOL j2k_read_sec(struct opj_j2k* /*p_j2k*/,
                      OPJ_BYTE* /*p_header_data*/,
                      OPJ_UINT32 p_header_size,
                      struct opj_event_mgr* /*p_manager*/) {
    // JPSEC (ISO/IEC 15444-8 / ITU-T T.807) clause 5.5 segments always carry
    // at least one body byte (the Form field); a zero-length body is malformed.
    if (p_header_size < 1) {
        return OPJ_FALSE;
    }
    return OPJ_TRUE;
}

// INSEC (re-synchronization) markers are accepted and otherwise ignored.
OPJ_BOOL j2k_read_insec(struct opj_j2k* /*p_j2k*/,
                        OPJ_BYTE* /*p_header_data*/,
                        OPJ_UINT32 /*p_header_size*/,
                        struct opj_event_mgr* /*p_manager*/) {
    return OPJ_TRUE;
}

}  // extern "C"