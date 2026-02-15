from tools.classical_ciphers import register as register_classical
from tools.modern_crypto import register as register_modern
from tools.hash_tools import register as register_hash
from tools.encoding import register as register_encoding
from tools.xor_tools import register as register_xor
from tools.esoteric import register as register_esoteric
from tools.math_crypto import register as register_math
from tools.string_analysis import register as register_string
from tools.web_tools import register as register_web
from tools.misc_tools import register as register_misc
from tools.rsa_attacks import register as register_rsa_attacks
from tools.ecc_tools import register as register_ecc
from tools.matrix_tools import register as register_matrix


def register_all(mcp):
    register_classical(mcp)
    register_modern(mcp)
    register_hash(mcp)
    register_encoding(mcp)
    register_xor(mcp)
    register_esoteric(mcp)
    register_math(mcp)
    register_string(mcp)
    register_web(mcp)
    register_misc(mcp)
    register_rsa_attacks(mcp)
    register_ecc(mcp)
    register_matrix(mcp)
