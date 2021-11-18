# S-AES implementation in python3
# Written by: GS Sasank


# Byte substitution layer: 8 input bits and 8 output bits
s_box = [0x9, 0x4, 0xa, 0xb, 0xd, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xc, 0xe, 0xf, 0x7]

# Inverse byte substitution layer
inverse_s_box = [0xa, 0x5, 0x9, 0xb, 0x1, 0x7, 0x8, 0xf, 0x6, 0x0, 0x2, 0x3, 0xc, 0x4, 0xd, 0xe]

# Takes 16-bit input and out puts 16-bit ciphertext using a 16-bit key


# MAIN FUNCTIONS --------------------------------------------------------------


def add_key(state, key):
    return [s ^ k for s, k in zip(state, key)]


def nibble_substitution(s_box, state):
    return [s_box[nibble] for nibble in state]


def shift_rows(state):
    return [state[0], state[1], state[3], state[2]]
# works the same way forward and backwards, hence eliminating the need for inverse shift rows

def inverse_shift_rows(state):
    return [state[0], state[1], state[3], state[2]]

def mix_columns(state):
    return state[0] ^ gf_multiplier(4, state[2]), state[1] ^ gf_multiplier(4, state[3]), state[2] ^ gf_multiplier(4,
                                                                                                              state[
                                                                                                                      0]), \
           state[3] ^ gf_multiplier(4, state[1]),

def inverse_mix_columns(state):
    return gf_multiplier(9, state[0]) ^ gf_multiplier(2, state[2]), gf_multiplier(9, state[1]) ^ gf_multiplier(2, state[
        3]), gf_multiplier(9, state[2]) ^ gf_multiplier(2, state[0]), gf_multiplier(9, state[3]) ^ gf_multiplier(2,
                                                                                                                 state[
                                                                                                                     1]),


def key_expansion(key_value):
    round_const_1 = 0x80
    round_const_2 = 0x30
    word_value = [0] * 6
    word_value[0] = (key_value & 0xFF00) >> 8
    word_value[1] = key_value & 0x00FF
    word_value[2] = word_value[0] ^ (substitute_word(rotate_word(word_value[1])) ^ round_const_1)
    word_value[3] = word_value[2] ^ word_value[1]
    word_value[4] = word_value[2] ^ (substitute_word(rotate_word(word_value[3])) ^ round_const_2)
    word_value[5] = word_value[4] ^ word_value[3]

    return int_to_state((word_value[0] << 8) + word_value[1]), int_to_state(
        (word_value[2] << 8) + word_value[3]), int_to_state((word_value[4] << 8) + word_value[5])


def encrypt(plaintext, key_0, key_1, key_2):
    state = add_key(key_0, int_to_state(plaintext))
    state = mix_columns(shift_rows(nibble_substitution(s_box, state)))
    state = add_key(key_1, state)
    state = shift_rows(nibble_substitution(s_box, state))
    state = add_key(key_2, state)
    return state_to_int(state)


def decrypt(ciphertext, key_0, key_1, key_2):
    state = add_key(key_2, int_to_state(ciphertext))
    state = nibble_substitution(inverse_s_box, inverse_shift_rows(state))
    state = inverse_mix_columns(add_key(key_1, state))
    state = nibble_substitution(inverse_s_box, inverse_shift_rows(state))
    state = add_key(key_0, state)
    return state_to_int(state)


# HELPER FUNCTIONS ------------------------------------------------------------

# Prime field multiplication: used to mix columns

def gf_multiplier(a, b):
    product = 0

    a = a & 0x0F
    b = b & 0x0F

    while a and b:
        if b & 1:
            product ^= a
        a = a << 1
        if a & (1 << 4):
            a = a ^ 0b10011
        b = b >> 1
    return product


# Used to convert a 16-bit binary int to a 4-bit state matrix
# Used in key-expansion and conversion of entered input into state
def int_to_state(integer):
    return [integer >> 12 & 0xF, (integer >> 4) & 0xF, (integer >> 8) & 0xF, integer & 0xF]


# Used to convert the state matrix to an integer
def state_to_int(state):
    return (state[0] << 12) + (state[2] << 8) + (state[1] << 4) + state[3]


# Used in key expansion
def substitute_word(word):
    return (s_box[(word >> 4)] << 4) + s_box[word & 0x0F]


# Used in key expansion
def rotate_word(word):
    return ((word & 0x0F) << 4) + ((word & 0xF0) >> 4)



if __name__ == "__main__":

    print("----Simple AES Encoder and Decoder----")
    print("------------------------------------------------------------------------")
    print("")
    print("!!!!Please enter the values in the form of 16 bit binary number only!!!!")
    print("")
    print("------------------------------------------------------------------------")
    print("")
    print("Choose 1 for Encryption and 2 for Decryption: ")
    choice = int(input())
    if choice == 1:
        print("Enter the plaintext: ")
        plaintext = int(input(), 2)
        print("Enter the key: ")
        key = int(input(), 2)
        key_0, key_1, key_2 = key_expansion(key)
        ciphertext = encrypt(plaintext, key_0, key_1, key_2)
        bin_ = '{0:016b}'.format(ciphertext)
        print("The ciphertext in binary is: ", bin_)
        print("The ciphertext in decimal is: ", ciphertext)
    elif choice == 2:
        print("Enter the ciphertext: ")
        ciphertext = int(input(), 2)
        print("Enter the key: ")
        key = int(input(), 2)
        key_0, key_1, key_2 = key_expansion(key)
        plaintext = decrypt(ciphertext, key_0, key_1, key_2)
        bin_ = '{0:016b}'.format(plaintext)
        print("The plaintext in binary is: ", bin_)
        print("The plaintext in decimal is: ", plaintext)
    else:
        print("Invalid choice")
