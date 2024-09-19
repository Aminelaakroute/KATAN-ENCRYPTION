class KATAN:
    def __init__(self, key, variant):
        self.key = key
        self.variant = variant
        self.set_parameters()
        self.generate_round_keys()

    def set_parameters(self):
        if self.variant == 32:
            self.block_size = 32
            self.n_rounds = 254
            self.l1_size = 13
            self.l2_size = 19
            self.ir = [12, 7, 8, 5, 3]
            self.fa = [18, 7, 12, 10, 8, 3]
        elif self.variant == 48:
            self.block_size = 48
            self.n_rounds = 254
            self.l1_size = 19
            self.l2_size = 29
            self.ir = [18, 12, 15, 7, 6]
            self.fa = [28, 19, 21, 13, 15, 6]
        elif self.variant == 64:
            self.block_size = 64
            self.n_rounds = 254
            self.l1_size = 25
            self.l2_size = 39
            self.ir = [24, 15, 20, 11, 9]
            self.fa = [38, 25, 33, 21, 14, 9]
        else:
            raise ValueError("Unsupported variant")

    def generate_round_keys(self):
        self.round_keys = []
        key_bits = [int(b) for b in format(self.key, '080b')]
        for i in range(self.n_rounds):
            self.round_keys.append(key_bits[0])
            new_bit = key_bits[0] ^ key_bits[19] ^ key_bits[30] ^ key_bits[67]
            key_bits = key_bits[1:] + [new_bit]

    def encrypt(self, plaintext):
        L1 = plaintext >> self.l2_size
        L2 = plaintext & ((1 << self.l2_size) - 1)

        for r in range(self.n_rounds):
            new_bit1 = self.round_function(L1, self.ir) ^ self.round_keys[r]
            new_bit2 = self.round_function(L2, self.fa)

            L1 = ((L1 << 1) | new_bit2) & ((1 << self.l1_size) - 1)
            L2 = ((L2 << 1) | new_bit1) & ((1 << self.l2_size) - 1)

        return (L1 << self.l2_size) | L2

    def decrypt(self, ciphertext):
        L1 = ciphertext >> self.l2_size
        L2 = ciphertext & ((1 << self.l2_size) - 1)

        for r in range(self.n_rounds - 1, -1, -1):
            old_bit1 = L1 & 1
            old_bit2 = L2 & 1

            L1 = (L1 >> 1) | (
                        (old_bit2 ^ self.round_function(L1 >> 1, self.ir) ^ self.round_keys[r]) << (self.l1_size - 1))
            L2 = (L2 >> 1) | ((old_bit1 ^ self.round_function(L2 >> 1, self.fa)) << (self.l2_size - 1))

        return (L1 << self.l2_size) | L2

    def round_function(self, x, positions):
        result = x >> positions[0]
        result ^= x >> positions[1]
        result ^= (x >> positions[2]) & (x >> positions[3])
        result ^= (x >> positions[4])
        if len(positions) > 5:
            result ^= x >> positions[5]
        return result & 1