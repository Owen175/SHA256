class SHA256:
    def __init__(self, entry):
        self.hashed = self.process(entry)


    def alpha_to_binary(self, entry):
        return ''.join(format(ord(x), 'b') for x in entry)
    def pre_processing_padding(self, binary_entry):
        original_length = len(binary_entry)
        binary_entry += '1'
        desired_length = ((len(binary_entry)+64)//512 + 1) * 512
        # Rounds to next 512 with space for 64 bits for size of initial message
        num_zeroes = desired_length - len(binary_entry) - 64
        for _ in range(num_zeroes):
            binary_entry += '0'
        bin_original_length = bin(original_length).zfill(64)
        binary_entry += bin_original_length
        print(len(binary_entry))
    def process(self, entry):
        binary_entry = self.alpha_to_binary(entry)
        padded_binary_entry = self.pre_processing_padding(binary_entry)

SHA256('hiadsf')