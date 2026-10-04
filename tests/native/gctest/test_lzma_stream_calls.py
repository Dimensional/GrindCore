"""LZMA stream encoding past a dictionary's worth of output (audit/lzma.md 3.5).

LzmaEncoder drives the multi-call API one BlockSize (= the dictionary size) per call. CodeOneBlock checks the pack limit
against the range coder's output since RangeEnc_Init, which on this solid path is the whole stream, so once the stream's
output passes BlockSize - 16 KiB every later call encodes a single symbol: correct output, hundreds of thousands of calls.
A small dictionary gets there in the first few hundred KiB. The output is decoded either way."""
import unittest

import gctest
from gctest import lzma_util as U, sample
from gctest.test_hashes import known

DICT = 64 << 10
WRITE = 64 << 10


class LzmaStreamCalls(unittest.TestCase):
    def test_calls_stay_block_sized_past_a_dictionary_of_output(self):
        data = sample.mixed(3 << 20, seed=71)
        bound = 4 * (len(data) // DICT) + 64          # ~1 call per dictionary of input by design; stalled: ~1 per symbol
        for level in (1, 5):
            e = U.LzmaStreamEncoder(gctest.LIB, level, DICT, max_calls=bound)
            out = bytearray()
            try:
                for i in range(0, len(data), WRITE):
                    out += e.encode_data(data[i:i + WRITE], final=False)
                for _ in range(64):
                    chunk = e.encode_data(b"", final=True)
                    out += chunk
                    if not chunk:
                        break
            except U.TooManyCalls:
                known(self, "lzma-stream-onesymbol")
            finally:
                props, calls = e.props, e.calls
                e.destroy()
            decoded, err = U.py_decode_alone(props + len(data).to_bytes(8, "little") + bytes(out))
            self.assertEqual(decoded, data, "level %d: %s" % (level, err))
            self.assertLessEqual(calls, bound, "level %d" % level)
            print("\n  level %d: %d bytes in, %d out, %d native calls (dictionary %d)" % (level, len(data), len(out), calls, DICT))
