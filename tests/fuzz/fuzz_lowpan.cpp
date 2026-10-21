/*
 *  Copyright (c) 2025, The OpenThread Authors.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the copyright holder nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include "thread/lowpan.hpp"

// Parser-only target. This does not fuzz mesh reassembly or sender identity.
// A successful parse must consume exactly the header and preserve all decoded fields.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *aData, size_t aSize)
{
    static constexpr size_t kMaxFrameSize = 127;

    if (aSize > kMaxFrameSize)
    {
        return 0;
    }

    ot::FrameData              frameData;
    ot::Lowpan::FragmentHeader header;

    frameData.Init(aData, static_cast<uint16_t>(aSize));

    bool      isFragment = ot::Lowpan::FragmentHeader::IsFragmentHeader(frameData);
    ot::Error error      = header.ParseFrom(frameData);

    if (error == ot::kErrorNone)
    {
        uint16_t headerLength = (aData[0] & 0x20) ? 5 : 4;
        uint16_t size         = static_cast<uint16_t>((static_cast<uint16_t>(aData[0]) << 8) | aData[1]);

        assert(isFragment);
        assert(aSize >= headerLength);
        assert(frameData.GetLength() == aSize - headerLength);
        assert(frameData.GetBytes() == aData + headerLength);
        assert(header.GetDatagramSize() == (size & 0x7ff));
        assert(header.GetDatagramTag() == (static_cast<uint16_t>(aData[2]) << 8 | aData[3]));
        assert(header.GetDatagramOffset() == (headerLength == 5 ? static_cast<uint16_t>(aData[4]) * 8 : 0));
    }
    else
    {
        // A malformed frame cannot advance the frame-data cursor.
        assert(frameData.GetLength() == aSize);
        assert(frameData.GetBytes() == aData);
        assert(!isFragment || (aSize == 4 && (aData[0] & 0x20)));
    }

    return 0;
}
