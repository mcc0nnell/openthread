/*
 *  Copyright (c) 2026, The OpenThread Authors.
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

#include <stdio.h>
#include <vector>

#include <openthread/platform/radio.h>

#include "net/checksum.hpp"
#include "net/ip6_headers.hpp"
#include "platform/nexus_core.hpp"
#include "platform/nexus_node.hpp"
#include "thread/message_framer.hpp"
#include "thread/neighbor_table.hpp"

namespace ot {
namespace Nexus {

#if OPENTHREAD_CONFIG_MULTI_RADIO

static constexpr uint16_t kPoisonTag = 0x4000;
static constexpr uint16_t kLegitTag  = kPoisonTag - 1;
static constexpr uint16_t kPayloadLength = 320;

static Message *BuildUdpMessage(Node &aOwner, const Ip6::Address &aSource, const Ip6::Address &aDestination)
{
    Message *message = aOwner.Get<MessagePool>().Allocate(Message::kTypeIp6);

    VerifyOrQuit(message != nullptr);

    std::vector<uint8_t> payload(kPayloadLength, 0x5a);

    Ip6::Header ip6Header;
    ip6Header.InitVersionTrafficClassFlow();
    ip6Header.SetPayloadLength(static_cast<uint16_t>(sizeof(Ip6::UdpHeader) + payload.size()));
    ip6Header.SetNextHeader(Ip6::kProtoUdp);
    ip6Header.SetHopLimit(Ip6::kDefaultHopLimit);
    ip6Header.SetSource(aSource);
    ip6Header.SetDestination(aDestination);

    Ip6::UdpHeader udpHeader;
    udpHeader.Clear();
    udpHeader.SetSourcePort(12345);
    udpHeader.SetDestinationPort(12345);
    udpHeader.SetLength(static_cast<uint16_t>(sizeof(Ip6::UdpHeader) + payload.size()));
    udpHeader.SetChecksum(0);

    SuccessOrQuit(message->Append(ip6Header));
    SuccessOrQuit(message->Append(udpHeader));
    SuccessOrQuit(message->AppendBytes(payload.data(), static_cast<uint16_t>(payload.size())));

    message->SetOffset(sizeof(Ip6::Header));
    Checksum::UpdateMessageChecksum(*message, aSource, aDestination, Ip6::kProtoUdp);
    message->SetOffset(0);
    message->SetLinkSecurityEnabled(true);

    return message;
}

static uint16_t DeliverFirstFragment(Node                 &aSender,
                                     Node                 &aReceiver,
                                     Message              &aMessage,
                                     const Mac::Addresses &aMacAddresses,
                                     bool                  aAddMeshHeader,
                                     uint16_t              aMeshSource,
                                     uint16_t              aMeshDestination)
{
    Radio::Frame frame;
    uint16_t nextOffset = aSender.Get<MessageFramer>().PrepareFrame(frame,
                                                                    aMessage,
                                                                    aMacAddresses,
                                                                    aAddMeshHeader,
                                                                    aMeshSource,
                                                                    aMeshDestination,
                                                                    true);

    VerifyOrQuit(nextOffset > 0);
    VerifyOrQuit(nextOffset < aMessage.GetLength());

    SuccessOrQuit(otMacFrameProcessTxSfd(&frame, Core::Get().GetNowMicro64(), &aSender.mRadio.mRadioContext));
    frame.UpdateFcs();

    Radio::Frame rxFrame(frame);
    rxFrame.mInfo.mRxInfo.mTimestamp = Core::Get().GetNowMicro64();
    rxFrame.mInfo.mRxInfo.mRssi      = -20;
    rxFrame.mInfo.mRxInfo.mLqi       = 255;

    otPlatRadioReceiveDone(&aReceiver.GetInstance(), &rxFrame, kErrorNone);

    return nextOffset;
}

void TestMeshOriginatorDoesNotOwnNeighborDuplicateState(void)
{
    Core  nexus;
    Node &receiver = nexus.CreateNode();
    Node &originA  = nexus.CreateNode();
    Node &relayB   = nexus.CreateNode();

    AllowLinkBetween(receiver, originA);
    AllowLinkBetween(receiver, relayB);

    receiver.Form();
    nexus.AdvanceTime(15 * 1000);

    originA.Join(receiver, Node::kAsFtd);
    relayB.Join(receiver, Node::kAsFtd);
    nexus.AdvanceTime(120 * 1000);

    VerifyOrQuit(receiver.Get<Mle::Mle>().IsLeader());
    VerifyOrQuit(originA.Get<Mle::Mle>().IsAttached());
    VerifyOrQuit(relayB.Get<Mle::Mle>().IsAttached());

    Neighbor *neighborA = receiver.Get<NeighborTable>().FindNeighbor(originA.Get<Mac::Mac>().GetExtAddress());
    Neighbor *neighborB = receiver.Get<NeighborTable>().FindNeighbor(relayB.Get<Mac::Mac>().GetExtAddress());

    VerifyOrQuit(neighborA != nullptr);
    VerifyOrQuit(neighborB != nullptr);

    neighborA->ClearLastRxFragmentTag();
    neighborB->ClearLastRxFragmentTag();

    const Ip6::Address &source = originA.Get<Mle::Mle>().GetMeshLocalRloc();
    const Ip6::Address &dest   = receiver.Get<Mle::Mle>().GetMeshLocalRloc();

    OwnedPtr<Message> poisonMessage(BuildUdpMessage(relayB, source, dest));
    poisonMessage->SetDatagramTag(kPoisonTag);

    Mac::Addresses relayAddresses;
    relayAddresses.mSource.SetShort(relayB.Get<Mac::Mac>().GetShortAddress());
    relayAddresses.mDestination.SetShort(receiver.Get<Mac::Mac>().GetShortAddress());

    DeliverFirstFragment(relayB,
                         receiver,
                         *poisonMessage,
                         relayAddresses,
                         true,
                         originA.Get<Mac::Mac>().GetShortAddress(),
                         receiver.Get<Mac::Mac>().GetShortAddress());

    // Duplicate suppression belongs to the authenticated immediate sender (relayB),
    // not to the Mesh Header originator (originA).
    VerifyOrQuit(!neighborA->IsLastRxFragmentTagSet());
    VerifyOrQuit(neighborB->IsLastRxFragmentTagSet());
    VerifyOrQuit(neighborB->GetLastRxFragmentTag() == kPoisonTag);

    MessageQueue::Info sendInfo;
    MessageQueue::Info reassemblyInfo;
    ClearAllBytes(sendInfo);
    ClearAllBytes(reassemblyInfo);
    receiver.Get<MeshForwarder>().GetQueueInfo(sendInfo, reassemblyInfo);
    VerifyOrQuit(reassemblyInfo.mNumMessages == 1);

    OwnedPtr<Message> legitMessage(BuildUdpMessage(originA, source, dest));
    legitMessage->SetDatagramTag(kLegitTag);

    Mac::Addresses directAddresses;
    directAddresses.mSource.SetShort(originA.Get<Mac::Mac>().GetShortAddress());
    directAddresses.mDestination.SetShort(receiver.Get<Mac::Mac>().GetShortAddress());

    DeliverFirstFragment(originA,
                         receiver,
                         *legitMessage,
                         directAddresses,
                         false,
                         0,
                         0);

    ClearAllBytes(sendInfo);
    ClearAllBytes(reassemblyInfo);
    receiver.Get<MeshForwarder>().GetQueueInfo(sendInfo, reassemblyInfo);

    VerifyOrQuit(neighborA->IsLastRxFragmentTagSet());
    VerifyOrQuit(neighborA->GetLastRxFragmentTag() == kLegitTag);
    VerifyOrQuit(reassemblyInfo.mNumMessages == 2);
}

#endif // OPENTHREAD_CONFIG_MULTI_RADIO

} // namespace Nexus
} // namespace ot

int main(void)
{
#if OPENTHREAD_CONFIG_MULTI_RADIO
    ot::Nexus::TestMeshOriginatorDoesNotOwnNeighborDuplicateState();
#endif
    printf("All tests passed\n");
    return 0;
}
