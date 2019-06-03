//
// Copyright (C) 2015-2019 Virgil Security Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
//

import Foundation
import VirgilSDK
import VirgilCrypto
import VirgilCryptoRatchet

/// SecureSession errors
///
/// - invalidUtf8String: invalid convesion to/from utf-8 string
@objc(VSCRSecureGroupSessionError) public enum SecureGroupSessionError: Int, Error {
    case invalidUtf8String = 1
}

/// SecureSession
/// NOTE: This class is thread-safe
@objc(VSRSecureGroupSession) public final class SecureGroupSession: NSObject {
    /// Crypto
    @objc public let crypto: VirgilCrypto

    /// SessionStorage
    @objc public let sessionStorage: GroupSessionStorage

    @objc public var identifier: String {
        return self.ratchetGroupSession.getSessionId().hexEncodedString()
    }

    @objc public var myIdentifier: String {
        return self.ratchetGroupSession.getMyId().hexEncodedString()
    }

    @objc public var participantsCount: UInt32 {
        return self.ratchetGroupSession.getParticipantsCount()
    }

    private let ratchetGroupSession: RatchetGroupSession
    private let queue = DispatchQueue(label: "SecureGroupSessionQueue")

    internal init(crypto: VirgilCrypto,
                  sessionStorage: GroupSessionStorage,
                  privateKeyData: Data,
                  myId: Data,
                  ratchetGroupMessage: RatchetGroupMessage,
                  cards: [Card]) throws {
        self.crypto = crypto
        self.sessionStorage = sessionStorage

        let ratchetGroupSession = RatchetGroupSession()
        ratchetGroupSession.setRng(rng: crypto.rng)

        try ratchetGroupSession.setPrivateKey(myPrivateKey: privateKeyData)
        ratchetGroupSession.setMyId(myId: myId)

        let info = RatchetGroupParticipantsInfo(size: UInt32(cards.count))

        try cards.forEach { card in
            guard let participantId = Data(hexEncodedString: card.identifier) else {
                throw NSError()
            }

            guard let publicKey = card.publicKey as? VirgilPublicKey else {
                throw NSError()
            }

            let publicKeyData = try crypto.exportPublicKey(publicKey)

            try info.addParticipant(id: participantId, pubKey: publicKeyData)
        }

        try ratchetGroupSession.setupSessionState(message: ratchetGroupMessage, participants: info)

        self.ratchetGroupSession = ratchetGroupSession

        super.init()
    }

    /// Encrypts string. Updates session in storage
    ///
    /// - Parameter message: message to encrypt
    /// - Returns: RatchetMessage
    /// - Throws:
    ///         - SecureSessionError.invalidUtf8String if given string is not correct utf-8 string
    ///         - Rethrows from crypto RatchetSession
    ///         - Rethrows from SessionStorage
    public func encrypt(string: String) throws -> RatchetGroupMessage {
        guard let data = string.data(using: .utf8) else {
            throw SecureSessionError.invalidUtf8String
        }

        return try self.encrypt(data: data)
    }

    /// Encrypts data. Updates session in storage
    ///
    /// - Parameter message: message to encrypt
    /// - Returns: RatchetMessage
    /// - Throws:
    ///         - Rethrows from crypto RatchetSession
    ///         - Rethrows from SessionStorage
    public func encrypt(data: Data) throws -> RatchetGroupMessage {
        return try self.queue.sync {
            let msg = try self.ratchetGroupSession.encrypt(plainText: data)

            try self.sessionStorage.storeSession(self)

            return msg
        }
    }

    /// Decrypts data from RatchetMessage. Updates session in storage
    ///
    /// - Parameter message: RatchetMessage
    /// - Returns: Decrypted data
    /// - Throws:
    ///         - Rethrows from crypto RatchetSession
    ///         - Rethrows from SessionStorage
    public func decryptData(from message: RatchetGroupMessage) throws -> Data {
        return try self.queue.sync {
            let data = try self.ratchetGroupSession.decrypt(message: message)

            try self.sessionStorage.storeSession(self)

            return data
        }
    }

    /// Decrypts utf-8 string from RatchetMessage. Updates session in storage
    ///
    /// - Parameter message: RatchetMessage
    /// - Returns: Decrypted utf-8 string
    /// - Throws:
    ///         - SecureSessionError.invalidUtf8String if decrypted data is not correct utf-8 string
    ///         - Rethrows from crypto RatchetSession
    ///         - Rethrows from SessionStorage
    public func decryptString(from message: RatchetGroupMessage) throws -> String {
        guard message.getType() == .regular else {
            throw NSError()
        }

        let data = try self.decryptData(from: message)

        guard let string = String(data: data, encoding: .utf8) else {
            throw SecureSessionError.invalidUtf8String
        }

        return string
    }

    public func createChangeMembersTicket() throws -> RatchetGroupMessage {
        return try self.ratchetGroupSession.createGroupTicket().getTicketMessage()
    }

    public func setMembers(ticket: RatchetGroupMessage,
                           cards: [Card]) throws {
        guard ticket.getType() == .groupInfo else {
            throw NSError()
        }

        let info = RatchetGroupParticipantsInfo(size: UInt32(cards.count))

        try cards.forEach { card in
            guard let participantId = Data(hexEncodedString: card.identifier) else {
                throw NSError()
            }

            guard let publicKey = card.publicKey as? VirgilPublicKey else {
                throw NSError()
            }

            let publicKeyData = try self.crypto.exportPublicKey(publicKey)

            try info.addParticipant(id: participantId, pubKey: publicKeyData)
        }

        try self.ratchetGroupSession.setupSessionState(message: ticket,
                                                       participants: info)
    }

    public func updateMembers(ticket: RatchetGroupMessage,
                              addCards: [Card],
                              removeCardIds: [String]) throws {
        guard ticket.getType() == .groupInfo else {
            throw NSError()
        }

        guard ticket.getEpoch() == self.ratchetGroupSession.getCurrentEpoch() + 1 else {
            throw NSError()
        }

        let addInfo = RatchetGroupParticipantsInfo(size: UInt32(addCards.count))
        let removeInfo = RatchetGroupParticipantsIds(size: UInt32(removeCardIds.count))

        try addCards.forEach { card in
            guard let participantId = Data(hexEncodedString: card.identifier) else {
                throw NSError()
            }

            guard let publicKey = card.publicKey as? VirgilPublicKey else {
                throw NSError()
            }

            let publicKeyData = try self.crypto.exportPublicKey(publicKey)

            try addInfo.addParticipant(id: participantId, pubKey: publicKeyData)
        }

        try removeCardIds.forEach { id in
            guard let idData = Data(hexEncodedString: id) else {
                throw NSError()
            }

            removeInfo.addId(id: idData)
        }

        try self.ratchetGroupSession.updateSessionState(message: ticket,
                                                        addParticipants: addInfo,
                                                        removeParticipants: removeInfo)
    }

    /// Init session from serialized representation
    ///
    /// - Parameters:
    ///   - data: Serialized session
    ///   - participantIdentity: participant identity
    ///   - sessionStorage: SessionStorage
    ///   - crypto: VirgilCrypto
    /// - Throws: Rethrows from SessionStorage
    public init(data: Data, privateKeyData: Data, sessionStorage: GroupSessionStorage, crypto: VirgilCrypto) throws {
        self.crypto = crypto
        let ratchetGroupSession = try RatchetGroupSession.deserialize(input: data)
        ratchetGroupSession.setRng(rng: crypto.rng)
        try ratchetGroupSession.setPrivateKey(myPrivateKey: privateKeyData)

        self.ratchetGroupSession = ratchetGroupSession
        self.sessionStorage = sessionStorage

        super.init()
    }

    /// Serialize session
    ///
    /// - Returns: Serialized data
    public func serialize() -> Data {
        return self.ratchetGroupSession.serialize()
    }
}
