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
import VirgilCrypto
import VirgilCryptoRatchet

/// SecureSession errors
///
/// - invalidUtf8String: invalid convesion to/from utf-8 string
@objc(VSCRSecureSessionError) public enum SecureSessionError: Int, Error {
    case invalidUtf8String = 1
}

/// SecureSession
/// NOTE: This class is thread-safe
@objc(VSRSecureSession) public final class SecureSession: NSObject {
    /// Participant identity
    @objc public let participantIdentity: String

    /// Crypto
    @objc public let crypto: VirgilCrypto

    /// SessionStorage
    @objc public let sessionStorage: SessionStorage

    private let ratchetSession: RatchetSession
    private let queue = DispatchQueue(label: "SecureSessionQueue")

    // As receiver
    internal init(crypto: VirgilCrypto,
                  sessionStorage: SessionStorage,
                  participantIdentity: String,
                  receiverIdentityPrivateKey: VirgilPrivateKey,
                  receiverLongTermPrivateKey: LongTermKey,
                  receiverOneTimePrivateKey: OneTimeKey?,
                  senderIdentityPublicKey: Data,
                  ratchetMessage: RatchetMessage) throws {
        self.crypto = crypto
        self.sessionStorage = sessionStorage
        self.participantIdentity = participantIdentity

        let ratchetSession = RatchetSession()
        ratchetSession.setRng(rng: crypto.rng)

        try ratchetSession.respond(senderIdentityPublicKey: senderIdentityPublicKey,
                                   receiverIdentityPrivateKey: self.crypto.exportPrivateKey(receiverIdentityPrivateKey),
                                   receiverLongTermPrivateKey: receiverLongTermPrivateKey.key,
                                   receiverOneTimePrivateKey: receiverOneTimePrivateKey?.key ?? Data(),
                                   message: ratchetMessage)

        self.ratchetSession = ratchetSession

        super.init()
    }

    // As sender
    internal init(crypto: VirgilCrypto,
                  sessionStorage: SessionStorage,
                  participantIdentity: String,
                  senderIdentityPrivateKey: Data,
                  receiverIdentityPublicKey: Data,
                  receiverLongTermPublicKey: Data,
                  receiverOneTimePublicKey: Data?) throws {
        self.crypto = crypto
        self.sessionStorage = sessionStorage
        self.participantIdentity = participantIdentity

        let ratchetSession = RatchetSession()
        ratchetSession.setRng(rng: crypto.rng)

        try ratchetSession.initiate(senderIdentityPrivateKey: senderIdentityPrivateKey,
                                    receiverIdentityPublicKey: receiverIdentityPublicKey,
                                    receiverLongTermPublicKey: receiverLongTermPublicKey,
                                    receiverOneTimePublicKey: receiverOneTimePublicKey ?? Data())

        self.ratchetSession = ratchetSession

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
    public func encrypt(string: String) throws -> RatchetMessage {
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
    public func encrypt(data: Data) throws -> RatchetMessage {
        return try self.queue.sync {
            let msg = try self.ratchetSession.encrypt(plainText: data)

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
    public func decryptData(from message: RatchetMessage) throws -> Data {
        return try self.queue.sync {
            let data = try self.ratchetSession.decrypt(message: message)

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
    public func decryptString(from message: RatchetMessage) throws -> String {
        let data = try self.decryptData(from: message)

        guard let string = String(data: data, encoding: .utf8) else {
            throw SecureSessionError.invalidUtf8String
        }

        return string
    }

    /// Init session from serialized representation
    ///
    /// - Parameters:
    ///   - data: Serialized session
    ///   - participantIdentity: participant identity
    ///   - sessionStorage: SessionStorage
    ///   - crypto: VirgilCrypto
    /// - Throws: Rethrows from SessionStorage
    public init(data: Data, participantIdentity: String, sessionStorage: SessionStorage, crypto: VirgilCrypto) throws {
        self.crypto = crypto
        let ratchetSession = try RatchetSession.deserialize(input: data)
        ratchetSession.setRng(rng: crypto.rng)

        self.ratchetSession = ratchetSession
        self.sessionStorage = sessionStorage
        self.participantIdentity = participantIdentity

        super.init()
    }

    /// Serialize session
    ///
    /// - Returns: Serialized data
    public func serialize() -> Data {
        return self.ratchetSession.serialize()
    }
}
