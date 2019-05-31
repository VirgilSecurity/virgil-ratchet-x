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
import VirgilCryptoRatchet
import VirgilCryptoFoundation
import VirgilCrypto

/// SecureChat errors
///
/// - sessionAlreadyExists: Session with this participant already exists
/// - wrongIdentityPublicKeyCrypto: PublicKey is not VirgilPublicKey
/// - identityKeyDoesntMatch: Identity key in the Card and on Ratchet Cloud doesn't match
/// - invalidLongTermKeySignature: Long-term key signature is invalid
/// - invalidMessageType: Message type should be .prekey
/// - invalidKeyType: Invalid key type
/// - publicKeysSetsMismatch: PublicKeysSets mismatch
@objc public enum SecureChatError: Int, Error {
    case sessionAlreadyExists = 1
    case wrongIdentityPublicKeyCrypto = 2
    case identityKeyDoesntMatch = 3
    case invalidLongTermKeySignature = 4
    case invalidMessageType = 5
    case invalidKeyType = 6
    case publicKeysSetsMismatch = 7
}

/// SecureChat. Class for rotating keys, starting and responding to conversation
@objc(VSRSecureChat) open class SecureChat: NSObject {
    /// Access token provider
    @objc public let accessTokenProvider: AccessTokenProvider

    /// Identity private key
    @objc public let identityPrivateKey: VirgilPrivateKey

    /// Crypto
    @objc public let crypto: VirgilCrypto

    /// Long-term keys storage
    @objc public let longTermKeysStorage: LongTermKeysStorage

    /// One-time keys storage
    @objc public let oneTimeKeysStorage: OneTimeKeysStorage

    /// Session storage
    @objc public let sessionStorage: SessionStorage

    @objc public let groupSessionStorage: GroupSessionStorage

    /// Client
    public let client: RatchetClientProtocol

    // Identity card id
    public let identityCard: Card

    private let keyId = RatchetKeyId()
    private let keysRotator: KeysRotatorProtocol

    public static let defaultSessionName = "DEFAULT"

    /// Initializer
    ///
    /// - Parameter context: SecureChatContext
    /// - Throws:
    ///         - Rethrows from KeychainLongTermKeysStorage
    @objc public convenience init(context: SecureChatContext) throws {
        let crypto = try VirgilCrypto()
        let client = RatchetClient()

        let params: KeychainStorageParams?
        if let appName = context.appName {
            params = try KeychainStorageParams.makeKeychainStorageParams(appName: appName)
        }
        else {
            params = nil
        }

        let longTermKeysStorage = try KeychainLongTermKeysStorage(identity: context.identity, params: params)
        let oneTimeKeysStorage = FileOneTimeKeysStorage(identity: context.identity,
                                                        crypto: crypto,
                                                        identityKeyPair: context.identityKeyPair)
        let sessionStorage = FileSessionStorage(identity: context.identity,
                                                crypto: crypto,
                                                identityKeyPair: context.identityKeyPair)
        let groupSessionStorage = try FileGroupSessionStorage(identity: context.identity,
                                                              crypto: crypto,
                                                              identityKeyPair: context.identityKeyPair)
        let keysRotator = KeysRotator(crypto: crypto,
                                      identityPrivateKey: context.identityKeyPair.privateKey,
                                      identityCardId: context.identityCard.identifier,
                                      orphanedOneTimeKeyTtl: context.orphanedOneTimeKeyTtl,
                                      longTermKeyTtl: context.longTermKeyTtl,
                                      outdatedLongTermKeyTtl: context.outdatedLongTermKeyTtl,
                                      desiredNumberOfOneTimeKeys: context.desiredNumberOfOneTimeKeys,
                                      longTermKeysStorage: longTermKeysStorage,
                                      oneTimeKeysStorage: oneTimeKeysStorage,
                                      client: client)

        self.init(crypto: crypto,
                  identityPrivateKey: context.identityKeyPair.privateKey,
                  identityCard: context.identityCard,
                  accessTokenProvider: context.accessTokenProvider,
                  client: client,
                  longTermKeysStorage: longTermKeysStorage,
                  oneTimeKeysStorage: oneTimeKeysStorage,
                  sessionStorage: sessionStorage,
                  groupSessionStorage: groupSessionStorage,
                  keysRotator: keysRotator)
    }

    /// Initializer
    ///
    /// - Parameters:
    ///   - identityPrivateKey: identity private key
    ///   - identityCardId: Identity card id
    ///   - accessTokenProvider: access token provider
    ///   - client: client
    ///   - longTermKeysStorage: long-term keys storage
    ///   - oneTimeKeysStorage: one-time keys storage
    ///   - sessionStorage: session storage
    ///   - keysRotator: keys rotation
    public init(crypto: VirgilCrypto,
                identityPrivateKey: VirgilPrivateKey,
                identityCard: Card,
                accessTokenProvider: AccessTokenProvider,
                client: RatchetClientProtocol,
                longTermKeysStorage: LongTermKeysStorage,
                oneTimeKeysStorage: OneTimeKeysStorage,
                sessionStorage: SessionStorage,
                groupSessionStorage: GroupSessionStorage,
                keysRotator: KeysRotatorProtocol) {
        self.crypto = crypto
        self.identityPrivateKey = identityPrivateKey
        self.identityCard = identityCard
        self.accessTokenProvider = accessTokenProvider
        self.client = client
        self.longTermKeysStorage = longTermKeysStorage
        self.oneTimeKeysStorage = oneTimeKeysStorage
        self.sessionStorage = sessionStorage
        self.groupSessionStorage = groupSessionStorage
        self.keysRotator = keysRotator

        super.init()
    }

    /// Rotates keys. See rotateKeys() -> GenericOperation<RotationLog> for details
    ///
    /// - Parameter completion: completion handler
    @objc public func rotateKeys(completion: @escaping (RotationLog?, Error?) -> Void) {
        self.rotateKeys().start(completion: completion)
    }

    /// Rotates keys
    ///
    /// Rotation process:
    ///         - Retrieve all one-time keys
    ///         - Delete one-time keys that were marked as orphaned more than orphanedOneTimeKeyTtl seconds ago
    ///         - Retrieve all long-term keys
    ///         - Delete long-term keys that were marked as outdated more than outdatedLongTermKeyTtl seconds ago
    ///         - Check that all relevant long-term and one-time keys are in the cloud
    ///             (still persistent in the cloud and were not used)
    ///         - Mark used one-time keys as used
    ///         - Decide on long-term key roration
    ///         - Generate needed number of one-time keys
    ///         - Upload keys to the cloud
    ///
    /// - Returns: GenericOperation
    public func rotateKeys() -> GenericOperation<RotationLog> {
        Log.debug("Keys rotation queued")

        return CallbackOperation { _, completion in
            Log.debug("Started keys rotation")

            let tokenContext = TokenContext(service: "ratchet", operation: "rotate", forceReload: false)
            let getTokenOperation = OperationUtils.makeGetTokenOperation(
                tokenContext: tokenContext, accessTokenProvider: self.accessTokenProvider)
            let rotateKeysOperation = self.keysRotator.rotateKeysOperation()

            let completionOperation = OperationUtils.makeCompletionOperation(completion: completion)

            rotateKeysOperation.addDependency(getTokenOperation)

            completionOperation.addDependency(getTokenOperation)
            completionOperation.addDependency(rotateKeysOperation)

            let queue = OperationQueue()
            let operations = [getTokenOperation, rotateKeysOperation, completionOperation]
            queue.addOperations(operations, waitUntilFinished: false)
        }
    }

    /// Checks for existing session with given participent in the storage
    ///
    /// - Parameter particpantIdentity: participant identity
    /// - Returns: SecureSession if exists
    @objc open func existingSession(withParticpantIdentity particpantIdentity: String,
                                    name: String? = nil) -> SecureSession? {
        if let session = self.sessionStorage.retrieveSession(participantIdentity: particpantIdentity,
                                                             name: name ?? SecureChat.defaultSessionName) {
            Log.debug("Found existing session with \(particpantIdentity)")

            return session
        }
        else {
            Log.debug("Existing session with \(particpantIdentity) was not found")

            return nil
        }
    }

    /// Deletes session with given participant identity
    ///
    /// - Parameter particpantIdentity: participant identity
    /// - Throws: Rethrows from SessionStorage
    @objc public func deleteSession(withParticpantIdentity particpantIdentity: String, name: String? = nil) throws {
        Log.debug("Deleting session with \(particpantIdentity)")

        try self.sessionStorage.deleteSession(participantIdentity: particpantIdentity,
                                              name: name ?? SecureChat.defaultSessionName)
    }

    /// Deletes session with given participant identity
    ///
    /// - Parameter particpantIdentity: participant identity
    /// - Throws: Rethrows from SessionStorage
    @objc public func deleteAllSessions(withParticpantIdentity particpantIdentity: String) throws {
        Log.debug("Deleting session with \(particpantIdentity)")

        try self.sessionStorage.deleteSession(participantIdentity: particpantIdentity, name: nil)
    }

    /// Starts new session with given participant using his identity card
    ///
    /// - Parameters:
    ///   - receiverCard: receiver identity cards
    ///   - completion: completion handler
    @objc open func startNewSessionAsSender(receiverCard: Card, name: String? = nil,
                                            completion: @escaping (SecureSession?, Error?) -> Void) {
        self.startNewSessionAsSender(receiverCard: receiverCard, name: name).start(completion: completion)
    }

    /// Starts new session with given participant using his identity card
    ///
    /// - Parameter receiverCard: receiver identity cards
    /// - Returns: GenericOperation with SecureSession
    /// - Throws:
    ///         - SecureChatError.sessionAlreadyExists if session already exists.
    ///             Try geting existing session or removing it
    ///         - SecureChatError.wrongIdentityPublicKeyCrypto PublicKey is not VirgilPublicKey
    ///         - SecureChatError.identityKeyDoesntMatch Identity key in the Card and on Ratchet Cloud doesn't match
    ///         - SecureChatError.invalidLongTermKeySignature Long-term key signature is invalid
    ///         - Rethrows from SessionStorage
    ///         - Rethrows from RatchetClient
    ///         - Rethrows form SecureSession
    ///         - Rethrows form AccessTokenProvider
    open func startNewSessionAsSender(receiverCard: Card, name: String? = nil) -> GenericOperation<SecureSession> {
        Log.debug("Starting new session with \(receiverCard.identity) queued")

        return CallbackOperation { _, completion in
            do {
                Log.debug("Starting new session with \(receiverCard.identity)")

                guard self.existingSession(withParticpantIdentity: receiverCard.identity,
                                           name: name ?? SecureChat.defaultSessionName) == nil else {
                    throw SecureChatError.sessionAlreadyExists
                }

                guard let identityPublicKey = receiverCard.publicKey as? VirgilPublicKey else {
                    throw SecureChatError.wrongIdentityPublicKeyCrypto
                }

                guard identityPublicKey.keyType == .ed25519 else {
                    throw SecureChatError.invalidKeyType
                }

                let tokenContext = TokenContext(service: "ratchet", operation: "get")
                let getTokenOperation = OperationUtils.makeGetTokenOperation(
                    tokenContext: tokenContext, accessTokenProvider: self.accessTokenProvider)

                let token = try getTokenOperation.startSync().getResult()

                let publicKeySet = try self.client.getPublicKeySet(forRecipientIdentity: receiverCard.identity,
                                                                   token: token.stringRepresentation())

                let session = try self.startNewSessionAsSender(identity: receiverCard.identity,
                                                               identityPublicKey: identityPublicKey,
                                                               name: name,
                                                               identityPublicKeyData: publicKeySet.identityPublicKey,
                                                               longTermPublicKey: publicKeySet.longTermPublicKey,
                                                               oneTimePublicKey: publicKeySet.oneTimePublicKey)

                completion(session, nil)
            }
            catch {
                completion(nil, error)
            }
        }
    }

    /// Starts multiple new sessions with given participants using their identity cards
    ///
    /// - Parameters:
    ///   - receiverCard: receivers identity cards
    ///   - completion: completion handler
    @objc open func startMultipleNewSessionsAsSender(receiverCards: [Card], name: String? = nil,
                                                     completion: @escaping ([SecureSession]?, Error?) -> Void) {
        self.startMutipleNewSessionsAsSender(receiverCards: receiverCards, name: name).start(completion: completion)
    }

    /// Starts multiple new sessions with given participants using their identity cards
    ///
    /// - Parameter receiverCards: receivers identity cards
    /// - Returns: GenericOperation with SecureSession array
    /// - Throws:
    ///         - SecureChatError.sessionAlreadyExists if session already exists.
    ///             Try geting existing session or removing it
    ///         - SecureChatError.wrongIdentityPublicKeyCrypto PublicKey is not VirgilPublicKey
    ///         - SecureChatError.identityKeyDoesntMatch Identity key in the Card and on Ratchet Cloud doesn't match
    ///         - SecureChatError.invalidLongTermKeySignature Long-term key signature is invalid
    ///         - Rethrows from SessionStorage
    ///         - Rethrows from RatchetClient
    ///         - Rethrows form SecureSession
    ///         - Rethrows form AccessTokenProvider
    open func startMutipleNewSessionsAsSender(receiverCards: [Card],
                                              name: String? = nil) -> GenericOperation<[SecureSession]> {
        Log.debug("Starting new session with \(receiverCards.map { $0.identity }) queued")

        return CallbackOperation { _, completion in
            do {
                Log.debug("Starting new session with \(receiverCards.map { $0.identity })")

                for card in receiverCards {
                    guard self.existingSession(withParticpantIdentity: card.identity,
                                               name: name ?? SecureChat.defaultSessionName) == nil else {
                        throw SecureChatError.sessionAlreadyExists
                    }

                    guard let identityPublicKey = card.publicKey as? VirgilPublicKey else {
                        throw SecureChatError.wrongIdentityPublicKeyCrypto
                    }

                    guard identityPublicKey.keyType == .ed25519 else {
                        throw SecureChatError.invalidKeyType
                    }
                }

                let tokenContext = TokenContext(service: "ratchet", operation: "get")
                let getTokenOperation = OperationUtils.makeGetTokenOperation(
                    tokenContext: tokenContext, accessTokenProvider: self.accessTokenProvider)

                let token = try getTokenOperation.startSync().getResult()

                let publicKeysSets = try self.client
                    .getMultiplePublicKeysSets(forRecipientsIdentities: receiverCards.map { $0.identity },
                                               token: token.stringRepresentation())

                guard publicKeysSets.count == receiverCards.count else {
                    throw SecureChatError.publicKeysSetsMismatch
                }

                var sessions: [SecureSession] = []

                for card in receiverCards {
                    let set = publicKeysSets.first { $0.identity == card.identity }

                    guard let publicKeySet = set else {
                        throw SecureChatError.publicKeysSetsMismatch
                    }

                    guard let identityPublicKey = card.publicKey as? VirgilPublicKey else {
                        throw SecureChatError.wrongIdentityPublicKeyCrypto
                    }

                    let session = try self
                        .startNewSessionAsSender(identity: card.identity,
                                                 identityPublicKey: identityPublicKey,
                                                 name: name,
                                                 identityPublicKeyData: publicKeySet.identityPublicKey,
                                                 longTermPublicKey: publicKeySet.longTermPublicKey,
                                                 oneTimePublicKey: publicKeySet.oneTimePublicKey)

                    sessions.append(session)
                }

                completion(sessions, nil)
            }
            catch {
                completion(nil, error)
            }
        }
    }

    private func startNewSessionAsSender(identity: String,
                                         identityPublicKey: VirgilPublicKey,
                                         name: String? = nil,
                                         identityPublicKeyData: Data,
                                         longTermPublicKey: SignedPublicKey,
                                         oneTimePublicKey: Data?) throws -> SecureSession {
        guard try self.crypto.exportPublicKey(identityPublicKey) == identityPublicKeyData else {
            throw SecureChatError.identityKeyDoesntMatch
        }

        guard try self.crypto.verifySignature(longTermPublicKey.signature,
                                              of: longTermPublicKey.publicKey,
                                              with: identityPublicKey) else {
                                                throw SecureChatError.invalidLongTermKeySignature
        }

        if oneTimePublicKey == nil {
            Log.error("Creating weak session with \(identity)")
        }

        let privateKeyData = try self.crypto.exportPrivateKey(self.identityPrivateKey)

        let session = try SecureSession(crypto: self.crypto,
                                        sessionStorage: self.sessionStorage,
                                        participantIdentity: identity,
                                        name: name ?? SecureChat.defaultSessionName,
                                        senderIdentityPrivateKey: privateKeyData,
                                        receiverIdentityPublicKey: identityPublicKeyData,
                                        receiverLongTermPublicKey: longTermPublicKey.publicKey,
                                        receiverOneTimePublicKey: oneTimePublicKey)

        try self.sessionStorage.storeSession(session)

        return session
    }

    private let queue = DispatchQueue(label: "VSRSecureChat", qos: .background)

    private func scheduleOneTimeKeyReplacement() {
        Log.debug("Adding one time key queued")

        // Replace one-time key after 1 seconds when chat is fully initialized
        self.queue.asyncAfter(deadline: DispatchTime.now() + DispatchTimeInterval.seconds(1)) {
            Log.debug("Adding one time started")

            let oneTimePublicKey: Data

            do {
                try self.oneTimeKeysStorage.startInteraction()

                defer {
                    try? self.oneTimeKeysStorage.stopInteraction()
                }

                let keyPair = try self.crypto.generateKeyPair(ofType: .curve25519)

                let oneTimePrivateKey = try self.crypto.exportPrivateKey(keyPair.privateKey)
                oneTimePublicKey = try self.crypto.exportPublicKey(keyPair.publicKey)
                let keyId = try self.keyId.computePublicKeyId(publicKey: oneTimePublicKey)

                _ = try self.oneTimeKeysStorage.storeKey(oneTimePrivateKey, withId: keyId)

                Log.debug("Saved one-time key successfully")
            }
            catch {
                Log.error("Error saving one-time key")
                return
            }

            do {
                let tokenContext = TokenContext(service: "ratchet", operation: "post")
                let token = try OperationUtils.makeGetTokenOperation(tokenContext: tokenContext,
                                                                     accessTokenProvider: self.accessTokenProvider)
                    .startSync()
                    .getResult()

                try self.client.uploadPublicKeys(identityCardId: nil,
                                                 longTermPublicKey: nil,
                                                 oneTimePublicKeys: [oneTimePublicKey],
                                                 token: token.stringRepresentation())

                Log.debug("Added one-time key successfully")
            }
            catch {
                Log.error("Error adding one-time key")
            }
        }
    }

    /// Responds with new session with given participant using his initiation message
    ///
    /// - Parameters:
    ///   - senderCard: Sender identity card
    ///   - ratchetMessage: Ratchet initiation message (should be prekey message)
    /// - Returns: SecureSession
    /// - Throws:
    ///         - SecureChatError.sessionAlreadyExists if session already exists.
    ///             Try geting existing session or removing it
    ///         - SecureChatError.wrongIdentityPublicKeyCrypto PublicKey is not VirgilPublicKey
    ///         - Rethrows from SessionStorage
    ///         - Rethrows form SecureSession
    ///         - Rethrows form AccessTokenProvider
    @objc public func startNewSessionAsReceiver(senderCard: Card,
                                                name: String? = nil,
                                                ratchetMessage: RatchetMessage) throws -> SecureSession {
        Log.debug("Responding to session with \(senderCard.identity) queued")

        guard self.existingSession(withParticpantIdentity: senderCard.identity, name: name) == nil else {
            throw SecureChatError.sessionAlreadyExists
        }

        guard let senderIdentityPublicKey = senderCard.publicKey as? VirgilPublicKey else {
            throw SecureChatError.wrongIdentityPublicKeyCrypto
        }

        guard senderIdentityPublicKey.keyType == .ed25519 else {
            throw SecureChatError.invalidKeyType
        }

        guard ratchetMessage.getType() == .prekey else {
            throw SecureChatError.invalidMessageType
        }

        let receiverLongTermPublicKey = ratchetMessage.getLongTermPublicKey()
        let longTermKeyId = try self.keyId.computePublicKeyId(publicKey: receiverLongTermPublicKey)
        let receiverLongTermPrivateKey = try self.longTermKeysStorage.retrieveKey(withId: longTermKeyId)

        let receiverOneTimePublicKey = ratchetMessage.getOneTimePublicKey()
        let receiverOneTimeKeyId: Data?

        if receiverOneTimePublicKey.isEmpty {
            receiverOneTimeKeyId = nil
        }
        else {
            receiverOneTimeKeyId = try self.keyId.computePublicKeyId(publicKey: receiverOneTimePublicKey)
        }

        let receiverOneTimePrivateKey: OneTimeKey?

        var interactionStarted = false

        if let receiverOneTimeKeyId = receiverOneTimeKeyId {
            try self.oneTimeKeysStorage.startInteraction()
            interactionStarted = true

            receiverOneTimePrivateKey = try self.oneTimeKeysStorage.retrieveKey(withId: receiverOneTimeKeyId)
        }
        else {
            receiverOneTimePrivateKey = nil
        }

        defer {
            if interactionStarted {
                try? self.oneTimeKeysStorage.stopInteraction()
            }
        }

        let session = try SecureSession(crypto: self.crypto,
                                        sessionStorage: self.sessionStorage,
                                        participantIdentity: senderCard.identity,
                                        name: name ?? SecureChat.defaultSessionName,
                                        receiverIdentityPrivateKey: self.identityPrivateKey,
                                        receiverLongTermPrivateKey: receiverLongTermPrivateKey,
                                        receiverOneTimePrivateKey: receiverOneTimePrivateKey,
                                        senderIdentityPublicKey: self.crypto.exportPublicKey(senderIdentityPublicKey),
                                        ratchetMessage: ratchetMessage)

        if let receiverOneTimeKeyId = receiverOneTimeKeyId {
            try self.oneTimeKeysStorage.deleteKey(withId: receiverOneTimeKeyId)

            self.scheduleOneTimeKeyReplacement()
        }

        try self.sessionStorage.storeSession(session)

        return session
    }

    @objc public func startNewGroupSession(customSessionId: Data? = nil) throws -> RatchetGroupMessage {
        let ticket = RatchetGroupTicket()
        ticket.setRng(rng: self.crypto.rng)

        try ticket.setupTicketAsNew()

        if let sessionId = customSessionId {
            // FIXME
            guard sessionId.count == 32 else {
                throw NSError()
            }

            ticket.setSessionId(sessionId: sessionId)
        }

        return ticket.getTicketMessage()
    }

    @objc public func startGroupSession(with receiversCards: [Card],
                                        using ratchetMessage: RatchetGroupMessage) throws -> SecureGroupSession {
        guard ratchetMessage.getType() == .groupInfo else {
            throw NSError()
        }

        let privateKeyData = try self.crypto.exportPrivateKey(self.identityPrivateKey)

        guard let myId = Data(hexEncodedString: self.identityCard.identifier) else {
            throw NSError()
        }

        return try SecureGroupSession(crypto: self.crypto,
                                      sessionStorage: self.groupSessionStorage,
                                      privateKeyData: privateKeyData,
                                      myId: myId,
                                      ratchetGroupMessage: ratchetMessage,
                                      cards: receiversCards)
    }

    @objc public func existingGroupSession(sessionId: Data) -> SecureGroupSession? {
        let identifier = sessionId.hexEncodedString()

        if let session = self.groupSessionStorage.retrieveSession(identifier: identifier) {
            Log.debug("Found existing group session with identifier: \(sessionId)")

            return session
        }
        else {
            Log.debug("Existing session with identifier: \(sessionId) was not found")

            return nil
        }
    }

    /// Removes all data corresponding to this user: sessions and keys.
    ///
    /// - Parameter completion: completion handler
    @objc public func reset(completion: @escaping (Error?) -> Void) {
        self.reset().start { _, error in
            completion(error)
        }
    }

    /// Removes all data corresponding to this user: sessions and keys.
    ///
    /// - Returns: GenericOperation
    public func reset() -> GenericOperation<Void> {
        Log.debug("Reset queued")

        return CallbackOperation { _, completion in
            do {
                Log.debug("Started reset")

                let tokenContext = TokenContext(service: "ratchet", operation: "delete")
                let tokenOp = OperationUtils.makeGetTokenOperation(
                    tokenContext: tokenContext, accessTokenProvider: self.accessTokenProvider)

                let token = try tokenOp.startSync().getResult()

                Log.debug("Reseting cloud")
                try self.client.deleteKeysEntity(token: token.stringRepresentation())

                Log.debug("Reseting one-time keys")
                try self.oneTimeKeysStorage.reset()

                Log.debug("Reseting long-term keys")
                try self.longTermKeysStorage.reset()

                Log.debug("Reseting sessions")
                try self.sessionStorage.reset()

                Log.debug("Reseting success")

                completion(Void(), nil)
            }
            catch {
                completion(nil, error)
            }
        }
    }
}
